package source

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"
)

// FileFromLayer is a file's contents together with the layer they came from.
// The layer is carried because it becomes Location.LayerDigest, and "which
// layer introduced this package" is the question a reader asks next.
type FileFromLayer struct {
	Data   []byte
	DiffID string
	// ViaDiffID is the newest layer among the links Files followed to reach
	// the file, "" when the path was a regular file at its own name. A
	// caller that keys a path's identity by layer (D162's owner rule) needs
	// the layer the path's meaning last changed in, which a link retargeted
	// in an upper layer changes without touching the bytes (QA 2026-11-11).
	ViaDiffID string
}

// Whiteout markers, from the OCI image-spec (layer.md).
//
// They are instructions to a reader assembling the filesystem, not files. A
// reader that returns them hands the next stage the literal bytes of a marker;
// a reader that ignores them reports packages that were uninstalled.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// maxSymlinks is how many links one wanted path may pass through, Linux's
// MAXSYMLINKS: path resolution that meets a forty-first link fails with ELOOP,
// so the container itself cannot open the path. It counts LINKS, one per hop.
// The bound used to count resolve passes, and the final file cost a pass, so
// the real limit was seven links and a chain one longer came back as a
// missing file (audit 2026-10-22 P4, re-verified 2026-11-02).
//
// A hardlink costs a hop too, though the kernel follows none: each hop here is
// one more pass over every layer, and counting both is what bounds the passes
// at maxSymlinks+1 whatever the image holds. A hardlink chain is not a shape
// a tar writer produces -- a tar hardlink names a file archived in full.
const maxSymlinks = 40

// noCeiling is query.before for every query not reached through a hardlink:
// no position within its top layer is out of reach.
const noCeiling = math.MaxInt

// Unresolved is a wanted path the walk could not finish resolving, and why.
// It is not an absent file: the image has a link at that path, and what the
// link leads to was not read.
type Unresolved struct {
	Path   string
	Reason string
}

// unresolvedLinks is the reason for a path still behind a link after
// maxSymlinks of them, a cycle included.
var unresolvedLinks = fmt.Sprintf("still a link after %d symbolic links (a chain Linux "+
	"refuses with ELOOP); what it leads to was not read", maxSymlinks)

// unresolvedCycle is the reason for a path whose links lead back to a path
// already followed -- what Linux refuses with ELOOP at once. Told apart from
// the length limit so a reader is not sent counting links, and ended at the
// first repeat rather than after maxSymlinks passes, because every pass
// reads and digest-drains every layer (D123): a two-link cycle at
// /etc/os-release would otherwise cost forty-one full reads of the image.
const unresolvedCycle = "a symbolic link cycle (Linux refuses it with ELOOP); what it leads to was not read"

// Unresolved returns every path a Files call on this image could not finish
// resolving, sorted by path. It lives on the Image beside the read budget,
// for the budget's reason: the Image is the scan, and every Files call the
// scan makes -- the distro probe and Bitnami's legacy path alike -- reports
// into it, so a path the scan gave up on is learnt here rather than from a
// result that simply lacks the key, which is what an absent file looks like.
func (img *Image) Unresolved() []Unresolved {
	out := append([]Unresolved(nil), img.unresolved...)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// NoteUnresolved records a path a caller of the image's read primitives
// looked for and could not resolve inside the image -- a link that leads
// nowhere, or out of the image -- with the reason. It joins the walk's own
// unresolved paths, which the scan reports as unread (D109 / audit P4), so
// --fail-on-incomplete sees it without a second mechanism.
func (img *Image) NoteUnresolved(p, reason string) { img.noteUnresolved(p, reason) }

func (img *Image) noteUnresolved(p, reason string) {
	for _, u := range img.unresolved {
		if u.Path == p {
			return
		}
	}
	img.unresolved = append(img.unresolved, Unresolved{Path: p, Reason: reason})
}

// Files resolves each wanted path against the image's layers, following
// symlinks and hardlinks.
//
// Layers are walked NEWEST FIRST and each path is resolved at most once, which
// is what makes a later layer win. Within ONE layer it is the LAST entry for a
// name that counts: a tar may carry a path twice, and docker's and
// containerd's untar and GNU tar all leave the later entry on disk, so the
// first is what the container does not have (audit 2026-10-22 P4, re-verified
// 2026-11-02), including a change of type. Whiteouts
// recorded on the way down apply only to the layers still to be read — the
// spec is explicit that a whiteout affects lower layers only, so one in the
// base layer must not hide a file a later layer installed. A hardlink is the
// one exception to newest-wins: its target is the inode of the layer that made
// the link, as it stood when the link entry was reached, so it is resolved
// from that point down and a later rewrite of the target's name does not reach
// it (D130, see query).
//
// Symlinks are not optional to handle. /etc/os-release is a regular file in
// alpine:3.19 and a symlink to ../usr/lib/os-release in alpine:3.21,
// alpine:latest, debian:12 and ubuntu:24.04 — one layer of that image carries
// 335 symlinks against 191 regular files. Reading a symlink's tar entry yields
// zero bytes, so a reader that treats it as a file reports "found it, here is
// nothing" for a path it never resolved.
//
// Nothing is written to disk. A scan wants a couple of files out of each layer,
// so the tar is streamed and the wanted entries copied out in passing. Path
// traversal, symlink escape, and archive bombs are extraction vulnerabilities;
// not extracting removes the class rather than defending against it.
//
// A wanted path that no layer carries is absent from the result and is not an
// error: an image with no apk database is a real image, and what that means is
// the caller's decision. A path still behind a link after maxSymlinks of them
// is absent from the result too, but not from the image, so it is recorded for
// Unresolved: before it was, an os-release reached through a long chain made
// the image read as having no distro, with nothing saying resolution stopped.
//
// Every file copied out is bounded by MaxFileBytes and counted against the
// image's MaxScanBytes budget, and ctx is checked between tar entries (D112):
// an over-limit file, an exhausted budget or a cancelled context is an error,
// never a shorter result.
func (img *Image) Files(ctx context.Context, want []string) (map[string]FileFromLayer, error) {
	newest := len(img.Layers) - 1
	qs := make([]query, 0, len(want))
	requested := make(map[string]bool, len(want))
	for _, w := range want {
		if requested[w] {
			continue
		}
		requested[w] = true
		// Answered under the name the caller gave, whatever its spelling;
		// a ".." in it is applied lazily (lazyDotDot), never folded here.
		n := normaliseLazy(w)
		qs = append(qs, query{path: n, want: w, top: newest, before: noCeiling, dir: path.Dir(n), via: -1})
	}

	out := make(map[string]FileFromLayer, len(want))
	// seen is, per wanted path, every (path, top, before) already queried
	// for it. A follow-up that repeats one would resolve exactly as it did
	// the first time: a cycle, ended here. top and before are part of the
	// key because a hardlink re-queues its target under a ceiling, and the
	// same path under a different ceiling is a different lookup.
	type lookup struct {
		path        string
		top, before int
	}
	seen := make(map[string]map[lookup]bool, len(qs))
	for _, q := range qs {
		seen[q.want] = map[lookup]bool{{q.path, q.top, q.before}: true}
	}
	// Ends: a follow-up query has one more link than the query it came from,
	// and none past maxSymlinks is queued, so there are at most maxSymlinks+1
	// passes; a cycle ends at its first repeated lookup.
	for len(qs) > 0 {
		next, err := img.resolvePass(ctx, qs, out)
		if err != nil {
			return nil, err
		}
		// Whatever comes back was a link; whatever came back nothing either
		// does not exist or was answered.
		qs = qs[:0]
		for _, q := range next {
			if q.links > maxSymlinks {
				img.noteUnresolved(q.want, unresolvedLinks)
				continue
			}
			k := lookup{q.path, q.top, q.before}
			if seen[q.want][k] {
				img.noteUnresolved(q.want, unresolvedCycle)
				continue
			}
			seen[q.want][k] = true
			qs = append(qs, q)
		}
	}
	return out, nil
}

// query is one path still being resolved: the caller's name it will answer
// under, and the newest layer it may be satisfied from.
//
// top is what tells a hardlink from a symlink (D130). A symlink resolves by
// NAME at runtime, so its target is looked up from the newest layer down like
// any other path. A hardlink is a second name for the inode as it was in the
// layer that made the link: a later layer that whites out and rewrites the
// target's name has changed that name, not the inode the link still holds. So
// a hardlink found in layer i re-queues its target with top = i -- that layer
// and the ones beneath it, never above -- and the whiteouts above i do not
// apply to it either. Found by the 2026-10-20 external review (#4): a package
// database hardlinked from a scratch path that a later layer rewrote came
// back as the rewritten database.
//
// before is the same rule one level down, inside layer top: the hardlink
// entry's own position in that layer's tar. A tar hardlink names a file
// archived EARLIER, and an extractor links to whatever is at that name when it
// reaches the link entry, so a later entry rewriting the target in the same
// layer -- which now wins for a plain read of the name -- does not reach the
// inode the link holds, and neither does a later whiteout of the name. Entries
// of layer top at or after before are invisible to the query; every query not
// reached through a hardlink has noCeiling.
//
// dir is the directory the name was reached THROUGH, which is what a relative
// symlink target resolves against: the kernel resolves it from the directory
// of the name being opened, and for a hardlink to a relative symlink that is
// the hardlink's directory, not the symlink entry's. For every chain without
// a hardlink the two coincide.
//
// links is how many links the chain passed through to reach path.
type query struct {
	path   string
	want   string
	top    int
	before int
	dir    string
	links  int
	// via is the newest layer index among the links followed so far, -1
	// for none (FileFromLayer.ViaDiffID).
	via int
}

// whiteout is one deletion marker, the layer that wrote it and its position in
// that layer's tar. A marker in layer j hides a name from a read of any layer
// below j -- for a query that may see layer j at all (q.top >= j) and, in a
// hardlink's own layer, only when the marker came before the link (q.before).
type whiteout struct {
	name  string
	layer int
	pos   int
}

// hitKind is what one layer last wrote at a query's path.
type hitKind int

const (
	hitNone hitKind = iota // nothing yet: the query goes on to the layer below
	hitFile                // a regular file: the query is answered
	hitLink                // a symlink or hardlink: the query follows it
	hitGone                // a directory, device, FIFO or whiteout: no file here, and lower layers are shadowed (A10)
)

// layerHit is the entry that decides a query in one layer. It is held until
// the layer ends rather than acted on at once, because a later entry for the
// same name in the same layer replaces it.
type layerHit struct {
	kind     hitKind
	data     []byte
	hard     bool
	linkname string
	pos      int
	// rest is what remains of the query's path below a symlink found at
	// one of its ancestors ("" for a link at the path itself): the query
	// continues at the link's target with rest appended (follow).
	rest string
}

// resolvePass reads every layer once, newest first, answering queries whose
// path is a regular file and returning a follow-up query for each one that
// turned out to be a link. One tar entry may answer several queries: two
// wanted names that resolve to the same target both get it (the first
// implementation kept only the last requester per target path).
//
// Within a layer nothing is decided until the layer ends: each entry for a
// query's path replaces what an earlier entry of the same layer said about it
// (Files). A regular file is still copied out when its entry is reached --
// the tar is a stream -- so a file a later entry replaces has spent its bytes
// against MaxScanBytes for nothing; the budget is generous by two orders of
// magnitude over a real package database, and only an image that writes the
// same database repeatedly pays it.
func (img *Image) resolvePass(ctx context.Context, qs []query, out map[string]FileFromLayer) ([]query, error) {
	var next []query
	done := make([]bool, len(qs))
	// answered is the queries a layer decided by a file or a link. done is
	// wider: it also marks a query the layers below some layer cannot
	// answer -- hidden by a whiteout or an opaque marker above, its
	// ancestor's link replaced by a directory above -- which for a path
	// holding a ".." means only that; the component before the ".." may
	// still be a directory in the layer that hid the rest, and the fold then
	// proceeds (PR #290 review: `RUN rm -rf /data/marker && mkdir
	// /data/marker` above the link's lower layer, whose opaque marker hid
	// the lower layers, left the path unanswered where the kernel reads
	// `/data/packages`).
	answered := make([]bool, len(qs))
	var deleted, opaque []whiteout
	newest := len(img.Layers) - 1
	// preState is, per query holding a "..", what the NEWEST layer that
	// speaks of each component a ".." follows (lazyDotDot) says it is: a
	// directory -- an explicit directory entry, or entries beneath the name
	// -- or not one: a file, a link, a whiteout of it or of an ancestor, an
	// opaque marker in its parent. A ".." folds only over a directory so
	// shown, left to right, and the folding stops at the first component
	// that is not one (foldDecided): a link there is followed by the next
	// pass's ancestor rule, a file or a deletion ends the path there, and a
	// component no layer shows leads nowhere, as the kernel's ENOENT says
	// (release check of main b732cac: `/data/absent/../qa-db` with no
	// `absent` anywhere had folded to `data/qa-db`). Folding every ".."
	// at once, over directories seen in ANY layer, had skipped the look at
	// the second component (release check of main 60c512c):
	// `/data/marker/../route/../packages` with `route` a symlink read
	// nothing, and with `route` deleted or replaced by a file in an upper
	// layer folded over the lower layer's directory and read a database the
	// link no longer reaches -- BusyBox's 7 findings, one Critical, lost
	// each way.
	preState := make([]map[string]preVerdict, len(qs))
	preOf := make([][]string, len(qs))
	for k, q := range qs {
		if strings.Contains("/"+q.path+"/", "/../") {
			preOf[k] = dotDotPrefixes(q.path)
			preState[k] = map[string]preVerdict{}
		}
	}
	// dirAbove is, per query, every ancestor of its path an upper layer
	// wrote an explicit directory entry at. The changeset rules keep an
	// existing path under a new entry only when BOTH are directories, so a
	// lower layer's symlink at such a name was replaced by the directory and
	// is not followed (release check 2026-11-11: `lib/apk/db` a link to an
	// old database below, a directory above, read the old database through
	// the replaced link -- BusyBox's 7 findings, one Critical, lost). An
	// implied directory (entries beneath a name with no entry for the name)
	// does not replace a link: the untar creates the path through it.
	dirAbove := make([]map[string]bool, len(qs))

	for i := newest; i >= 0; i-- {
		l := img.Layers[i]
		// A query an upper layer's whiteout hides from this layer is hidden
		// from every layer below it too, so it ends here, unanswered.
		for k, q := range qs {
			if !done[k] && i <= q.top && hiddenFrom(q, i, deleted, opaque) {
				done[k] = true
			}
		}
		// Whiteouts found in THIS layer must not hide this layer's entries
		// through the cross-layer sets, so they are collected separately and
		// merged after the pass.
		var layerDeleted, layerOpaque []whiteout
		// For each prefix, record current entries separately from markers that
		// cut off lower layers. A changeset can both delete an old directory
		// and recreate it with just a child entry, in either tar order.
		layerPre := make([]map[string]preSay, len(qs))
		for k, q := range qs {
			if preOf[k] == nil || done[k] || i > q.top {
				continue
			}
			layerPre[k] = map[string]preSay{}
		}
		hits := make([]layerHit, len(qs))
		// above is what this layer wrote at a strict ancestor of each
		// query's path; it decides the query only when nothing in this
		// layer decided it by name (see the ancestor case below).
		above := make([]layerHit, len(qs))
		pos := -1

		err := readLayer(ctx, l, func(name string, h *tar.Header, r io.Reader) error {
			pos++
			dir, base := path.Split(name)
			marker, removed := false, ""
			switch {
			case base == whiteoutOpaque:
				layerOpaque = append(layerOpaque, whiteout{path.Clean(dir), i, pos})
				marker = true
			case strings.HasPrefix(base, whiteoutPrefix):
				removed = path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))
				layerDeleted = append(layerDeleted, whiteout{removed, i, pos})
				marker = true
			}
			var data []byte
			read := false
			for k, q := range qs {
				if done[k] || i > q.top || (i == q.top && pos >= q.before) {
					continue
				}
				if preOf[k] != nil {
					for _, pre := range preOf[k] {
						if st := preState[k][pre]; st == preDir || st == preNotDir {
							continue
						}
						say := layerPre[k][pre]
						switch {
						case removed != "" && (pre == removed || strings.HasPrefix(pre, removed+"/")):
							// The marker hides what LOWER layers hold at the
							// name; what this layer itself put there before the
							// marker stands (the OCI image spec's whiteout rule,
							// "Layer semantics" in docs/DESIGN.md, held again
							// 2026-11-12), so the layer's word so far is kept.
							say.hidesLower = true
						case base == whiteoutOpaque && (dir == "" || strings.HasPrefix(pre, dir)):
							say.hidesLower = true
						case !marker && name == pre:
							say.entry = preNotDir
							if h.Typeflag == tar.TypeDir {
								say.entry = preDir
							}
						case strings.HasPrefix(name, pre+"/") && say.entry == preUnknown:
							// The marker's enclosing directory exists as well. An
							// opaque marker removes its lower children, never itself.
							say.entry = preImplied
						default:
							continue
						}
						layerPre[k][pre] = say
					}
				}
				switch {
				case strings.HasPrefix(name, q.path+"/"):
					// An entry anywhere under the path -- a file, a directory, a
					// whiteout or opaque marker inside it -- makes the path a
					// directory in this layer, and a directory is not the file
					// the query wants (audit A10). A file turned into a
					// directory writes "<name>/" and maybe
					// "<name>/.wh..wh..opq", never ".wh.<name>", so the
					// whiteout rules do not see it.
					hits[k] = layerHit{kind: hitGone}
				case marker:
					// A marker is an instruction, never the file. A plain
					// whiteout applies to LOWER layers only (OCI image spec,
					// layer.md "Whiteouts": files present in the same layer
					// as a whiteout can only be hidden by a later layer's
					// whiteout), so it decides nothing in its own layer: this
					// layer's entry before it stands, one after it is written
					// over it, and the lower layers' copies are shadowed by
					// `deleted` (hiddenFrom) once the layer ends. One rule for
					// every layer: the media type is not consulted (see
					// fromV1). Revised 2026-11-12: the untars' naive paths
					// RemoveAll the path on reaching the marker, but the
					// production paths (moby overlay2, containerd's overlay
					// applier) fail the apply instead, and every scanner and
					// extractor keeps the file.
				case strings.HasPrefix(q.path, name+"/"):
					// An entry at a strict ANCESTOR of the path. A symlink
					// there is where the kernel would leave this path and
					// continue at the link's target: a package directory
					// linked to /opt/current, with /opt/current itself
					// re-pointed at /opt/version2 by an upper layer, read the
					// lower layer's /opt/current/package.json -- the old
					// version (release check 2026-11-11; the limitation
					// deferred at PR #275). A file or device there means the
					// path's parent is not a directory: nothing is at the
					// path, and lower layers are shadowed (A10). A directory
					// entry is the ordinary case and decides nothing. A
					// hardlink cannot name a directory, so it is a file here.
					//
					// Held apart from a hit by name in the SAME layer, which
					// wins: a tar that carries both `lib -> usr/lib` and
					// `lib/apk/db/installed` is read by name as before (the
					// untar writes the entry through the link, so the name
					// still reaches it). The ancestor decides against lower
					// layers only -- a link over a directory hides the
					// directory's tree (the changeset rule collectWith
					// applies), and this is the resolver's half of it.
					switch h.Typeflag {
					case tar.TypeSymlink:
						if dirAbove[k][name] {
							// Replaced by the directory an upper layer put
							// here: the link and what it led to are gone.
							above[k] = layerHit{kind: hitGone}
						} else {
							above[k] = layerHit{kind: hitLink, linkname: h.Linkname, pos: pos, rest: strings.TrimPrefix(q.path, name+"/")}
						}
					case tar.TypeDir:
						if dirAbove[k] == nil {
							dirAbove[k] = map[string]bool{}
						}
						dirAbove[k][name] = true
					default:
						above[k] = layerHit{kind: hitGone}
					}
				case name == q.path:
					switch h.Typeflag {
					case tar.TypeSymlink, tar.TypeLink:
						hits[k] = layerHit{kind: hitLink, hard: h.Typeflag == tar.TypeLink, linkname: h.Linkname, pos: pos}
					case tar.TypeReg, tar.TypeGNUSparse, tar.TypeCont:
						if !read {
							b, err := img.readEntry(name, r)
							if err != nil {
								return err
							}
							data, read = b, true
						}
						hits[k] = layerHit{kind: hitFile, data: data}
					default:
						// A directory, device or FIFO at the wanted path: this
						// layer has something there that is not a file (A10).
						hits[k] = layerHit{kind: hitGone}
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read layer %s: %w", l.DiffID, err)
		}

		for k, hit := range hits {
			if hit.kind == hitNone {
				hit = above[k]
			}
			if hit.kind == hitNone {
				continue
			}
			done[k] = true
			switch hit.kind {
			case hitFile:
				answered[k] = true
				f := FileFromLayer{Data: hit.data, DiffID: l.DiffID}
				if qs[k].via >= 0 {
					f.ViaDiffID = img.Layers[qs[k].via].DiffID
				}
				out[qs[k].want] = f
			case hitLink:
				// Record the link and stop looking for this path: a lower
				// layer's copy is shadowed by the link that replaced it.
				answered[k] = true
				next = append(next, follow(qs[k], hit, i, newest))
			}
			// hitGone ends the query unanswered, as for an absent file: a
			// lower layer's copy is shadowed by what this layer put there.
		}

		// The newest layer's word stands; an implied directory (entries
		// beneath the name, no entry for it) is provisional: the untar
		// creates such a path through whatever an older layer left at the
		// name, so an older explicit entry decides -- a symlink stands and
		// is followed, a file is no directory -- while an older deletion
		// does not undo the newer directory (PR #290 review: an upper
		// layer's `data/route/x` had read a lower layer's `data/route ->
		// /srv/active/deep` as a directory and folded over it).
		for k := range qs {
			for pre, say := range layerPre[k] {
				// Implied directories can traverse a symlink in a lower
				// layer. Once a whiteout hides that layer, the children
				// create a fresh directory and the lookup is settled.
				switch {
				case say.entry == preDir || say.entry == preNotDir:
					preState[k][pre] = say.entry
				case say.hidesLower:
					if say.entry == preImplied || preState[k][pre] == preImplied {
						preState[k][pre] = preDir
					} else {
						preState[k][pre] = preNotDir
					}
				case say.entry == preImplied:
					preState[k][pre] = preImplied
				}
			}
		}
		deleted = append(deleted, layerDeleted...)
		opaque = append(opaque, layerOpaque...)
	}
	// A path still holding a ".." was not decided by any entry at the
	// component before its first "..", in any layer: the leading ".."s whose
	// components the layers decided are directories are applied, left to
	// right -- each over a plain directory, no link to follow -- and the
	// path looked up again (lazyDotDot); a fold is not a link hop. The
	// folding stops at the first component that is not a directory, and the
	// next pass looks at it as it looks at any ancestor: a link is followed,
	// a file or a deletion ends the path. A component no layer shows ends
	// the path unanswered. (A mutation counting a re-queue as a hop
	// survives: a path folds once per pass, so forty-four `a/..` over one
	// directory cost one, not forty-four.)
	for k, q := range qs {
		if answered[k] || preOf[k] == nil {
			continue
		}
		folded, ok := foldDecided(q.path, preState[k])
		if !ok {
			continue
		}
		next = append(next, query{path: folded, want: q.want, top: q.top, before: q.before, dir: path.Dir(folded), links: q.links, via: q.via})
	}
	return next, nil
}

// preVerdict is what the layers say of a component a ".." follows.
type preVerdict uint8

const (
	preUnknown preVerdict = iota // no layer has spoken of it yet
	preDir                       // a directory: a ".." after it folds
	preNotDir                    // a file, a link, a deletion: the next pass decides it as an ancestor
	preImplied                   // a directory implied by entries beneath it, unless an older layer's entry says otherwise
)

type preSay struct {
	entry      preVerdict
	hidesLower bool
}

// dotDotPrefixes is, for a path holding "..", the component each ".."
// applies to, as the path folds left to right: for `a/b/../../c` the
// prefixes `a/b` and `a`. Every strict ancestor is checked too: a directory
// at an old spelling is unreachable when an ancestor has become a symlink.
func dotDotPrefixes(p string) []string {
	var out []string
	seen := map[string]bool{}
	for strings.Contains("/"+p+"/", "/../") {
		segs := strings.Split(p, "/")
		for i, c := range segs {
			if c == ".." {
				for pre := strings.Join(segs[:i], "/"); pre != "." && pre != "" && !seen[pre]; pre = path.Dir(pre) {
					seen[pre] = true
					out = append(out, pre)
				}
				break
			}
		}
		p = foldFirstDotDot(p)
	}
	return out
}

// foldDecided folds the leading ".."s of p whose components the layers
// decided are directories (state), left to right, and stops at the first
// that is not. It reports the partly or wholly folded path and true when at
// least one ".." folded -- the next pass looks at the component it stopped
// at with the ancestor rules -- and false when the first ".." applies to a
// component the layers do not show as a directory: one no layer shows leads
// nowhere, and one shown as a file, a link or a deletion was decided by the
// pass itself, as an ancestor of the path. A ".." at the root is dropped,
// as the kernel drops it.
func foldDecided(p string, state map[string]preVerdict) (string, bool) {
	folded := 0
	checked := map[string]bool{}
	for strings.Contains("/"+p+"/", "/../") {
		segs := strings.Split(p, "/")
		for i, c := range segs {
			if c != ".." {
				continue
			}
			for pre := strings.Join(segs[:i], "/"); pre != "." && pre != "" && !checked[pre]; pre = path.Dir(pre) {
				if state[pre] != preDir && state[pre] != preImplied {
					return p, folded != 0
				}
				checked[pre] = true
			}
			break
		}
		p = foldFirstDotDot(p)
		folded++
	}
	if folded == 0 {
		return "", false
	}
	return p, true
}

// lazyDotDot is the rule for a ".." inside a link target. A target such as
// `/opt/route/../qa-db` means, to the kernel, "enter opt/route, then go up
// from wherever that is": when opt/route is a symlink the ".." applies to
// its target, not to the name. Folding it lexically before opt/route was
// looked at read `opt/qa-db` for a link that reaches `srv/nested/qa-db`
// (release check 2026-11-11: an apk database behind such a link read 0 of
// BusyBox's 7 findings, and a package.json behind one read nothing). So
// resolveLink folds a ".." only against the directory the link was reached
// through -- a real directory, since the link entry lives in it -- and
// leaves one that follows a component of the target itself in the path. The
// pass treats the component before it as an ancestor (resolvePass): a
// symlink entry there re-roots the path, a file there ends it, and when no
// layer has an entry at it the ".." is folded after the pass and the path
// queued again, one more hop. A hardlink's target is an archive name and is
// folded whole.
//
// joinLazy appends rest to base, dropping empty and "." segments and keeping
// every "..": the shape resolvePass reads.
func joinLazy(base, rest string) string {
	var segs []string
	for _, c := range strings.Split(base+"/"+rest, "/") {
		if c != "" && c != "." {
			segs = append(segs, c)
		}
	}
	return strings.Join(segs, "/")
}

// normaliseLazy is normaliseEntry for a wanted path that may hold a "..":
// leading slashes and "." segments go, the ".." stays for the pass.
func normaliseLazy(name string) string {
	return joinLazy("", name)
}

// foldFirstDotDot applies the first ".." in p to the segment before it (or
// drops it at the root).
func foldFirstDotDot(p string) string {
	segs := strings.Split(p, "/")
	for i, c := range segs {
		if c != ".." {
			continue
		}
		if i == 0 {
			segs = segs[1:]
		} else {
			segs = append(segs[:i-1], segs[i+1:]...)
		}
		break
	}
	return strings.Join(segs, "/")
}

// follow turns a link found in layer i into the query for its target.
//
// The two kinds resolve differently, twice over. A symlink's target is
// relative to the link's own directory; a hardlink's is relative to the
// archive root -- treating a hardlink like a symlink turns
// "usr/lib/os-release" into "etc/usr/lib/os-release" and finds nothing. And a
// symlink's target is looked up from the newest layer, a hardlink's from its
// own entry in this layer down (see query).
//
// Per query, not per entry: two queries can reach one symlink through
// different hardlinks and resolve its relative target from different
// directories.
func follow(q query, hit layerHit, i, newest int) query {
	top, before := newest, noCeiling
	if hit.hard {
		top, before = i, hit.pos
	}
	linkDir := q.dir
	if hit.rest != "" {
		// A symlink at an ancestor resolves from that ancestor's own
		// directory, and the rest of the path continues below its target.
		ancestor := strings.TrimSuffix(q.path, "/"+hit.rest)
		linkDir = path.Dir(ancestor)
	}
	target := resolveLink(linkDir, hit.linkname, hit.hard)
	if hit.rest != "" {
		// The rest continues below the target as the kernel continues it,
		// a ".." in it applied once the target's own components are known
		// (lazyDotDot), not folded against a name that may be a link.
		target = joinLazy(target, hit.rest)
	}
	dir := q.dir // a hardlink keeps the directory it was reached through
	if !hit.hard {
		dir = path.Dir(target)
	}
	via := q.via
	if i > via {
		via = i
	}
	return query{path: target, want: q.want, top: top, before: before, dir: dir, links: q.links + 1, via: via}
}

// hiddenFrom reports whether a whiteout hides q's path from a read of layer
// i: the marker must sit above i (a whiteout affects lower layers only) and at
// or below q.top (a hardlink made in a lower layer never sees a later layer's
// deletions) -- and, in layer q.top itself, before q.before (nor a deletion
// later in its own layer). The directory and opaque rules are isDeleted's and
// underAnyOpaque's.
func hiddenFrom(q query, i int, deleted, opaque []whiteout) bool {
	reach := func(w whiteout) bool {
		return w.layer > i && w.layer <= q.top && (w.layer < q.top || w.pos < q.before)
	}
	for _, d := range deleted {
		if reach(d) && (q.path == d.name || strings.HasPrefix(q.path, d.name+"/")) {
			return true
		}
	}
	for _, o := range opaque {
		if reach(o) && (o.name == "." || strings.HasPrefix(q.path, o.name+"/")) {
			return true
		}
	}
	return false
}

// resolveLink turns a link target into a path from the image root.
//
// A SYMLINK's relative target is relative to the directory the link was
// reached through (query.dir), which is why that directory is needed and not
// just the target. A HARDLINK's Linkname is always relative to the archive
// root instead, so joining it to any directory would invent a path that does
// not exist.
//
// A ".." in a symlink's target is folded only while it still applies to dir
// (the link's own, real directory); one that follows a component of the
// target is kept for the pass to apply (lazyDotDot). An absolute target's
// leading ".." is dropped at the root, as the kernel drops it.
func resolveLink(dir, target string, hard bool) string {
	if hard {
		return normaliseEntry(target)
	}
	var segs []string
	if !strings.HasPrefix(target, "/") {
		segs = strings.Split(normaliseEntry(dir), "/")
		if len(segs) == 1 && segs[0] == "" {
			segs = nil
		}
	}
	own := 0 // components of the target itself pushed so far
	for _, c := range strings.Split(target, "/") {
		switch c {
		case "", ".":
		case "..":
			switch {
			case own > 0:
				segs = append(segs, "..")
				own++
			case len(segs) > 0:
				segs = segs[:len(segs)-1]
			}
		default:
			segs = append(segs, c)
			own++
		}
	}
	return strings.Join(segs, "/")
}

// isDeleted reports whether a whiteout covers this path.
//
// A whiteout names a path, and that path may be a directory: `RUN rm -rf
// /lib/apk` emits `lib/.wh.apk`, which deletes everything beneath it. Matching
// only exactly would leave the packages of a deleted apk database reported as
// installed.
func isDeleted(name string, deleted map[string]bool) bool {
	if deleted[name] {
		return true
	}
	for d := range deleted {
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// shadowAncestors records, as not a file, every directory strictly below root
// that name sits under: an entry at "root/x/y" in this layer makes "root/x" a
// directory here, so a lower layer's regular file "root/x" is shadowed and
// must not be returned (audit A10). A file turned into a directory carries no
// ".wh.<name>", so the whiteout rules never see it. Recorded whatever the
// entry is -- a file, a directory, a whiteout or opaque marker -- because each
// proves the directory exists in this layer; a whiteout that hides the
// directory itself also hides the lower file, so marking it is never wrong.
// Into the layer's own last-entry map, not the cross-layer one, so a later
// entry of the same layer that puts a file back at "root/x" wins as any later
// entry does (audit 2026-10-22 P4).
func shadowAncestors(last map[string]underHit, name, root string) {
	if !strings.HasPrefix(name, root+"/") {
		return
	}
	for p := path.Dir(name); p != root && p != "." && p != "/"; p = path.Dir(p) {
		last[p] = underHit{kind: hitGone}
	}
}

func underAnyOpaque(name string, dirs []string) bool {
	for _, d := range dirs {
		if d == "." {
			return true
		}
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return false
}

// normaliseEntry makes tar names comparable. Builders disagree on the leading
// "./" and on trailing slashes for directories, and comparing raw names makes a
// lookup succeed or fail depending on which tool built the image — an empty
// inventory rather than an error.
func normaliseEntry(name string) string {
	n := path.Clean("/" + name)
	return strings.TrimPrefix(n, "/")
}

// readLayer streams one layer's tar entries to visit.
//
// ctx is checked before every entry (D112), so a cancelled or expired scan
// stops at the next entry rather than at the end of the layer — a layer is
// the unit an attacker controls the size of, and a scan makes several full
// passes over every one. The error is ctx's own, unwrapped here, so
// errors.Is still recognises it after each caller's "read layer <diff id>"
// wrapping names where the walk was.
//
// A single entry is not interrupted part-way. A wanted one is bounded in
// size by MaxFileBytes; an unwanted one is skipped by tar.Reader.Next, which
// reads through it before the next check runs, so a docker-archive or
// oci-dir layer holding one enormous entry delays an expired context by
// however long that entry takes to decompress. A registry layer does not
// have that gap: its blob is fetched on a request carrying the same context,
// so the read itself fails once the context is done.
func readLayer(ctx context.Context, l Layer, visit func(name string, h *tar.Header, r io.Reader) error) error {
	rc, err := l.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			// The archive's end marker is not the stream's end: drain to EOF
			// so the layer's digest is checked before its entries count
			// (D123). Returning here was a clean scan of unverified bytes.
			return drainLayer(ctx, rc)
		}
		if err != nil {
			return err
		}
		// Directory entries are visited too: a directory at a wanted path, or
		// at a file's place in a lower layer, shadows that file (A10). Every
		// visitor reads only TypeReg entries as file content.
		if err := visit(normaliseEntry(h.Name), h, tr); err != nil {
			return err
		}
	}
}
