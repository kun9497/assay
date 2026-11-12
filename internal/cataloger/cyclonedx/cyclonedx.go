// Package cyclonedx turns a CycloneDX SBOM into the normalized inventory.
//
// This is a Cataloger like any other: later slices add image and binary
// catalogers that produce the same pkgmeta.Target, so nothing downstream
// changes when they arrive.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/version"
)

// Stats records what the cataloger could not use. Reported rather than
// discarded: a package silently dropped here is indistinguishable from a
// package with no vulnerabilities.
type Stats struct {
	Components                  int
	Cataloged                   int
	SkippedNoPURL               int
	SkippedNoVersion            int
	SkippedUnsupportedEcosystem int
	// SerialNumber (CycloneDX) and DocumentNamespace (SPDX) are the SBOM's
	// own identity as its producer wrote it, carried for the scan's
	// provenance record (D120). Not counts: every other cataloger leaves both
	// empty, and nothing sums them.
	SerialNumber      string
	DocumentNamespace string
}

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SerialNumber string      `json:"serialNumber"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

// metadata carries the document's subject: metadata.component is the slot
// CycloneDX reserves for the thing the SBOM is about. For an image SBOM that
// is the image (syft: a purl-less container); for a library's own SBOM it is
// the library, and a generator may nest the inventory under it
// (metadata.component.components) instead of, or as well as, bom.components.
type metadata struct {
	Component *component `json:"component"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	// CycloneDX lets a component carry its own components array. Reading only
	// the top level would make those packages invisible — not skipped, but
	// absent from every counter, which is worse than a counted skip because
	// nothing in the report hints they existed.
	Components []component `json:"components"`
	Properties []property  `json:"properties"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Parse(r io.Reader) (pkgmeta.Target, Stats, error) {
	var doc bom
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("decode CycloneDX: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BOMFormat)
	}

	var (
		target pkgmeta.Target
		stats  Stats
	)
	// syft emits the distro as a component of type "operating-system", not on
	// metadata.component — and the real fixture puts it last (components[16] of
	// 17), after the packages that need its release. So the whole document is
	// read for the distro in a first pass, before packages are cataloged in a
	// second: a single forward pass would catalog every apk package unkeyed.
	//
	// QA 2026-11-10: the operating-system component is read where it sits.
	// A distro package is keyed by the OS declared beside it -- among its own
	// siblings -- or, failing one, by the nearest unambiguous one above it,
	// so an OS component nested with its packages under metadata.component
	// keys them (Alpine and busybox moved under the subject read 0 findings,
	// not evaluated, exit 2), and one branch's OS never keys another
	// branch's packages. See osContext.
	top := contextFor(doc.Components, osContext{})
	target.Distro = documentDistro(doc, top)

	catalog(doc.Components, top, &target, &stats)
	if doc.Metadata.Component != nil {
		catalogSubject(*doc.Metadata.Component, top, &target, &stats)
	}
	stats.SerialNumber = doc.SerialNumber
	return target, stats, nil
}

// catalogSubject reads metadata.component after bom.components (QA
// 2026-11-02, "CycloneDX subject"). Until then the reader walked
// bom.components only, so a vulnerable library written as the document's
// subject -- lodash 4.17.20 as metadata.component, the shape a library's own
// SBOM takes -- or nested under the subject was never cataloged: not
// scanned, not counted, in no skip bucket, exit 0 under --fail-on low
// --fail-on-incomplete=target. The subject is excluded only by what it IS,
// the rule #230 set for SPDX's DESCRIBES (spdx.pseudoPackageShape): a
// document-root shape -- no purl (syft's container), a pkg:oci purl (Red
// Hat's image), a purl without a version (a product named without a build)
// -- is dropped uncounted exactly as before, so the one syft fixture still
// counts four components; anything else the subject is gets whatever a
// top-level twin would have got, a candidate or a counted skip.
//
// The subject's own nested components are the inventory when a generator
// writes it there, so they are cataloged like top-level components -- every
// skip counted, no pseudo-package rule -- and the same walk applies to their
// children.
//
// Dedupe: a generator that names the root package in its own inventory lists
// one package twice, as subject and as component. Cataloging the subject
// tree second, a package bom.components already yielded is dropped
// uncounted here, so the report says one package and one finding, not two
// -- and the dropped listing's evidence (its locations, a source identity
// only it carried) is folded onto the kept one, so the report still shows
// every place the document listed the package. The dedupe is the subject
// tree against bom.components and nothing else: two top-level listings, or
// two listings both nested under the subject, were never read as one
// package and stay two, so where a generator put its inventory does not
// change how many packages it holds.
func catalogSubject(subject component, ctx osContext, target *pkgmeta.Target, stats *Stats) {
	// The dedupe base is fixed before the subject tree adds anything to
	// target.Packages: everything bom.components yielded, and only that.
	base := len(target.Packages)
	// Catalog the subject once, preserving the OS context of each branch.
	all := pkgmeta.Target{Packages: append([]pkgmeta.Package{}, target.Packages...)}
	var subjectStats Stats
	catalogOne(subject, ctx, &all, &subjectStats)
	if len(all.Packages) == base && pseudoSubjectShape(subject, subjectStats) {
		subjectStats = Stats{} // a document root is not a counted skip
	}
	catalog(subject.Components, childContext(subject, ctx), &all, &subjectStats)
	subjectPackages := all.Packages[base:]
	// Skips are counted here. Cataloged components are counted only when
	// the merge retains a separate inventory entry.
	stats.Components += subjectStats.Components - len(subjectPackages)
	stats.SkippedNoPURL += subjectStats.SkippedNoPURL
	stats.SkippedNoVersion += subjectStats.SkippedNoVersion
	stats.SkippedUnsupportedEcosystem += subjectStats.SkippedUnsupportedEcosystem
	if base == 0 {
		target.Packages = subjectPackages
		stats.Components += len(subjectPackages)
		stats.Cataloged += len(subjectPackages)
		return
	}
	keyed := keyedReleases(all.Packages)
	// The key a merge adopts comes from the subject tree alone -- the
	// listings that merge into the base -- never from another top-level
	// listing, which the top-vs-top rule keeps a separate package: a keyed
	// top-level twin must not key an unkeyed one through a third, unkeyed
	// listing under the subject (PR #277 review). Counted once: counting it
	// again per identity made the subject walk quadratic -- a 1,000-package
	// SBOM took 648 ms and 490 MB where it had taken 32 ms and 3 MB
	// (release check 2026-11-11).
	subjectKeyed := keyedReleases(subjectPackages)
	for id, sk := range subjectKeyed {
		r := keyed[id]
		if sk.n != 1 {
			r.key = ""
		}
		keyed[id] = r
	}
	for id, r := range keyed {
		if _, inSubject := subjectKeyed[id]; !inSubject {
			r.key = ""
			keyed[id] = r
		}
	}
	d := &dedupe{keyed: keyed}
	typed := map[string]bool{}
	for _, p := range subjectPackages {
		if p.Arch != "" {
			typed[bareIdentity(p)] = true
		}
	}
	// Process concrete installs before bare copies of the same identity:
	// a bare subject and a bare top listing might state different source
	// versions, either of which the concrete install could rule out.
	var deferred []pkgmeta.Package
	for _, p := range subjectPackages {
		if p.Arch == "" && typed[bareIdentity(p)] {
			deferred = append(deferred, p)
			continue
		}
		mergeDeduped(p, base, d, target, stats)
	}
	for _, p := range deferred {
		mergeDeduped(p, base, d, target, stats)
	}
	weighBareListings(d, target, stats, all.Packages[:base])
}

// weighBareListings lends every bare top-level listing of an identity, as
// stated, to each install of it -- all of them together, after the whole
// document is read, so the document's order decides nothing. An install
// takes the evidence of every bare listing it does not contradict; when two
// of those contradict EACH OTHER the install is left unjudged with both
// values in the reason (D165): the document states its source two ways and
// the install states none. Weighing as each install was met (release check
// of main 60c512c) had judged an install that joined a bare listing before
// the contradicting ones were read -- `[u13, u14, none]` with the sourceless
// install last read 90 findings and exit 0, `[u13, none, u14]` 70 and exit 2
// -- because a join weighed nothing and an own weighed only what had been
// joined by then, and the pair it named was the first two, one of which
// stated no source and so marked nothing.
//
// A stable source order gives the same contradiction when more than two
// candidates state different versions.
func weighBareListings(d *dedupe, target *pkgmeta.Target, stats *Stats, originalTop []pkgmeta.Package) {
	if len(d.pooled) == 0 {
		return
	}
	// A subject installation can correspond to more than one original
	// bare top-level listing. Replacing one slot with the install must not
	// leave its other plausible source versions outside the candidate set.
	promoted := map[string]int{}
	for _, e := range d.pooled {
		if originalTop[e.twin].Arch == "" {
			promoted[bareIdentity(e.p)] = e.twin
		}
	}
	moved := map[int]bool{}
	for i, p := range target.Packages[:len(originalTop)] {
		if p.Arch != "" || unplaceable(p, d.keyed) {
			continue
		}
		if twin, ok := promoted[bareIdentity(p)]; ok {
			d.pooled = append(d.pooled, pooledListing{p: p, twin: twin})
			moved[i] = true
		}
	}
	pool := map[string][]int{}
	for i, e := range d.pooled {
		k := bareIdentity(e.p)
		pool[k] = append(pool[k], i)
	}
	for _, indices := range pool {
		sort.SliceStable(indices, func(i, j int) bool {
			a, b := d.pooled[indices[i]].p, d.pooled[indices[j]].p
			if a.Source == nil || b.Source == nil {
				return a.Source == nil && b.Source != nil
			}
			if a.Source.Name != b.Source.Name {
				return a.Source.Name < b.Source.Name
			}
			return a.Source.Version < b.Source.Version
		})
	}
	lent := make([]bool, len(d.pooled))
	// p holds the complete evidence from this architecture, before any bare
	// listings are lent. A later same-arch record can supply the source
	// version a shorter top-level record omitted.
	for idx, p := range target.Packages {
		if p.Arch == "" {
			continue
		}
		for _, i := range pool[bareIdentity(p)] {
			s := d.pooled[i].p
			// A bare record keyed to one of several plausible releases
			// cannot decide the release of an unkeyed installation.
			if p.Ecosystem == "" && s.Ecosystem != "" && ambiguous(s, d.keyed) {
				continue
			}
			if (s.Ecosystem == "" || p.Ecosystem == "" || s.Ecosystem == p.Ecosystem) && !contradicts(p, s) {
				// The install's own qualifiers win the purl; what the bare
				// listing alone states is carried (mergePURL).
				keepEvidence(&target.Packages[idx], s)
				target.Packages[idx].PURL = mergePURL(target.Packages[idx].PURL, s.PURL, target.Packages[idx].Ecosystem)
				lent[i] = true
			}
		}
	}
	// A pooled listing that contradicts every install it could be: the
	// document's inconsistency is reported on this listing -- keyed as its
	// twins are, so the report says why it is not judged rather than that
	// nothing covers it -- and the installs are judged on their own
	// statements (D165). The twins share one release (archTwins refuses two),
	// and that release is this listing's too: taken from the twin directly,
	// since the subject-tree rule withholds a key the top-level twins alone
	// give (PR #277 review) and this listing carries it to no other package.
	// The key and the twin named in the reason are taken from ALL of the
	// identity's installs, not from whichever install the listing happened
	// to match first: with one install keyed and another not, the first
	// match -- the document's order -- had decided whether the unlent
	// listing carried a key, and with it whether its skip was the target's
	// (exit 2 under --fail-on-incomplete=target) or nobody's (exit 0)
	// (release review of v0.18.0, 2026-11-12).
	// Per listing, not per bare identity: two releases' listings of one
	// name and version share a bare identity, and a map keyed on it had
	// let the Debian 12 listing's twin name the Debian 11 listing's
	// reason ("2 and 2" for a conflict of 2 and 7; independent review of
	// v0.18.0, 2026-11-12).
	keyOf, twinOf := identityKeys(target.Packages, d.pooled, lent)
	for i, e := range d.pooled {
		if lent[i] {
			continue
		}
		p := e.p
		if p.Ecosystem == "" && keyOf[i] != ambiguousKey {
			p.Ecosystem = keyOf[i]
		}
		twin := target.Packages[e.twin]
		if j, ok := twinOf[i]; ok {
			twin = target.Packages[j]
		}
		markSourceContradiction(&p, p, twin)
		target.Packages = append(target.Packages, p)
		stats.Components++
		stats.Cataloged++
	}
	// Unlent entries have just been appended with their contradiction.
	// Remove the old slots of the entries moved into the pool.
	if len(moved) > 0 {
		kept := target.Packages[:0]
		for i, p := range target.Packages {
			if !moved[i] {
				kept = append(kept, p)
			}
		}
		target.Packages = kept
		stats.Components -= len(moved)
		stats.Cataloged -= len(moved)
	}
}

// identityKeys is, per unlent pooled listing (indexed as pooled is), the one
// release the arch-stating installs it could be are keyed to (archTwins
// refuses two, so the non-empty keys agree) and the install its reason names:
// the lowest by source name and version among those it contradicts, so the
// reason reads the same in every document order. An install of another
// release is not a candidate (the archTwins rule): with Debian 11 and Debian
// 12 both listing one name and version, a map keyed on the bare identity had
// let the Debian 12 install name the Debian 11 listing's reason -- "2 and 2"
// for a conflict of 2 and 7 (independent review of v0.18.0, 2026-11-12).
func identityKeys(pkgs []pkgmeta.Package, pooled []pooledListing, lent []bool) (keyOf map[int]string, twinOf map[int]int) {
	keyOf, twinOf = map[int]string{}, map[int]int{}
	for i, e := range pooled {
		if lent[i] {
			continue
		}
		id := bareIdentity(e.p)
		for j, q := range pkgs {
			if q.Arch == "" || bareIdentity(q) != id {
				continue
			}
			if q.Ecosystem != "" && e.p.Ecosystem != "" && q.Ecosystem != e.p.Ecosystem {
				continue
			}
			switch {
			case q.Ecosystem == "":
			case keyOf[i] == "":
				keyOf[i] = q.Ecosystem
			case keyOf[i] != q.Ecosystem:
				// An unkeyed listing whose installs are keyed to two
				// releases belongs to neither provably (the indexOfPackage
				// rule, PR #270 review): it stays unkeyed in every order
				// rather than taking whichever release came first.
				keyOf[i] = ambiguousKey
			}
			if !contradicts(e.p, q) {
				continue
			}
			if k, ok := twinOf[i]; !ok || sourceLess(q, pkgs[k]) {
				twinOf[i] = j
			}
		}
	}
	return keyOf, twinOf
}

// ambiguousKey marks, in identityKeys' keyOf, an unkeyed listing whose
// candidate installs are keyed to two releases.
const ambiguousKey = "\x00ambiguous"

// sourceLess orders installs by their stated source, name then version,
// with an unstated source first.
func sourceLess(a, b pkgmeta.Package) bool {
	switch {
	case a.Source == nil || b.Source == nil:
		return a.Source == nil && b.Source != nil
	case a.Source.Name != b.Source.Name:
		return a.Source.Name < b.Source.Name
	default:
		return a.Source.Version < b.Source.Version
	}
}

// bareIdentity is identity without the architecture: what a bare listing
// and an arch-stating one of one package share.
func bareIdentity(p pkgmeta.Package) string {
	return p.Type + "\x00" + p.Name + "\x00" + p.Version
}

// dedupe is the state the subject walk's merges share (catalogSubject).
type dedupe struct {
	keyed map[string]releases
	// pooled holds the original bare evidence from either side of a join.
	// No release or source obtained from an arch-stating twin enters it.
	pooled []pooledListing
}

// pooledListing is one bare listing and the install it initially matched.
type pooledListing struct {
	p    pkgmeta.Package
	twin int
}

// mergeDeduped compares a subject listing against the original top-level
// inventory. An arch-less listing's own evidence is retained separately
// until the document's complete, architecture-specific records are known.
func mergeDeduped(p pkgmeta.Package, base int, d *dedupe, target *pkgmeta.Target, stats *Stats) {
	top := target.Packages[:base]
	if p.Arch == "" {
		if twins := archTwins(top, p, d.keyed); len(twins) > 0 {
			d.pooled = append(d.pooled, pooledListing{p: p, twin: twins[0]})
			return
		}
	}
	i := indexOfPackage(top, p, d.keyed)
	if i < 0 {
		target.Packages = append(target.Packages, p)
		stats.Components++
		stats.Cataloged++
		return
	}
	kept := &top[i]
	if kept.Arch == "" && p.Arch != "" {
		d.pooled = append(d.pooled, pooledListing{p: *kept, twin: i})
		*kept = p
		return
	}
	// The aggregate across architectures is for detecting ambiguity only.
	// Only this architecture or an arch-less declaration can supply a key.
	k := d.keyed[identity(p)]
	if p.Arch != "" {
		k = keyFor(p, d.keyed)
	} else if kept.Arch != "" {
		k = keyFor(*kept, d.keyed)
	}
	if kept.Ecosystem == "" && k.n == 1 {
		kept.Ecosystem = k.key
	}
	if kept.Arch != "" && p.Arch == "" && contradicts(*kept, p) {
		if p.Ecosystem == "" {
			p.Ecosystem = kept.Ecosystem
		}
		markSourceContradiction(&p, p, *kept)
		target.Packages = append(target.Packages, p)
		stats.Components++
		stats.Cataloged++
		return
	}
	keepEvidence(kept, p)
	if kept.PURL != p.PURL {
		kept.PURL = mergePURL(kept.PURL, p.PURL, kept.Ecosystem)
	}
}

// archTwins is every listing in pkgs that states an architecture and is
// otherwise p's identity -- p stating none -- when the document keys that
// identity to at most one release. The twins of two releases are refused as
// ambiguous, as indexOfPackage refuses them.
func archTwins(pkgs []pkgmeta.Package, p pkgmeta.Package, keyed map[string]releases) []int {
	if unplaceable(p, keyed) {
		return nil
	}
	var out []int
	for i, q := range pkgs {
		if q.Arch != "" && q.Type == p.Type && q.Name == p.Name && q.Version == p.Version && (q.Ecosystem == "" || p.Ecosystem == "" || q.Ecosystem == p.Ecosystem) {
			out = append(out, i)
		}
	}
	return out
}

// markSourceContradiction marks kept as unjudged because the document
// states its source two ways, a's and b's (D165), naming both.
func markSourceContradiction(kept *pkgmeta.Package, a, b pkgmeta.Package) {
	if a.Source == nil || b.Source == nil {
		return
	}
	if a.Source.Name != b.Source.Name {
		markContradiction(kept, "source", a.Source.Name, b.Source.Name)
		return
	}
	markContradiction(kept, "source "+a.Source.Name+" at", a.Source.Version, b.Source.Version)
}

// mergePURL is kept's purl carrying every qualifier other states too: a
// join must not drop what one listing confirmed (release check of main
// b732cac: the twin's purl replaced the kept one whole, and a VEX statement
// scoped by the dropped `distro=` no longer reached the install). On a
// qualifier both state, kept's value stands: the install is the kept
// listing, and the other's value for the same qualifier is at best the same
// and at worst another listing's (release check of main 60c512c: a bare
// twin's `distro=alpine-3.20` overwrote the install's `alpine-3.19`, the
// release the package was evaluated under, and a VEX statement written for
// 3.20 exonerated the 3.19 install -- 2 findings hidden, exit 0). A
// `distro=` from either side is carried only when it names the release the
// package is keyed to (ecosystem); one naming another release is the
// document contradicting itself and is left off, so the purl the VEX
// matcher sees agrees with the evaluation. A version the kept purl lacks
// (a top-level purl written without `@version`) is taken from the other,
// which lists the same version by identity, so a version-scoped statement
// still reaches the install.
func mergePURL(kept, other, ecosystem string) string {
	kp, kerr := pkgmeta.ParsePURL(kept)
	op, oerr := pkgmeta.ParsePURL(other)
	switch {
	case kerr != nil:
		return other
	case oerr != nil:
		return kept
	}
	if kp.Qualifiers == nil {
		kp.Qualifiers = map[string]string{}
	}
	if kp.Version == "" {
		kp.Version = op.Version
	}
	for k, v := range op.Qualifiers {
		if _, stated := kp.Qualifiers[k]; !stated {
			kp.Qualifiers[k] = v
		}
	}
	// Language packages use their language ecosystem regardless of the OS
	// they are installed on. Their distro qualifier still scopes a VEX.
	_, language := pkgmeta.EcosystemForPURLType(kp.Type)
	if d, ok := kp.Qualifiers["distro"]; ok && ecosystem != "" && !language {
		if eco, known := pkgmeta.EcosystemForDistroQualifier(d); known && eco != ecosystem {
			if od, ok := op.Qualifiers["distro"]; ok {
				if oeco, known := pkgmeta.EcosystemForDistroQualifier(od); known && oeco == ecosystem {
					kp.Qualifiers["distro"] = od
					return kp.String()
				}
			}
			delete(kp.Qualifiers, "distro")
		}
	}
	return kp.String()
}

// contradicts reports whether two listings of one package state different
// sources: different names, or the same name at two versions under the
// package's own ordering -- keepEvidence's contradiction, asked before a
// join rather than marked after one.
func contradicts(a, b pkgmeta.Package) bool {
	if a.Source == nil || b.Source == nil {
		return false
	}
	if a.Source.Name != b.Source.Name {
		return true
	}
	av, bv := a.Source.Version, b.Source.Version
	if av == "" || bv == "" {
		return false
	}
	eco := a.Ecosystem
	if eco == "" {
		eco = b.Ecosystem
	}
	return !sameVersion(eco, av, bv)
}

// indexOfPackage is the position in pkgs of the package p is a second
// listing of, or -1. The identity is the one the matcher judges: type, name,
// version and ecosystem key. It is deliberately NOT the purl string: a
// package's type, name and ecosystem are functions of its purl, but its
// version is not -- a purl with no @version takes component.version
// (catalogOne, pkgmeta.ResolveDistroPURL) -- so an equal purl can name two
// versions, and deduping on it dropped a vulnerable subject because
// bom.components carried the same bare purl at the fixed version. A
// qualifier-only difference (syft's per-document package-id, two install
// paths) is the same package, which the field comparison says and a
// verbatim purl comparison would not.
func indexOfPackage(pkgs []pkgmeta.Package, p pkgmeta.Package, keyed map[string]releases) int {
	// A concrete copy is stronger evidence of identity than a compatible
	// arch-less record. Save the latter as a fallback regardless of order.
	compatible := -1
	for i, q := range pkgs {
		if q.Type == p.Type && q.Name == p.Name && q.Version == p.Version && q.Ecosystem == p.Ecosystem && sameArch(q, p) {
			if q.Arch == p.Arch {
				return i
			}
			if compatible < 0 {
				compatible = i
			}
		}
	}
	if compatible >= 0 {
		return compatible
	}
	// D166: an OS nested under the subject keys the subject's listing of a
	// package, while its top-level twin, with no OS beside it, stays
	// unkeyed. They are still one package listed twice -- and the keyed one
	// is the one that can be judged (PR #270 review: two packages, one of
	// them a spurious not-evaluated, exit 2 under the strict gate). Only a
	// unique twin is that package: an unkeyed listing beside busybox keyed
	// to Alpine 3.19 AND busybox keyed to 3.20 belongs to neither provably,
	// and merging it into the first one attached its install path to that
	// release's findings -- the other release's when the document listed
	// them the other way round (PR #270 review). It stays its own package,
	// unkeyed and reported not evaluated.
	if ambiguous(p, keyed) {
		return -1
	}
	match := -1
	for i, q := range pkgs {
		if q.Type == p.Type && q.Name == p.Name && q.Version == p.Version && (q.Ecosystem == "" || p.Ecosystem == "") && sameArch(q, p) {
			if ambiguous(q, keyed) {
				// The kept listing states no architecture and the document
				// keys its identity to two releases through two
				// architectures: it belongs to neither provably (PR #277
				// review -- the PR #270 mirror case, arch-shaped).
				return -1
			}
			if match >= 0 {
				// Two releases are refused above (keyed); two top-level
				// listings keyed to ONE release are judged alike whichever
				// takes the evidence, so a mutation of this line survives.
				return -1
			}
			match = i
		}
	}
	return match
}

// unplaceable reports whether a bare listing cannot be placed with any one
// release's installs: it states no release of its own and the document keys
// its identity to more than one. A listing that NAMES its release
// (`distro=debian-11`) is placed with that release's installs however many
// releases the document holds -- archTwins and weighBareListings already
// hold the candidates to its key. Refusing it on the document's aggregate
// (review of the v0.18.1 branches, 2026-11-12) had sent it down
// indexOfPackage's first-match path, so a document listing one name and
// version under two releases read 3 packages and exit 0 in one order of its
// installs and 4 packages with a spurious not-evaluated listing and exit 2
// in the other; two bare listings of one release had been judged on a
// source the document contradicts in one order only; and a reason had named
// whichever same-release install came first.
func unplaceable(p pkgmeta.Package, keyed map[string]releases) bool {
	return p.Ecosystem == "" && ambiguous(p, keyed)
}

// ambiguous reports whether the document keys p's identity to more than
// one release. A listing that states an architecture meets only the twins
// of that architecture; one that states none meets them all, through the
// arch-less identity keyedReleases also counts.
func ambiguous(p pkgmeta.Package, keyed map[string]releases) bool {
	// keyFor's fallback is consulted here only through a listing stating
	// an architecture no keyed twin states; the kept listing it would meet
	// (indexOfPackage's second loop) is then arch-less and refused by its
	// own ambiguity, so a mutation reading the arch'd identity alone here
	// survives -- an equivalent, not a gap.
	return keyFor(p, keyed).n > 1
}

// keyFor is what the document keys p's identity to. A listing stating an
// architecture whose twins of that architecture state no key is keyed by
// what the document says of the name and version without one: a keyed
// listing with no arch beside two amd64 ones left the amd64 identity
// unkeyed, and the two were then compared unkeyed -- 25 findings one order,
// 0 the other (release check 2026-11-11, the QA 2026-11-11 item 1 shape
// with the arch left off the keyed record).
//
// Release check of main 5197df4: the fallback reads what records stating NO
// architecture key the name and version to -- not what every architecture's
// records together key theirs to, which had lent an aarch64-only Alpine 3.19
// to an unkeyed x86_64 install (4 findings and no not-evaluated for a
// document that keys x86_64 to nothing). A bare listing still meets every
// architecture's keys (keyedReleases' aggregate), since it may be any of them.
func keyFor(p pkgmeta.Package, keyed map[string]releases) releases {
	if p.Arch == "" {
		return keyed[identity(p)+anyArch]
	}
	if r, ok := keyed[identity(p)]; ok {
		return r
	}
	q := p
	q.Arch = ""
	return keyed[identity(q)]
}

// anyArch marks keyedReleases' aggregate of an identity's keys across every
// architecture, kept apart from the bare records' own entry.
const anyArch = "\x00*"

// identity is a package's type, name, version and -- when the purl states
// one -- architecture: what an unkeyed listing and its keyed twins share. Two
// listings of one name and version that state different architectures are
// two installs (QA 2026-11-11: an aarch64 busybox was merged into the x86_64
// one, its path put on that finding and its own not-evaluated count lost);
// a listing stating none is merged with either (sameArch).
func identity(p pkgmeta.Package) string {
	return p.Type + "\x00" + p.Name + "\x00" + p.Version + "\x00" + p.Arch
}

// sameArch is identity's architecture rule as a comparison.
func sameArch(a, b pkgmeta.Package) bool {
	return a.Arch == "" || b.Arch == "" || a.Arch == b.Arch
}

// releases is what the document keys one identity to: how many distinct
// ecosystem keys, and the key itself when there is exactly one.
type releases struct {
	n   int
	key string
}

// keyedReleases counts, per identity, the distinct ecosystem keys pkgs give
// it; an unkeyed listing counts for none. Every record is counted once more
// under its arch-less identity's anyArch aggregate, so an unkeyed listing
// that states no architecture meets its keyed twins' releases whatever
// architecture they state (keyFor).
func keyedReleases(pkgs []pkgmeta.Package) map[string]releases {
	seen := map[string]map[string]bool{}
	add := func(id, eco string) {
		if seen[id] == nil {
			seen[id] = map[string]bool{}
		}
		seen[id][eco] = true
	}
	for _, p := range pkgs {
		if p.Ecosystem == "" {
			continue
		}
		add(identity(p), p.Ecosystem)
		q := p
		q.Arch = ""
		add(identity(q)+anyArch, p.Ecosystem)
	}
	out := make(map[string]releases, len(seen))
	for id, ecos := range seen {
		r := releases{n: len(ecos)}
		if r.n == 1 {
			for eco := range ecos {
				r.key = eco
			}
		}
		out[id] = r
	}
	return out
}

// keepEvidence folds a dropped second listing onto the kept package: every
// location the document gave the package is evidence (D10), and a source
// identity (D8), SRPM name or module stream the kept listing lacks is taken
// from the dropped one -- a deb purl with ?upstream= on one listing and not
// the other must still be judged on its source. What the kept listing
// already states is never overwritten.
func keepEvidence(kept *pkgmeta.Package, dropped pkgmeta.Package) {
	kept.DistroContext = kept.DistroContext.Merge(dropped.DistroContext)
	// The keyed listing's key wins over an unkeyed twin's (indexOfPackage).
	if kept.Ecosystem == "" && dropped.Ecosystem != "" {
		kept.Ecosystem = dropped.Ecosystem
	}
	for _, loc := range dropped.Locations {
		if !hasLocation(kept.Locations, loc) {
			kept.Locations = append(kept.Locations, loc)
		}
	}
	// D165 (QA 2026-11-10): what either listing states about the source is
	// evidence whichever listing came first. A source named without a version
	// (deb `upstream=glibc`, no @version) states the name only -- the version
	// is unstated, not "the binary's own" -- so a version the other listing
	// gives is kept: without it libc6 2.31-13+deb11u14 from glibc
	// 2.31-13+deb11u13 read 25 findings one way round and 20 the other. Two
	// listings that state different source names, or the same name at two
	// versions, contradict each other, and the package is judged on neither
	// (Unevaluable), with a reason naming both, sorted so it reads the same
	// either way round. Copied in every arm, so the kept package never shares
	// a Source with the dropped one.
	switch {
	case dropped.Source == nil:
	case kept.Source == nil:
		src := *dropped.Source
		kept.Source = &src
	case dropped.Source.Name != kept.Source.Name:
		markContradiction(kept, "source", kept.Source.Name, dropped.Source.Name)
	default:
		switch kv, dv := kept.Source.Version, dropped.Source.Version; {
		case kv == "" && dv != "":
			src := *kept.Source
			src.Version = dv
			kept.Source = &src
		case dv != "" && !sameVersion(kept.Ecosystem, kv, dv):
			markContradiction(kept, "source "+kept.Source.Name+" at", kv, dv)
		}
	}
	if kept.Upstream == "" {
		kept.Upstream = dropped.Upstream
	}
	if kept.ModuleStream == "" {
		kept.ModuleStream = dropped.ModuleStream
	}
}

// sameVersion reports whether two spellings of a source version are one
// version under the ecosystem's own ordering (D9): Debian's
// 0:2.31-13+deb11u13 is 2.31-13+deb11u13, which a string comparison called
// a contradiction and left the package unjudged (PR #269 review). A key with
// no comparer, or a version it cannot parse, falls back to the strings
// themselves -- two values that cannot be shown equal are not assumed to be.
func sameVersion(ecosystem, a, b string) bool {
	if a == b {
		return true
	}
	c, ok := version.For(ecosystem)
	if !ok {
		return false
	}
	r, err := c.Compare(a, b)
	return err == nil && r == 0
}

// markContradiction records, once, that the document's listings of kept
// state two different values of one thing (D165).
func markContradiction(kept *pkgmeta.Package, what, a, b string) {
	if kept.Unevaluable != "" {
		return
	}
	if b < a {
		a, b = b, a
	}
	kept.Unevaluable = fmt.Sprintf("the SBOM lists %s %s twice with %s two values, %s and %s; it is not judged on either",
		kept.Name, kept.Version, what, a, b)
}

func hasLocation(locs []pkgmeta.Location, loc pkgmeta.Location) bool {
	for _, l := range locs {
		if l == loc {
			return true
		}
	}
	return false
}

// pseudoSubjectShape mirrors spdx.pseudoPackageShape for a subject that
// yielded no package: no purl at all (syft's container, every image SBOM
// syft writes), a pkg:oci purl (Red Hat's container), or a parsed purl
// without a version (a product named without a build -- catalogOne counts
// that under SkippedNoVersion, and only that). A malformed purl is none of
// these and stays a counted SkippedNoPURL, as a top-level twin's would be.
func pseudoSubjectShape(subject component, scratch Stats) bool {
	if subject.PURL == "" {
		return true
	}
	if parsed, err := pkgmeta.ParsePURL(subject.PURL); err == nil && parsed.Type == "oci" {
		return true
	}
	return scratch.SkippedNoVersion == 1
}

// catalog walks components depth-first so nested ones are seen. Every path out
// of catalogOne increments exactly one counter, which is what lets the report's
// summary account for every component the document contained.
func catalog(components []component, ctx osContext, target *pkgmeta.Target, stats *Stats) {
	for _, c := range components {
		catalogOne(c, ctx, target, stats)
		catalog(c.Components, childContext(c, ctx), target, stats)
	}
}

func catalogOne(c component, ctx osContext, target *pkgmeta.Target, stats *Stats) {
	if c.Type == "operating-system" {
		// Described the target in the first pass (D7); it is not a package to
		// scan, and counting it here would inflate the component total.
		return
	}
	if c.Type == "file" {
		// Modern syft emits thousands of purl-less "file" components per
		// image — content-scanned files, not packages (6,161 of 6,306
		// top-level components measured on a real rockylinux:9 syft 1.51.0
		// SBOM). Counting them as SkippedNoPURL used to inflate Components
		// enough on its own to trip --fail-on-incomplete=target on a scan
		// that was otherwise complete. Excluded here the same way the
		// operating-system component is above: not counted anywhere, rather
		// than adding a Stats field for a bucket nothing needs to gate on —
		// the least new machinery, and consistent with the one exclusion
		// this file already had.
		return
	}
	stats.Components++
	if c.PURL == "" {
		stats.SkippedNoPURL++
		return
	}
	p, err := pkgmeta.ParsePURL(c.PURL)
	if err != nil {
		stats.SkippedNoPURL++
		return
	}

	var (
		eco          string
		version      string
		source       *pkgmeta.SourcePackage
		upstream     string
		moduleStream string
		arch         string
	)
	scope := ctx.scope()
	switch p.Type {
	case "apk", "rpm", "deb", "alpm":
		// D83/D84/D97. The shared core (internal/pkgmeta/distropurl.go): ecosystem
		// resolution from the target's distro with a per-purl "distro"
		// qualifier fallback (and, for rpm, a further repository_id
		// fallback), epoch prefixing, upstream->Source, the gpg-pubkey
		// filter, and rpmmod->ModuleStream. SPDX calls the identical
		// function, which is the point: CycloneDX and SPDX cannot judge one
		// installed package two different ways.
		res := pkgmeta.ResolveDistroPURL(p, c.Version, ctx.ecosystem, ctx.distro != nil)
		if ctx.distro == nil {
			// D165: no single native key in this branch. An explicit
			// distro on this OS package identifies its own installation.
			scope = pkgmeta.DistroScope{}
		}
		if res.Skip {
			// gpg-pubkey (a keyring entry, not an installed package) or an
			// arch=src SRPM (D84). Routed into the existing "unsupported
			// ecosystem" bucket rather than a new Stats field — the least new
			// machinery, and it is, like an unsupported purl type, a
			// component this cataloger deliberately never turns into a
			// package.
			stats.SkippedUnsupportedEcosystem++
			return
		}
		eco = res.Ecosystem
		version = res.Version
		source = res.Source
		upstream = res.Upstream
		moduleStream = res.ModuleStream
		arch = p.Qualifiers["arch"]
	default:
		var ok bool
		eco, ok = pkgmeta.EcosystemForPURLType(p.Type)
		if !ok {
			stats.SkippedUnsupportedEcosystem++
			return
		}
		version = p.Version
		if version == "" {
			version = c.Version
		}
		if p.Type == "gem" {
			version = pkgmeta.InstalledGemVersion(version, p.Qualifiers["platform"])
		}
	}
	if version == "" {
		// Nothing for a comparer to place inside a range. Counting it as
		// cataloged would claim the package was evaluated when it was not.
		stats.SkippedNoVersion++
		return
	}

	// apk, rpm, deb and alpm purls carry the distro name as their namespace
	// (pkg:apk/alpine/..., pkg:rpm/rhel/..., pkg:alpm/arch/...), which is not
	// part of the package identity: OSV's/Arch's own advisories name the
	// bare package ("openssl", not "alpine/openssl"; "libelf", not
	// "arch/libelf"), and the rpm namespace itself is not even stable —
	// syft 0.84.1 writes "rhel", syft 1.51.0 writes "redhat", for the same
	// distro. Prefixing either into the name here would make every distro
	// lookup miss its advisory, or miss it only on some SBOMs.
	name := p.Name
	if p.Namespace != "" && p.Type != "apk" && p.Type != "rpm" && p.Type != "deb" && p.Type != "alpm" {
		// The purl spec always separates namespace and name with "/"
		// (pkg:maven/group/artifact), but OSV's Maven advisories name the
		// package "group:artifact" — measured 12,457/12,457 live records.
		// Joining with "/" here would build a name OSV never publishes and
		// every Maven package would silently miss its advisory.
		sep := "/"
		if p.Type == "maven" {
			sep = ":"
		}
		name = p.Namespace + sep + p.Name
	}

	loc := pkgmeta.Location{Path: "sbom"}
	if path := propValue(c, "syft:location:0:path"); path != "" {
		loc.Path = path
	}
	if layer := propValue(c, "syft:location:0:layerID"); layer != "" {
		loc.LayerDigest = layer
	}

	pkg := pkgmeta.Package{
		Name:          name,
		Version:       version,
		Type:          p.Type,
		Ecosystem:     eco,
		PURL:          c.PURL,
		DistroContext: scope.ForInstallation(p.Qualifiers["distro"]),
		Locations:     []pkgmeta.Location{loc},
		Source:        source,
		Upstream:      upstream,
		ModuleStream:  moduleStream,
		// The architecture the purl states (distro types only): part of the
		// dedupe identity, nothing else here.
		Arch: arch,
	}
	switch p.Type {
	case "deb":
		// syft writes dpkg's source version twice: in the purl's upstream
		// qualifier ("name@version") and as the syft:metadata:sourceVersion
		// property. The purl is read first (the shared core), and the
		// property fills the version only when the purl named the source
		// without one -- a producer that writes the bare name in the purl
		// but still carries syft's property. The purl's own version is
		// never overwritten: the two agree when both exist, and the purl is
		// the statement SPDX readers see too.
		if pkg.Source != nil && pkg.Source.Version == "" {
			if v := propValue(c, "syft:metadata:sourceVersion"); v != "" {
				pkg.Source.Version = v
			}
		}
	case "apk":
		// syft reports the origin package name only via a CycloneDX property
		// (D8) — the shared core has no purl-qualifier equivalent to read
		// this from, so it is layered on here rather than in
		// pkgmeta.ResolveDistroPURL. Alpine binary packages carry their
		// source package's version, so leaving Version empty here is correct
		// rather than a gap: the binary's own version is the one the
		// comparer uses.
		if origin := propValue(c, "syft:metadata:originPackage"); origin != "" {
			pkg.Source = &pkgmeta.SourcePackage{Name: origin}
		}
	case "rpm":
		// D80. syft writes the module label as a CycloneDX property rather
		// than a purl qualifier (Red Hat's own SPDX documents do the
		// opposite — the shared core's "rpmmod" qualifier reading above), so
		// this is layered on the same way apk's origin property is: the
		// string-splitting itself is the moved, shared helper
		// (pkgmeta.ModuleStreamFromLabel), only the property read stays
		// here.
		if label := propValue(c, "syft:metadata:modularityLabel"); label != "" {
			if ms := pkgmeta.ModuleStreamFromLabel(label); ms != "" {
				pkg.ModuleStream = ms
			}
		}
	}
	target.Packages = append(target.Packages, pkg)
	stats.Cataloged++
}

// propValue returns the value of the first property named name, or "" if the
// component does not carry it. Every syft extension property read by this
// package goes through here so a missing one degrades to empty rather than a
// panic.
func propValue(c component, name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// osContext is the operating system a distro package is keyed by: the one
// its branch of the document declares (contextFor). distro nil means none
// applies -- none declared on the way down, or two different ones side by
// side at some level above it, which leaves every package beneath that level
// without one (the branch declares two; inheriting from further up would
// key it to an OS the branch itself contradicts) -- and the package falls
// back to its purl's distro qualifier, or an rpm's repository_id (D83);
// with no qualifier either it is cataloged unkeyed and the matcher reports
// it not evaluated, with the reason, rather than keyed to a guess.
// ecosystem is distro's key, "" when its release does not resolve (the same
// fall-back: unkeyed, reported, never guessed).
type osContext struct {
	distro       *pkgmeta.Distro
	ecosystem    string
	mixedRelease bool
	// family is a known distro declared with no version at all (contextFor):
	// it names the target for the report, keys nothing, and refuses an
	// inherited context of another family.
	family *pkgmeta.Distro
}

func (c osContext) scope() pkgmeta.DistroScope {
	if c.mixedRelease {
		return pkgmeta.DistroScope{Mixed: true}
	}
	if c.distro == nil {
		return releaseScope(c.family)
	}
	return releaseScope(c.distro)
}

func releaseScope(d *pkgmeta.Distro) pkgmeta.DistroScope {
	if d == nil {
		return pkgmeta.DistroScope{}
	}
	if d.VersionID == "" {
		return pkgmeta.DistroScope{Qualifier: d.ID}
	}
	return pkgmeta.DistroScope{Qualifier: d.ID + "-" + d.VersionID}
}

// contextFor is the context of a list of sibling components: the one
// operating system declared among them, if they declare exactly one; the
// inherited context when they declare none; and no context when they
// declare two different ones, because a package beside both cannot be told
// which it belongs to. Two OS components that describe the same distro and
// release are one declaration.
func contextFor(siblings []component, inherited osContext) osContext {
	var found *pkgmeta.Distro
	mixedRelease := false
	// family is a known distro declared among the siblings WITHOUT a key
	// (no version, or one no key is built from): it says which family the
	// packages beside it belong to and no more. It keys nothing itself, but
	// it refuses an inherited context of another family -- Debian declared
	// at the top does not key the busybox beside a version-less Alpine --
	// and leaves the purl's own distro qualifier to identify the package
	// (QA 2026-11-11). An OS whose ID this build does not know ("linux")
	// declares nothing.
	var family *pkgmeta.Distro
	for _, c := range siblings {
		d := distroOf(c)
		if d == nil {
			continue
		}
		if _, err := d.Ecosystem(); err != nil && d.VersionID == "" {
			// No release stated and none needed for a key -- Wolfi, Arch
			// and the other release-less ecosystems key from the ID alone
			// and are a context as a versioned OS is (release check
			// 2026-11-11: `wolfi` with no version beside openssl read 0 of
			// its 84 findings, while the same OS as the parent read all 84).
			// A known family declares the family; an unknown ID ("linux")
			// declares nothing. Either way it is not a context that would
			// switch the purl qualifier off. An OS that DOES state a
			// release no key is built from ("edge") is a context as before:
			// the document's own identity failed to resolve, and the purl
			// may not contradict it.
			if pkgmeta.KnownDistroID(d.ID) {
				if family != nil && !strings.EqualFold(family.ID, d.ID) {
					// Two families beside one package: it belongs to
					// neither provably, whichever was declared last
					// (release check 2026-11-11: `alpine` then `debian`
					// beside Debian 11 keyed busybox to Debian, 51
					// findings; `debian` then `alpine` read it as the
					// qualifier said, 2).
					return osContext{mixedRelease: true}
				}
				family = d
			}
			continue
		}
		if found == nil {
			found = d
			continue
		}
		if !sameDistro(found, d) {
			// Native packages still fall back to their own PURL/key. A
			// language package's VEX must retain the conflicting OS evidence.
			return osContext{mixedRelease: true}
		}
		if !mixedRelease && (found.ID != d.ID || found.VersionID != d.VersionID) {
			next := releaseScope(d)
			merged := releaseScope(found).Merge(next)
			mixedRelease = merged.Mixed
			if merged == next {
				found = d
			}
		}
	}
	if found != nil && family != nil && !strings.EqualFold(found.ID, family.ID) {
		return osContext{mixedRelease: true}
	}
	if found == nil {
		if family != nil {
			if inherited.distro != nil && !strings.EqualFold(inherited.distro.ID, family.ID) {
				return osContext{family: family}
			}
			if inherited.distro == nil {
				inherited.family = family
			}
		}
		return inherited
	}
	ctx := osContext{distro: found, mixedRelease: mixedRelease}
	if eco, err := found.Ecosystem(); err == nil {
		ctx.ecosystem = eco
	}
	return ctx
}

// childContext is the context parent's own components are keyed in. An
// operating-system component with children declares the OS they belong to,
// as an OS among them would (PR #270 review: metadata.component as Alpine
// with busybox directly under it left busybox unkeyed, and keyed it to a
// Debian declared at the top when there was one -- 51 false findings); an
// OS declared among the children is nearer still and comes first
// (contextFor).
func childContext(parent component, inherited osContext) osContext {
	// Only an OS that resolves to an ecosystem key overrides what the
	// children inherit: one with no version, or a name no key is built for
	// ("linux"), would leave them a distro with no key -- unkeyed, and with
	// the purl qualifier fallback switched off (PR #270 review).
	if d := distroOf(parent); d != nil {
		if eco, err := d.Ecosystem(); err == nil {
			inherited = osContext{distro: d, ecosystem: eco}
		} else if d.VersionID == "" && pkgmeta.KnownDistroID(d.ID) && inherited.distro != nil && !strings.EqualFold(inherited.distro.ID, d.ID) {
			// A known family with no release refuses an inherited context
			// of another family, as among siblings (contextFor): Alpine
			// with no version as the subject, Debian 11 at the top, read
			// its busybox as Debian -- 51 findings (QA 2026-11-11). An
			// inherited FAMILY of another ID is not refused: a family keys
			// nothing, so the children read the same either way.
			inherited = osContext{family: d}
		} else if err != nil && d.VersionID != "" {
			// A release no key is built from: the document's identity, as
			// a sibling OS of that shape is (contextFor).
			inherited = osContext{distro: d}
		}
	}
	return contextFor(parent.Components, inherited)
}

// documentDistro is the Target's distro, the one the scan reports and its
// end-of-life and coverage lines read: the top-level context's when the
// document declares one there, else the one the subject itself declares --
// metadata.component as an operating system, or one OS among its own
// children, the shape a container SBOM nests its OS in. An OS declared only
// in some other branch keys that branch's packages and does not name the
// whole target (PR #270 review: the report must not name a distro its
// top-level packages were not judged against).
func documentDistro(doc bom, top osContext) *pkgmeta.Distro {
	if top.distro != nil {
		return top.distro
	}
	if top.family != nil {
		return top.family
	}
	s := doc.Metadata.Component
	if s == nil {
		return nil
	}
	if d := distroOf(*s); d != nil {
		return d
	}
	return contextFor(s.Components, osContext{}).distro
}

// sameDistro reports whether two OS components declare one distro release:
// the same ecosystem key when both resolve to one (alpine 3.19.9 and 3.19.1
// are both Alpine:v3.19), else the same ID and VERSION_ID.
func sameDistro(a, b *pkgmeta.Distro) bool {
	ea, errA := a.Ecosystem()
	eb, errB := b.Ecosystem()
	if errA == nil && errB == nil {
		return ea == eb
	}
	return strings.EqualFold(a.ID, b.ID) && a.VersionID == b.VersionID
}

// distroOf reads one operating-system component, or nil for any other
// component or one that names no distro.
func distroOf(c component) *pkgmeta.Distro {
	if c.Type != "operating-system" {
		return nil
	}
	var d pkgmeta.Distro
	for _, p := range c.Properties {
		switch p.Name {
		case "syft:distro:id":
			d.ID = p.Value
		case "syft:distro:versionID":
			d.VersionID = p.Value
		case "syft:distro:prettyName":
			d.PrettyName = p.Value
		}
	}
	// Fall back to the component's own fields: the properties are a syft
	// extension, but name/version are spec and carry the same thing.
	if d.ID == "" {
		d.ID = c.Name
	}
	if d.VersionID == "" {
		d.VersionID = c.Version
	}
	if d.ID == "" {
		return nil
	}
	return &d
}
