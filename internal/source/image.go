package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// TargetKind says what a scan argument names. It exists because `assay scan X`
// has to mean all of these, and the wrong guess produces an error about the
// wrong subject — a Go binary read as an SBOM reports a malformed document.
//
// Classify (classify.go) is what decides, and it prints the answer, so a wrong
// guess is visible in the scan's output rather than inferred from a confusing
// downstream error.
type TargetKind int

const (
	TargetSBOM TargetKind = iota
	TargetImage
	TargetDirectory
	TargetGoBinary
	// TargetJar is a Java archive (.jar or .war), D70. Distro stays nil for it
	// the same way it does for TargetGoBinary and TargetDirectory (D7): a jar
	// is not an operating system.
	TargetJar
)

func (k TargetKind) String() string {
	switch k {
	case TargetSBOM:
		return "sbom"
	case TargetImage:
		return "image"
	case TargetDirectory:
		return "directory"
	case TargetGoBinary:
		return "go-binary"
	case TargetJar:
		return "jar"
	}
	// Not reachable through Classify, but a kind rendered as "" turns
	// "scanned X as a " into what reads as a rendering bug rather than an
	// unknown classification.
	return fmt.Sprintf("TargetKind(%d)", int(k))
}

type kind int

const (
	kindRegistry kind = iota
	kindTarball
	kindLayout
)

// Schemes are matched against a fixed set rather than by splitting on the first
// colon. Registry references contain colons of their own — a tag
// (alpine:3.19), a digest (repo@sha256:…), and a host port
// (registry.example.com:5000/team/app) — so "everything before the first colon
// is a scheme" routes real images to the tarball loader.
const (
	schemeTarball = "docker-archive:"
	schemeLayout  = "oci-dir:"
)

func classify(ref string) kind {
	switch {
	case strings.HasPrefix(ref, schemeTarball):
		return kindTarball
	case strings.HasPrefix(ref, schemeLayout):
		return kindLayout
	}
	return kindRegistry
}

// IsRegistryReference reports whether an image target is a registry
// reference rather than a docker-archive: tarball or an oci-dir: layout. Only
// a registry reference has a repository and tag that a VEX statement's image
// product can name (D121); the other two are identified by digest alone.
func IsRegistryReference(ref string) bool { return classify(ref) == kindRegistry }

// Open resolves a target to its layers. A registry reference reaches the
// network; the other two never do (D14).
//
// platform is a --platform value (D119), or "" for the host's
// (DefaultPlatform). Every image path resolves it through one selector — an
// index, nested or not, picks by containerd's normalisation, exact match
// first and then the runtime's compatibility ladder; a single image is
// compared by its config — and the returned Image's Platform says what was
// chosen and how. A miss, and a single image that is not an explicitly
// requested platform, are errors; a single image that is not the host's
// default is scanned and reported as MatchMismatch for the caller to warn on.
//
// The context is honoured on the registry path, so a caller that sets a
// deadline gets one; `assay scan --timeout` is what sets it (D112), and the
// layer walks check the same context between tar entries, so it bounds a
// local archive's decompression as well as a registry's fetch. Without the
// flag there is still no deadline — go-containerregistry's default transport
// has no overall one either, so a black-holed registry can hang a scan that
// did not ask for a limit.
//
// A registry pull offers credentials from D118's chain — ASSAY_REGISTRY_AUTH_*,
// then the docker login, then the podman login — and the returned Image says
// which answered. A 401 or 403 comes back as *AuthError, wherever in the pull
// it arrives: the top manifest, an index child, a config or a layer blob.
func Open(ctx context.Context, ref, platform string) (*Image, error) {
	want, explicit := DefaultPlatform(), false
	if platform != "" {
		p, err := ParsePlatform(platform)
		if err != nil {
			return nil, err
		}
		want, explicit = p, true
	}
	img, creds, err := load(ctx, ref, want, explicit)
	if err != nil {
		return nil, err
	}
	out, err := fromV1(img)
	if err != nil {
		if creds.kc != nil {
			err = asAuthError(err, ref, creds.kc)
		}
		return nil, err
	}
	out.Platform = creds.choice
	if creds.kc != nil {
		out.Credentials = Credentials{Registry: creds.kc.target, Source: creds.kc.source()}
		// A layer blob is fetched when the cataloger opens the layer, after
		// this function has returned, and a registry can refuse that request
		// as well (D118).
		for i := range out.Layers {
			open := out.Layers[i].Open
			out.Layers[i].Open = func() (io.ReadCloser, error) {
				rc, err := open()
				if err != nil {
					return nil, asAuthError(err, ref, creds.kc)
				}
				return rc, nil
			}
		}
	}
	return out, nil
}

// loaded carries what load learned besides the image: the registry path's
// keychain, so Open can report which source answered — nil for a tarball or a
// layout, which never build one and so cannot consult one (D14, D118) — and
// the platform choice (D119), which every path makes.
type loaded struct {
	kc     *keychain
	choice PlatformChoice
}

func load(ctx context.Context, ref string, want v1.Platform, explicit bool) (v1.Image, loaded, error) {
	// Errors below name `ref`, not the path trimmed out of it: a user who typed
	// docker-archive:x.tar should see that back, not a bare x.tar they never
	// wrote.
	switch classify(ref) {
	case kindTarball:
		p := strings.TrimPrefix(ref, schemeTarball)
		img, err := tarball.ImageFromPath(p, nil)
		if err != nil {
			return nil, loaded{}, fmt.Errorf("read docker archive %s: %w", ref, err)
		}
		// A docker archive holds one image and no index, so the only
		// question is whether that image is the platform asked for.
		d, err := img.Digest()
		if err != nil {
			return nil, loaded{}, fmt.Errorf("read docker archive %s: %w", ref, err)
		}
		choice, err := checkSingle(img, nil, ref, d, want, explicit)
		if err != nil {
			return nil, loaded{}, err
		}
		return img, loaded{choice: choice}, nil

	case kindLayout:
		p := strings.TrimPrefix(ref, schemeLayout)
		idx, err := layout.ImageIndexFromPath(p)
		if err != nil {
			return nil, loaded{}, fmt.Errorf("read oci layout %s: %w", ref, err)
		}
		m, err := idx.IndexManifest()
		if err != nil {
			return nil, loaded{}, fmt.Errorf("read oci layout %s: %w", ref, err)
		}
		// A one-image layout is a single image (D119): index.json is the
		// layout's table of contents, not a choice of platforms, so it is
		// judged the way a docker archive is.
		if len(m.Manifests) == 1 && !m.Manifests[0].MediaType.IsIndex() {
			d := m.Manifests[0]
			img, err := idx.Image(d.Digest)
			if err != nil {
				return nil, loaded{}, fmt.Errorf("read oci layout %s: %w", ref, err)
			}
			choice, err := checkSingle(img, d.Platform, ref, d.Digest, want, explicit)
			if err != nil {
				return nil, loaded{}, err
			}
			return img, loaded{choice: choice}, nil
		}
		// The layout's own index.json has no digest anyone pushed, so it is
		// not recorded as the index: the zero parent.
		img, choice, err := imageFromIndex(v1Index{idx}, ref, v1.Hash{}, want, explicit)
		return img, loaded{choice: choice}, err

	default:
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, loaded{}, fmt.Errorf("parse reference %q: %w", ref, err)
		}
		// Built before any request, so a half-set ASSAY_REGISTRY_AUTH_*
		// stops the scan without the registry ever being contacted (D118).
		kc, err := newKeychain(r)
		if err != nil {
			return nil, loaded{}, fmt.Errorf("pull %s: %w", ref, err)
		}
		// Every error past this point may be a registry refusal. The requests
		// below — the top manifest, an index child, a nested index, a config
		// read to judge a platform-less descriptor — all carry the keychain,
		// because the descriptor remote.Get returns keeps its options for
		// every child it fetches.
		fail := func(err error) (v1.Image, loaded, error) {
			var pe *platformError
			if errors.As(err, &pe) {
				return nil, loaded{}, err
			}
			if ae := asAuthError(err, ref, kc); ae != err {
				return nil, loaded{}, ae
			}
			return nil, loaded{}, fmt.Errorf("pull %s: %w", ref, err)
		}
		// remote.Get, not remote.Image with WithPlatform: the library's own
		// selection takes the first arm entry, misses arm64/v8 against a
		// variant-less arm64, never descends into a nested index and returns
		// a single image for any platform asked (D119). The descriptor is
		// resolved here, by the same selector the layout path uses.
		desc, err := remote.Get(r,
			remote.WithContext(ctx),
			remote.WithAuthFromKeychain(kc),
		)
		if err != nil {
			return fail(err)
		}
		if desc.MediaType.IsIndex() {
			idx, err := desc.ImageIndex()
			if err != nil {
				return fail(err)
			}
			img, choice, err := imageFromIndex(v1Index{idx}, ref, desc.Digest, want, explicit)
			if err != nil {
				return fail(err)
			}
			return img, loaded{kc: kc, choice: choice}, nil
		}
		img, err := desc.Image()
		if err != nil {
			return fail(err)
		}
		choice, err := checkSingle(img, desc.Platform, ref, desc.Digest, want, explicit)
		if err != nil {
			return fail(err)
		}
		return img, loaded{kc: kc, choice: choice}, nil
	}
}

// platformError is a selection refusal: a miss, or an explicit platform a
// single image is not. Its own type so the registry path passes it through as
// written instead of prefixing "pull" — the pull worked; the image is not
// the one asked for.
type platformError struct{ msg string }

func (e *platformError) Error() string { return e.msg }

// checkSingle judges one image against want by its config (D119). descPlat
// is the descriptor's platform, if any, consulted only when the config names
// no OS or architecture.
//
// Exact or compatible is scanned as such. A config naming nothing is scanned
// as MatchUnchecked. Anything else is refused when the platform was asked for
// — the caller asked a question this image does not answer — and scanned as
// MatchMismatch when it was the host default: the image offers nothing else,
// so it is the image that would be deployed, and refusing would turn every
// amd64 runner scanning an arm64-only image into exit 2.
func checkSingle(img v1.Image, descPlat *v1.Platform, ref string, digest v1.Hash, want v1.Platform, explicit bool) (PlatformChoice, error) {
	choice := PlatformChoice{
		Requested:      PlatformString(want),
		Explicit:       explicit,
		ManifestDigest: digest.String(),
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return PlatformChoice{}, fmt.Errorf("read image config of %s: %w", ref, err)
	}
	got := v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}
	if (got.OS == "" || got.Architecture == "") && descPlat != nil &&
		descPlat.OS != "" && descPlat.Architecture != "" {
		got = *descPlat
	}
	if got.OS == "" || got.Architecture == "" {
		choice.Match = MatchUnchecked
		return choice, nil
	}
	got = normalizePlatform(got)
	choice.Platform = PlatformString(got)
	if _, match, ok := choosePlatform(want, []v1.Platform{got}); ok {
		choice.Match = match
		return choice, nil
	}
	if explicit {
		return PlatformChoice{}, &platformError{fmt.Sprintf(
			"%s is a single %s image; --platform asked for %s", ref, choice.Platform, choice.Requested)}
	}
	choice.Match = MatchMismatch
	return choice, nil
}

// indexReader is the slice of v1.ImageIndex that platform selection needs.
// Narrowing it here keeps the test double to two methods, and v1.ImageIndex
// cannot be embedded in one anyway — it carries a method named ImageIndex,
// which an embedded field of that name shadows.
type indexReader interface {
	IndexManifest() (*v1.IndexManifest, error)
	Image(v1.Hash) (v1.Image, error)
	// ImageIndex returns indexReader rather than v1.ImageIndex so a test double
	// can satisfy it. Go has no covariant returns, so the real type is adapted
	// by v1Index below rather than used directly.
	ImageIndex(v1.Hash) (indexReader, error)
}

// v1Index adapts go-containerregistry's index to indexReader, narrowing the
// recursive method's return type as it goes.
type v1Index struct{ idx v1.ImageIndex }

func (w v1Index) IndexManifest() (*v1.IndexManifest, error) { return w.idx.IndexManifest() }
func (w v1Index) Image(h v1.Hash) (v1.Image, error)         { return w.idx.Image(h) }
func (w v1Index) ImageIndex(h v1.Hash) (indexReader, error) {
	c, err := w.idx.ImageIndex(h)
	if err != nil {
		return nil, err
	}
	return v1Index{c}, nil
}

// imageFromIndex picks want out of a multi-platform index, nested ones
// included, through choosePlatform (D119). parent is the index's own digest,
// or zero for an oci-dir: layout's index.json.
//
// Scanning the wrong architecture's image is a wrong answer that looks like a
// right one — it produces a full package list, just not the one that is
// running — so a miss is an error naming what was on offer, never a fallback
// to the first entry.
func imageFromIndex(idx indexReader, what string, parent v1.Hash, want v1.Platform, explicit bool) (v1.Image, PlatformChoice, error) {
	var cands []candidate
	var skipped []unreadable
	if err := collectCandidates(idx, what, parent, 0, &cands, &skipped); err != nil {
		return nil, PlatformChoice{}, err
	}
	plats := make([]v1.Platform, len(cands))
	for i, c := range cands {
		plats[i] = c.plat
	}
	i, match, ok := choosePlatform(want, plats)
	if !ok {
		if len(cands) == 0 {
			if len(skipped) > 0 {
				// Nothing was offered because nothing could be read: that read
				// failure is the cause, not a platform miss, so it is what the
				// error names.
				return nil, PlatformChoice{}, fmt.Errorf("%s offers no readable image: entry %s: %w",
					what, skipped[0].digest, skipped[0].err)
			}
			return nil, PlatformChoice{}, &platformError{fmt.Sprintf(
				"%s contains no image for any platform; wanted %s", what, PlatformString(want))}
		}
		hint := ""
		if !explicit {
			hint = "; pass --platform to scan one of them"
		}
		return nil, PlatformChoice{}, &platformError{fmt.Sprintf(
			"%s has no %s image; it offers %s%s%s", what, PlatformString(want), offeredList(plats),
			skippedNote(skipped), hint)}
	}
	c := cands[i]
	img := c.img
	if img == nil {
		var err error
		if img, err = c.idx.Image(c.digest); err != nil {
			return nil, PlatformChoice{}, err
		}
	}
	choice := PlatformChoice{
		Platform:       PlatformString(c.plat),
		Requested:      PlatformString(want),
		Explicit:       explicit,
		Match:          match,
		ManifestDigest: c.digest.String(),
	}
	if c.parent.Hex != "" {
		choice.IndexDigest = c.parent.String()
	}
	return img, choice, nil
}

// candidate is one image an index offers, its platform normalised.
type candidate struct {
	plat   v1.Platform
	digest v1.Hash
	// parent is the digest of the index that listed it; zero for a layout's
	// index.json.
	parent v1.Hash
	idx    indexReader
	// img is set when the image was already read to learn its platform.
	img v1.Image
}

// unreadable is a platform-less index entry whose image or config could not
// be read, and so was skipped rather than offered.
type unreadable struct {
	digest v1.Hash
	err    error
}

// skippedNote tells a miss that entries were skipped, so "it offers X" is not
// read as the index's whole contents when part of it could not be read.
func skippedNote(skipped []unreadable) string {
	switch len(skipped) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(" (entry %s could not be read: %v)", skipped[0].digest, skipped[0].err)
	}
	return fmt.Sprintf(" (%d entries could not be read; the first, %s: %v)",
		len(skipped), skipped[0].digest, skipped[0].err)
}

// maxIndexDepth bounds nesting. `skopeo copy --all` writes an index whose
// children are themselves indexes, and a malformed one could cycle.
const maxIndexDepth = 4

// collectCandidates walks an index, descending into nested ones, and appends
// every image it offers in walk order. The WHOLE tree is collected before
// anything is chosen, so an exact match in a later nested index beats a
// compatible one met first (D119: exact first, anywhere).
//
// Two shapes appear in real indexes with no usable Platform on the
// descriptor: a nested index (a manifest-list export), and a single image
// whose descriptor carries only a ref-name annotation. The first is walked;
// the second is judged by its image's config. Both used to fail with "it
// offers " and an empty list — an error naming nothing.
func collectCandidates(idx indexReader, what string, parent v1.Hash, depth int, out *[]candidate, skipped *[]unreadable) error {
	if depth >= maxIndexDepth {
		return fmt.Errorf("%s nests indexes more than %d deep", what, maxIndexDepth)
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	for _, d := range m.Manifests {
		if d.MediaType.IsIndex() {
			child, err := idx.ImageIndex(d.Digest)
			if err != nil {
				return err
			}
			if err := collectCandidates(child, what, d.Digest, depth+1, out, skipped); err != nil {
				return err
			}
			continue
		}

		p := d.Platform
		if p == nil || p.OS == "" || p.Architecture == "" {
			// No platform on the descriptor. The image's own config still
			// carries one, so ask it rather than discarding the entry — a
			// layout written by layout.Write lands here.
			//
			// A registry's 401 or 403 reading it is returned: skipping it
			// would turn a refusal into a "has no image" miss naming the wrong
			// problem (D118). Any other read failure — a blob missing from a
			// partial layout copy, a config that is not JSON, an artifact with
			// no image config — skips the entry, as it did before D119: the
			// whole tree is now walked before choosing, so returning it would
			// let one broken entry sink an index that holds the exact match.
			// The skip is recorded so a miss still says it happened.
			img, err := idx.Image(d.Digest)
			if err != nil {
				if refusal(err) != nil {
					return err
				}
				*skipped = append(*skipped, unreadable{d.Digest, err})
				continue
			}
			cf, err := img.ConfigFile()
			if err != nil {
				if refusal(err) != nil {
					return err
				}
				*skipped = append(*skipped, unreadable{d.Digest, err})
				continue
			}
			if cf.OS == "" || cf.Architecture == "" || cf.OS == "unknown" || cf.Architecture == "unknown" {
				continue
			}
			*out = append(*out, candidate{
				plat:   normalizePlatform(v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}),
				digest: d.Digest, parent: parent, idx: idx, img: img,
			})
			continue
		}
		// Attestation and SBOM manifests are carried in the same index with
		// platform unknown/unknown — alpine:3.19 has several among its 14.
		// They contain no filesystem, so selecting one yields an empty scan,
		// and listing them as options tells an operator nothing.
		if p.OS == "unknown" || p.Architecture == "unknown" {
			continue
		}
		*out = append(*out, candidate{
			plat:   normalizePlatform(*p),
			digest: d.Digest, parent: parent, idx: idx,
		})
	}
	return nil
}

func fromV1(img v1.Image) (*Image, error) {
	ls, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("read layers: %w", err)
	}
	out := &Image{Layers: make([]Layer, 0, len(ls))}
	for _, l := range ls {
		// DiffID, not Digest: Digest is the compressed blob's digest and is a
		// different value for the same layer.
		d, err := l.DiffID()
		if err != nil {
			return nil, fmt.Errorf("read layer diff id: %w", err)
		}
		out.Layers = append(out.Layers, Layer{
			DiffID: d.String(),
			Open:   func() (io.ReadCloser, error) { return l.Uncompressed() },
		})
	}
	return out, nil
}
