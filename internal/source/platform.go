package source

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// D119. One normalisation, one selector, for every image path: a registry
// index, an oci-dir: layout and the single-image check all go through
// choosePlatform below, so the three cannot disagree about which image a
// platform names.
//
// go-containerregistry's remote.WithPlatform is not used for the choice. It
// takes the FIRST arm entry for a bare linux/arm (v5 or v6 on most real
// indexes, where docker runs v7), misses linux/arm64/v8 on an index whose
// arm64 entry carries no variant, never descends into a nested index, and
// returns a single-platform image for any platform asked — each measured
// against real indexes on 2026-10-13 (the roadmap's D119).

// The four values PlatformChoice.Match takes.
const (
	// MatchExact: the scanned image is the requested platform, after both
	// were normalised.
	MatchExact = "exact"
	// MatchCompatible: nothing matched exactly, and the runtime's
	// compatibility ladder chose an older variant the requested host runs
	// (arm/v6 for an arm/v7 request; amd64 for amd64/v3).
	MatchCompatible = "compatible"
	// MatchUnchecked: a single image whose config names no OS or
	// architecture, so there was nothing to compare.
	MatchUnchecked = "unchecked"
	// MatchMismatch: a single image that is not the host's platform, scanned
	// anyway because the platform was the host default rather than asked for.
	MatchMismatch = "mismatch"
)

// PlatformChoice is what an image scan chose and why (D119). source has no
// stderr, so it reports here and scancmd prints the record line, the
// warnings and the JSON `image` object from it.
//
// The zero value — Match "" — is every target that is not an image.
type PlatformChoice struct {
	// Platform is the scanned image's platform, normalised (linux/arm/v7).
	// Empty when Match is MatchUnchecked: the image did not say.
	Platform string
	// Requested is the platform asked for, normalised: --platform when given,
	// the host's otherwise.
	Requested string
	// Explicit says Requested came from --platform rather than the host.
	Explicit bool
	// Match is one of MatchExact, MatchCompatible, MatchUnchecked or
	// MatchMismatch.
	Match string
	// ManifestDigest is the digest of the image manifest scanned.
	ManifestDigest string
	// IndexDigest is the digest of the index that listed it, when an index
	// was resolved — the index the manifest was listed in, so for a nested
	// index the inner one. Empty for a single image, and for an oci-dir:
	// layout's own index.json, which is the layout's table of contents rather
	// than an image index anyone pushed.
	IndexDigest string
	// OuterIndexDigests are the indexes above IndexDigest that the image was
	// reached through, outermost first: for a nested index, the one that was
	// asked for. A VEX statement naming any of them names this image
	// (QA 2026-10-30). A sibling index is not on the path and is not here.
	OuterIndexDigests []string
}

// HostPlatform is the platform a scan asks for when --platform is not given:
// linux plus this binary's GOARCH, normalised by DefaultPlatform (so an arm
// build asks for arm/v7). Both the registry and the layout path read it
// through DefaultPlatform.
//
// It is a variable so a test can ask for a platform this machine is not.
// Hard-coding runtime.GOARCH makes the "we forgot to state the platform" bug
// invisible on an amd64 host, because the library's default happens to be the
// right answer there — and amd64 is where it will be tested. Until D119 the
// layout path compared against runtime.GOARCH directly, out of this seam's
// reach.
var HostPlatform = func() v1.Platform {
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// DefaultPlatform is HostPlatform, normalised.
func DefaultPlatform() v1.Platform { return normalizePlatform(HostPlatform()) }

// ParsePlatform reads a --platform value: os/arch[/variant], normalised the
// way containerd normalises it. An OS version (linux/arm64:10.0) and anything
// past a variant are refused rather than half-supported, and so is a Windows
// platform: assay reads Linux package databases only.
func ParsePlatform(s string) (v1.Platform, error) {
	if strings.TrimSpace(s) == "" {
		return v1.Platform{}, fmt.Errorf("--platform: empty value; want os/arch[/variant], e.g. linux/arm64 or linux/arm/v7")
	}
	if strings.Contains(s, ":") {
		return v1.Platform{}, fmt.Errorf("--platform: %q carries an OS version, which is not supported; "+
			"give os/arch[/variant] only", s)
	}
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return v1.Platform{}, fmt.Errorf("--platform: %q is not os/arch[/variant] "+
			"(one variant at most), e.g. linux/arm64 or linux/arm/v7", s)
	}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return v1.Platform{}, fmt.Errorf("--platform: %q has an empty part; want os/arch[/variant], "+
				"e.g. linux/arm64 or linux/arm/v7", s)
		}
	}
	p := v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	p = normalizePlatform(p)
	if p.OS == "windows" {
		return v1.Platform{}, fmt.Errorf("--platform: %q: Windows images are not supported", s)
	}
	return p, nil
}

// normalizePlatform applies containerd's normalisation, which is what docker
// and grype both compare by: x86_64/x86-64 are amd64 and amd64/v1 is amd64;
// aarch64 is arm64 and arm64/v8 is arm64 with no variant; armhf is arm/v7,
// armel is arm/v6, and a bare arm is arm/v7; i386 is 386. Variants are read
// with or without their "v" (arm/7 is arm/v7). OSVersion is dropped: a
// candidate's (linux/arm64:cbl-mariner-2.0) is not compared, and a request
// carrying one never gets this far.
func normalizePlatform(p v1.Platform) v1.Platform {
	os := strings.ToLower(strings.TrimSpace(p.OS))
	arch := strings.ToLower(strings.TrimSpace(p.Architecture))
	variant := strings.ToLower(strings.TrimSpace(p.Variant))
	if os == "macos" {
		os = "darwin"
	}
	switch arch {
	case "i386":
		arch, variant = "386", ""
	case "x86_64", "x86-64", "amd64":
		arch = "amd64"
		switch variant {
		case "v1", "1":
			variant = ""
		case "2", "3", "4":
			variant = "v" + variant
		}
	case "aarch64", "arm64":
		arch = "arm64"
		switch variant {
		case "8", "v8", "v8.0", "8.0":
			variant = ""
		case "9", "9.0", "v9.0":
			variant = "v9"
		}
	case "armhf":
		arch, variant = "arm", "v7"
	case "armel":
		arch, variant = "arm", "v6"
	case "arm":
		switch variant {
		case "", "7":
			variant = "v7"
		case "5", "6", "8":
			variant = "v" + variant
		}
	}
	return v1.Platform{OS: os, Architecture: arch, Variant: variant}
}

// PlatformString renders a platform as os/arch[/variant].
func PlatformString(p v1.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

func samePlatform(a, b v1.Platform) bool {
	return a.OS == b.OS && a.Architecture == b.Architecture && a.Variant == b.Variant
}

// compatibilityLadder is what a host of the requested platform also runs,
// best first, after nothing matched exactly. Two ladders exist, and nothing
// else falls back:
//
//   - 32-bit arm, from below the requested variant down to v5: a v7 CPU runs
//     a v6 image, and docker chose arm/v6 for an arm/v7 request on an index
//     offering only v6 (measured, D119). It never climbs: an arm/v5 host
//     cannot run a v6 image.
//   - amd64/vN down to plain amd64, for the same reason.
//
// arm64 does not fall back to arm: whether an arm64 host runs 32-bit code is a
// kernel and CPU property this cannot see, and docker does not assume it.
func compatibilityLadder(want v1.Platform) []v1.Platform {
	var rungs []v1.Platform
	step := func(variant string) {
		rungs = append(rungs, v1.Platform{OS: want.OS, Architecture: want.Architecture, Variant: variant})
	}
	switch want.Architecture {
	case "arm":
		n := variantNumber(want.Variant)
		for v := n - 1; v >= 5 && n <= 8; v-- {
			step(fmt.Sprintf("v%d", v))
		}
	case "amd64":
		n := variantNumber(want.Variant)
		for v := n - 1; v >= 2 && n <= 4; v-- {
			step(fmt.Sprintf("v%d", v))
		}
		if n >= 2 && n <= 4 {
			step("")
		}
	}
	return rungs
}

// variantNumber reads "v7" as 7, and anything else as 0, which no ladder
// starts from.
func variantNumber(v string) int {
	if len(v) != 2 || v[0] != 'v' || v[1] < '0' || v[1] > '9' {
		return 0
	}
	return int(v[1] - '0')
}

// choosePlatform picks one of candidates (normalised platforms, in walk
// order) for want: an exact match anywhere first, the first in walk order;
// only if there is none, the highest rung of the compatibility ladder any
// candidate offers. ok is false on a miss.
func choosePlatform(want v1.Platform, candidates []v1.Platform) (i int, match string, ok bool) {
	for i, c := range candidates {
		if samePlatform(c, want) {
			return i, MatchExact, true
		}
	}
	for _, rung := range compatibilityLadder(want) {
		for i, c := range candidates {
			if samePlatform(c, rung) {
				return i, MatchCompatible, true
			}
		}
	}
	return -1, "", false
}

// offeredList renders what an index offers, for a miss: normalised, sorted and
// deduplicated, so the same index produces the same error on every run.
func offeredList(candidates []v1.Platform) string {
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		s := PlatformString(c)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
