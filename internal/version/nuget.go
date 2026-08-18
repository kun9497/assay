package version

import (
	"fmt"
	"strconv"
	"strings"
)

// NuGet orders NuGet package versions the way NuGet.Versioning's
// VersionComparer.Default does (D9), ported from the verbatim NuGet.Client
// sources and cross-checked against its own xUnit rows. Its three deliberate
// divergences from strict SemVer 2.0.0 all matter here:
//
//   - a legacy FOURTH numeric part (Revision): 1.0.0.1 > 1.0.0, while
//     1.0.0.0 == 1.0.0;
//   - release labels compare case-INSENSITIVELY (1.0.0-BETA == 1.0.0-beta),
//     where strict semver's ordinal compare would order them;
//   - leading zeros are LEGAL in the numeric parts (1.0.01 == 1.0.1) and
//     illegal only in an all-digit release label.
type NuGet struct{}

// nugetVersion is the parsed form. labels == nil means stable; metadata is
// validated at parse and then ignored by ordering, because 1.0.0+meta_data
// silently comparing equal to 1.0.0 would hide corrupt input (D9: the error
// is the useful outcome).
type nugetVersion struct {
	nums   [4]int64 // int32 range enforced at parse; int64 avoids casts
	labels []string
}

func (NuGet) Compare(a, b string) (int, error) {
	av, err := nugetParse(a)
	if err != nil {
		return 0, err
	}
	bv, err := nugetParse(b)
	if err != nil {
		return 0, err
	}

	for i := 0; i < 4; i++ {
		switch {
		case av.nums[i] < bv.nums[i]:
			return -1, nil
		case av.nums[i] > bv.nums[i]:
			return 1, nil
		}
	}

	// No labels sorts above labels: a prerelease precedes its release.
	switch {
	case av.labels == nil && bv.labels == nil:
		return 0, nil
	case av.labels == nil:
		return 1, nil
	case bv.labels == nil:
		return -1, nil
	}

	// Element-wise to the longer array; the side that runs out is less.
	n := len(av.labels)
	if len(bv.labels) > n {
		n = len(bv.labels)
	}
	for i := 0; i < n; i++ {
		switch {
		case i >= len(av.labels):
			return -1, nil
		case i >= len(bv.labels):
			return 1, nil
		}
		if c := nugetLabelCompare(av.labels[i], bv.labels[i]); c != 0 {
			return c, nil
		}
	}
	return 0, nil
}

// nugetLabelCompare: both int32 -> numeric; exactly one -> the number is
// LESS; neither -> case-insensitive ordinal. The int32 bound is faithful on
// purpose: a >10-digit label fails .NET's int.TryParse and falls back to the
// string path, so 1.0.0-10000000000 < 1.0.0-9999999999, numerically
// backwards — but it is how every NuGet client resolves, and disagreeing
// with the ecosystem's own ordering is the wrong kind of correctness.
func nugetLabelCompare(a, b string) int {
	x, xerr := strconv.ParseInt(a, 10, 32)
	y, yerr := strconv.ParseInt(b, 10, 32)
	switch {
	case xerr == nil && yerr == nil:
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case xerr == nil:
		return -1
	case yerr == nil:
		return 1
	}
	// Labels are ASCII-only by construction (parse rejects the rest), so
	// OrdinalIgnoreCase reduces exactly to comparing upper-folded bytes —
	// no locale, no Unicode folding, no KELVIN SIGN to worry about.
	fa, fb := strings.ToUpper(a), strings.ToUpper(b)
	return strings.Compare(fa, fb)
}

func nugetParse(v string) (nugetVersion, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return nugetVersion{}, fmt.Errorf("%w: empty version", ErrInvalid)
	}

	// Section split, upstream's quirk included: a '-' or '+' as the LAST
	// character belongs to the numeric part, which is what makes "1.0.0-"
	// and "1.0.0+" invalid rather than empty-labeled.
	numPart, labelPart, metaPart := s, "", ""
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c == '-' || c == '+') && i != len(s)-1 {
			numPart = s[:i]
			if c == '-' {
				rest := s[i+1:]
				if j := strings.IndexByte(rest, '+'); j >= 0 && j != len(rest)-1 {
					labelPart, metaPart = rest[:j], rest[j+1:]
				} else {
					labelPart = rest
				}
			} else {
				metaPart = s[i+1:]
			}
			break
		}
	}

	var out nugetVersion
	parts := strings.Split(numPart, ".")
	if len(parts) > 4 {
		return nugetVersion{}, fmt.Errorf("%w: %q has %d numeric parts, NuGet allows at most 4", ErrInvalid, v, len(parts))
	}
	for i, p := range parts {
		// Upstream tolerates whitespace around a section ("1. 2 .3") but not
		// inside a number. Tightened here to none at all: no real package
		// version carries it, rejecting turns a would-be guess into a
		// skipped package, and the divergence is recorded in the roadmap's
		// divergence table.
		if p == "" || strings.TrimFunc(p, func(r rune) bool { return r >= '0' && r <= '9' }) != "" {
			return nugetVersion{}, fmt.Errorf("%w: %q: numeric part %q", ErrInvalid, v, p)
		}
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n > 2147483647 {
			// int32 is the parser's own bound; leading zeros are fine here.
			return nugetVersion{}, fmt.Errorf("%w: %q: part %q exceeds int32", ErrInvalid, v, p)
		}
		out.nums[i] = n
	}

	if labelPart != "" {
		out.labels = strings.Split(labelPart, ".")
		for _, l := range out.labels {
			if err := nugetCheckPart(v, l, false); err != nil {
				return nugetVersion{}, err
			}
		}
	}
	if metaPart != "" {
		for _, m := range strings.Split(metaPart, ".") {
			if err := nugetCheckPart(v, m, true); err != nil {
				return nugetVersion{}, err
			}
		}
		if strings.ContainsRune(metaPart, '+') {
			return nugetVersion{}, fmt.Errorf("%w: %q: second '+'", ErrInvalid, v)
		}
	}
	return out, nil
}

// nugetCheckPart validates one dot-separated label or metadata part:
// non-empty, ASCII [0-9A-Za-z-] only, and — for release labels alone — an
// all-digit part must not carry a leading zero unless it IS "0". That
// asymmetry against the numeric sections (where 1.0.01 is fine) is the
// easiest thing in this scheme to get backwards.
func nugetCheckPart(v, p string, allowLeadingZero bool) error {
	if p == "" {
		return fmt.Errorf("%w: %q: empty label", ErrInvalid, v)
	}
	allDigits := true
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= '0' && c <= '9':
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-':
			allDigits = false
		default:
			return fmt.Errorf("%w: %q: label %q has a character outside [0-9A-Za-z-]", ErrInvalid, v, p)
		}
	}
	if !allowLeadingZero && allDigits && len(p) > 1 && p[0] == '0' {
		return fmt.Errorf("%w: %q: numeric release label %q has a leading zero", ErrInvalid, v, p)
	}
	return nil
}
