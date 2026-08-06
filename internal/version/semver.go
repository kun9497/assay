package version

import (
	"fmt"
	"strings"
)

// maxVersionLen bounds work on hostile advisory or SBOM input. Not a spec rule.
const maxVersionLen = 256

type SemVer struct{}

type semverParsed struct {
	core [3]string // numeric identifiers, leading zeros already rejected
	pre  []string  // nil when absent
}

func (SemVer) Compare(a, b string) (int, error) {
	pa, err := parseSemVer(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseSemVer(b)
	if err != nil {
		return 0, err
	}
	for i := range 3 {
		if c := compareNumeric(pa.core[i], pb.core[i]); c != 0 {
			return c, nil
		}
	}
	// A version without a pre-release outranks one with it (§11.3). This pulls
	// the opposite way from the "more fields wins" rule below; conflating the
	// two is the classic semver bug.
	switch {
	case pa.pre == nil && pb.pre == nil:
		return 0, nil
	case pa.pre == nil:
		return 1, nil
	case pb.pre == nil:
		return -1, nil
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		x, y := pa.pre[i], pb.pre[i]
		nx, ny := isNumericID(x), isNumericID(y)
		switch {
		case nx && ny:
			if c := compareNumeric(x, y); c != 0 {
				return c, nil
			}
		case !nx && !ny:
			if c := strings.Compare(x, y); c != 0 {
				return c, nil
			}
		case nx: // numeric identifiers rank below alphanumeric ones (§11.4.3)
			return -1, nil
		default:
			return 1, nil
		}
	}
	// All shared fields equal: more fields wins (§11.4.4).
	switch {
	case len(pa.pre) < len(pb.pre):
		return -1, nil
	case len(pa.pre) > len(pb.pre):
		return 1, nil
	}
	return 0, nil
}

func parseSemVer(s string) (semverParsed, error) {
	var p semverParsed
	if s == "" || len(s) > maxVersionLen {
		return p, fmt.Errorf("semver %q: %w", s, ErrInvalid)
	}
	// Strip exactly one lowercase v, at position 0 only. OSV SEMVER bounds
	// carry no prefix while Go artifacts do, so both operands must be
	// normalized — normalizing one side sends every Go comparison to the
	// error path.
	s = strings.TrimPrefix(s, "v")

	// suffixed records that a pre-release or build suffix was present, for the
	// short-form rule below. It has to be tracked here because both are stripped
	// off s before the core is split, so by then "4.0" and "4.0-rc.1" look alike.
	suffixed := false

	// Build metadata is discarded before comparison, not used as a tiebreaker
	// (§10). It must still be syntactically valid.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if err := validIdentifiers(s[i+1:], true); err != nil {
			return p, fmt.Errorf("semver %q build metadata: %w", s, ErrInvalid)
		}
		s = s[:i]
		suffixed = true
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		if err := validIdentifiers(pre, false); err != nil {
			return p, fmt.Errorf("semver %q pre-release: %w", s, ErrInvalid)
		}
		p.pre = strings.Split(pre, ".")
		s = s[:i]
		suffixed = true
	}
	parts := strings.Split(s, ".")
	// D32: a bare short core is a shorthand, padded with zeros. Advisory range
	// bounds routinely carry two components where the spec demands three —
	// github.com/canonical/lxd at "4.0", npm's next at "13.0" — and refusing
	// them made the whole package unevaluable. This is verbatim
	// golang.org/x/mod/semver's documented exception, which govulncheck already
	// relies on to read these same bounds.
	//
	// The bare-form restriction is the rule, not a detail. x/mod's IsValid is
	// false for "v4.0-rc1" and "v4.0+meta", and node-semver refuses both in
	// strict and loose alike; padding them would be an invention neither
	// reference makes. Four or more identifiers stay an error too: node-semver's
	// coerce would read "1.2.3.4" as 1.2.3, which silently discards a component
	// rather than supplying a missing one.
	//
	// The OSV sentinel is excluded by name. "0" is a bare one-identifier core
	// and would otherwise pad to 0.0.0, which is not what it means: the range
	// layer resolves it to negative infinity, and a 0.0.0 reading sorts ABOVE
	// every 0.0.0-prerelease build and would silently drop them out of the
	// window. That protection used to come free from the three-identifier check
	// this rule relaxes, so relaxing it has to restore the guard deliberately.
	padded := false
	if len(parts) < 3 && !suffixed && s != introducedSentinel {
		for len(parts) < 3 {
			parts = append(parts, "0")
			padded = true
		}
	}
	if len(parts) != 3 {
		return p, fmt.Errorf("semver %q: core needs exactly three identifiers: %w", s, ErrInvalid)
	}
	for i, part := range parts {
		if !isNumericID(part) {
			return p, fmt.Errorf("semver %q core identifier %q: %w", s, part, ErrInvalid)
		}
		// D34: a leading zero in the core is accepted and normalized away, the
		// way node-semver's loose mode does — SemVer("19.03.0", {loose:true})
		// reports 19.3.0, and equals 19.3.0. Docker really tags 19.03.x, so
		// GHSA range bounds carry the string and refusing it meant skipping
		// github.com/docker/docker, github.com/moby/moby and every image that
		// vendors them.
		//
		// Accepting WITHOUT normalizing would have been worse than refusing,
		// which is why D32 declined to do it: compareNumeric orders digit
		// strings by length first, so "072" would sort above "72" while
		// denoting the same release — a silent reordering in place of a loud
		// skip. Acceptance and normalization are one rule, not two.
		//
		// This is a deliberate divergence from golang.org/x/mod/semver, which
		// refuses a leading zero outright, and it is taken knowingly: 19.03.9 is
		// a real upstream tag that Go's own version rules cannot express, which
		// is part of why docker is carried as +incompatible in the first place.
		// The bound is GHSA's text about a release, not a Go module version.
		if hasLeadingZero(part) {
			// Not extended to the D32 shorthand. Those are separate rules from
			// separate references, and neither reference applies both at once:
			// node-semver's loose parser needs three identifiers and throws on
			// "4.072", while x/mod's shorthand needs no leading zero. Combining
			// them would read "4.072" as 4.72.0, which only coerce() does — a
			// lossier entry point that also silently truncates "1.2.3.4".
			if padded {
				return p, fmt.Errorf("semver %q core identifier %q: %w", s, part, ErrInvalid)
			}
			part = trimLeadingZeros(part)
		}
		p.core[i] = part
	}
	return p, nil
}

// trimLeadingZeros normalizes a numeric identifier for comparison. All-zero
// input keeps one digit — "00" is 0, not the empty string, and an empty core
// identifier would compare below every real version rather than equal to zero.
func trimLeadingZeros(s string) string {
	i := 0
	for i < len(s)-1 && s[i] == '0' {
		i++
	}
	return s[i:]
}

// validIdentifiers checks a dot-separated identifier list. build allows leading
// zeros on numeric-looking identifiers; pre-release does not (§10 versus §9).
func validIdentifiers(s string, build bool) error {
	if s == "" {
		return ErrInvalid
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return ErrInvalid
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			ok := c == '-' || (c >= '0' && c <= '9') ||
				(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			if !ok {
				return ErrInvalid
			}
		}
		if !build && isNumericID(id) && hasLeadingZero(id) {
			return ErrInvalid
		}
	}
	return nil
}

func isNumericID(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func hasLeadingZero(s string) bool { return len(s) > 1 && s[0] == '0' }

// compareNumeric orders two digit strings without parsing them into a fixed
// width. The spec sets no upper bound on numeric identifiers, so strconv would
// be a conformance bug on real input.
func compareNumeric(a, b string) int {
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return strings.Compare(a, b)
}
