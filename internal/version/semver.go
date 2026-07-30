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

	// Build metadata is discarded before comparison, not used as a tiebreaker
	// (§10). It must still be syntactically valid.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if err := validIdentifiers(s[i+1:], true); err != nil {
			return p, fmt.Errorf("semver %q build metadata: %w", s, ErrInvalid)
		}
		s = s[:i]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		if err := validIdentifiers(pre, false); err != nil {
			return p, fmt.Errorf("semver %q pre-release: %w", s, ErrInvalid)
		}
		p.pre = strings.Split(pre, ".")
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return p, fmt.Errorf("semver %q: core needs exactly three identifiers: %w", s, ErrInvalid)
	}
	for i, part := range parts {
		if !isNumericID(part) || hasLeadingZero(part) {
			return p, fmt.Errorf("semver %q core identifier %q: %w", s, part, ErrInvalid)
		}
		p.core[i] = part
	}
	return p, nil
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
