package version

import (
	"fmt"
	"regexp"
	"strings"
)

// Gem orders RubyGems versions the way Gem::Version does (D9). The rules are
// rubygems' own — lib/rubygems/version.rb, cross-checked against its
// test_gem_version.rb assertions — not a semver approximation: a letter
// segment makes the whole version a prerelease that sorts BELOW its release,
// hyphens are rewritten to ".pre." before anything else, and trailing
// zero-runs are canonicalized away, none of which semver does.
type Gem struct{}

// gemPattern is ANCHORED_VERSION_PATTERN, minus Ruby's atomic group (RE2 has
// no backtracking, so the atomicity is moot). The whole version group is
// optional in rubygems — empty means version 0 there — but assay rejects
// empty separately below, so the pattern keeps upstream's shape.
var gemPattern = regexp.MustCompile(`^\s*([0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)?\s*$`)

// gemSegment is one canonical segment: an integer run or a letter run. The
// integer is kept as its digit string with leading zeros trimmed rather than
// parsed, because rubygems integers are bignums — a real upstream fixture
// carries a 9-digit segment and adversarial input can carry 30 — and an
// int64 overflow that wraps negative is a silent misorder, the exact class
// D9 exists to prevent. Comparing (length, then lexically) on trimmed digit
// strings is exact for arbitrary precision.
type gemSegment struct {
	num   string // trimmed digits; empty when the segment is a letter run
	alpha string // the letter run; empty when numeric
}

func (Gem) Compare(a, b string) (int, error) {
	as, err := gemCanonical(a)
	if err != nil {
		return 0, err
	}
	bs, err := gemCanonical(b)
	if err != nil {
		return 0, err
	}

	// Walk the common prefix; first difference decides.
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if c := gemSegmentCompare(as[i], bs[i]); c != 0 {
			return c, nil
		}
	}

	// Equal prefix: the longer list decides, segment by segment. A letter
	// tail makes the longer side a PRERELEASE of the shorter (smaller); a
	// nonzero numeric tail makes it a later patch (larger); zeros say
	// nothing. Getting the letter case backwards clears a vulnerable
	// prerelease — rails 5.0.0.beta1 vs the >= 5.0.0.beta1.1 fix is the
	// real-world shape this rule exists for.
	longer, sign := as, 1
	if len(bs) > len(as) {
		longer, sign = bs, -1
	}
	for i := n; i < len(longer); i++ {
		s := longer[i]
		if s.alpha != "" {
			return -sign, nil
		}
		if s.num != "0" {
			return sign, nil
		}
	}
	return 0, nil
}

// gemCanonical validates v and returns its canonical segments.
func gemCanonical(v string) ([]gemSegment, error) {
	if !gemPattern.MatchString(v) {
		return nil, fmt.Errorf("%w: %q is not a RubyGems version", ErrInvalid, v)
	}
	s := strings.TrimSpace(v)
	// Rubygems maps empty to version 0; assay refuses instead. A package
	// cataloged with no version is corrupt input, and treating it as 0 would
	// compare it below every advisory bound — reported vulnerable to
	// everything, which is loud but still wrong. Divergence recorded in the
	// roadmap's divergence table.
	if s == "" {
		return nil, fmt.Errorf("%w: empty version", ErrInvalid)
	}

	// Upstream's exact order: strip, THEN rewrite every hyphen to ".pre.".
	// "1.2.3-1" is "1.2.3.pre.1" — the hyphen alone makes it a prerelease.
	s = strings.ReplaceAll(s, "-", ".pre.")
	prerelease := strings.ContainsFunc(s, isASCIILetter)

	// Canonicalization step 1 (both kinds): drop ONE trailing run of dots
	// and zeros whose preceding character is a letter or a dot. This is
	// upstream's `sub(/(?<=[a-zA-Z.])[.0]+\z/, "")` — a lookbehind RE2 does
	// not have, so it is the equivalent leftmost scan: i starts at the head
	// of the maximal trailing {.,0} run and slides right until the boundary
	// character qualifies. "1.0" truncates at the "0" (boundary '.'),
	// making 1.0 == 1; "10" has no qualifying boundary and keeps its zero.
	run := len(s)
	for run > 0 && (s[run-1] == '.' || s[run-1] == '0') {
		run--
	}
	for i := run; i < len(s); i++ {
		if i > 0 && (isASCIILetter(rune(s[i-1])) || s[i-1] == '.') {
			s = s[:i]
			break
		}
	}

	// Step 2 (prereleases only): drop ONE run of zeros-and-dots sitting
	// immediately before the FIRST letter, anchored at the string start or
	// after a dot — upstream's `sub!(/(?<=\.|\A)[0.]+(?=[a-zA-Z])/, "")`.
	// "1.0.0.pre.2" == "1.pre.2" and "0.beta.1" == "0.0.beta.1" both come
	// from here. Zeros elsewhere survive: "1.0.1.pre" keeps its 0, and
	// "1.0.0.a.0.0.b" keeps its interior run (upstream fires each sub at
	// most once — these scans must not loop).
	if prerelease {
		k := strings.IndexFunc(s, isASCIILetter)
		for i := 0; i < k; i++ {
			if i > 0 && s[i-1] != '.' {
				continue
			}
			allRun := i < k
			for j := i; j < k; j++ {
				if s[j] != '0' && s[j] != '.' {
					allRun = false
					break
				}
			}
			if allRun {
				s = s[:i] + s[k:]
				break
			}
		}
	}

	// Partition: alternating digit and letter runs; dots only separate.
	var segs []gemSegment
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			num := strings.TrimLeft(s[i:j], "0")
			if num == "" {
				num = "0"
			}
			segs = append(segs, gemSegment{num: num})
			i = j
		case isASCIILetter(rune(c)):
			j := i
			for j < len(s) && isASCIILetter(rune(s[j])) {
				j++
			}
			segs = append(segs, gemSegment{alpha: s[i:j]})
			i = j
		default: // '.'
			i++
		}
	}
	return segs, nil
}

// gemSegmentCompare orders two segments at the same index: letters sort
// below numbers (a prerelease marker loses to a patch number), numbers
// compare as integers, letters compare as raw ASCII — case-sensitive, so
// "RC" < "alpha" because uppercase bytes sort first. That is upstream's
// String#<=> verbatim, surprising as it reads.
func gemSegmentCompare(a, b gemSegment) int {
	switch {
	case a.alpha != "" && b.alpha == "":
		return -1
	case a.alpha == "" && b.alpha != "":
		return 1
	case a.alpha != "":
		return strings.Compare(a.alpha, b.alpha)
	}
	// Both numeric: trimmed digit strings compare by length, then bytes.
	if len(a.num) != len(b.num) {
		if len(a.num) < len(b.num) {
			return -1
		}
		return 1
	}
	return strings.Compare(a.num, b.num)
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
