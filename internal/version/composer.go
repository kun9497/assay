package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Composer orders Packagist versions the way composer does (D9): composer's
// own VersionParser::normalize() first, then PHP's version_compare() on the
// normalized strings — composer contributes no ordering of its own. Both
// halves were ported from the canonical sources (composer/semver
// VersionParser.php; php-src ext/standard/versioning.c) via an oracle
// validated against composer's own test data, 98/98 rows.
//
// The ladder that surprises: dev < alpha < beta < RC < stable < patch. A
// "-patch1" (or -p1/-pl1) release sorts ABOVE its stable — getting that
// backwards inverts a fix boundary.
type Composer struct{}

// composerMod is the stability/dev tail both version shapes share. The
// alternation order is upstream's: longer spellings before their one-letter
// forms, so "beta2" is beta+2, never b+"eta2".
const composerMod = `(?:[._-]?(?:(stable|beta|b|RC|alpha|a|patch|pl|p)((?:[.-]?\d+)*)?)?([.-]?dev)?)`

var (
	composerAlias    = regexp.MustCompile(`^([^,\s]+) +as +([^,\s]+)$`)
	composerFlag     = regexp.MustCompile(`(?i)@(stable|RC|beta|alpha|dev)$`)
	composerMeta     = regexp.MustCompile(`^([^,\s+]+)\+[^\s]+$`)
	composerClassic  = regexp.MustCompile(`(?i)^v?(\d{1,5})(\.\d+)?(\.\d+)?(\.\d+)?` + composerMod + `$`)
	composerDate     = regexp.MustCompile(`(?i)^v?(\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})` + composerMod + `$`)
	composerDevTail  = regexp.MustCompile(`(?i)^(.*?)[.-]?dev$`)
	composerBranchNr = regexp.MustCompile(`^v?(\d+)(\.(?:\d+|[xX*]))?(\.(?:\d+|[xX*]))?(\.(?:\d+|[xX*]))?$`)
	composerNonDigit = regexp.MustCompile(`\D`)
)

func (Composer) Compare(a, b string) (int, error) {
	na, err := composerNormalize(a)
	if err != nil {
		return 0, err
	}
	nb, err := composerNormalize(b)
	if err != nil {
		return 0, err
	}

	// A dev- branch does not order. Constraint::versionCompare answers false
	// to <, > AND == when one side is a branch — a refusal, not a rank — and
	// the only truth it asserts is that a branch equals itself. Returning 0
	// for anything else would make dev-master look equal to every version,
	// the silent-miss shape D9 exists to prevent, so it is an error that
	// surfaces as a skipped package.
	aDev, bDev := strings.HasPrefix(na, "dev-"), strings.HasPrefix(nb, "dev-")
	if aDev || bDev {
		if aDev && bDev && na == nb {
			return 0, nil
		}
		return 0, fmt.Errorf("%w: %q and %q do not order (a dev- branch has no position among versions)", ErrInvalid, a, b)
	}
	return phpVersionCompare(na, nb), nil
}

// composerNormalize is VersionParser::normalize(), step for step.
func composerNormalize(v string) (string, error) {
	s := strings.TrimSpace(v)
	if m := composerAlias.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	s = composerFlag.ReplaceAllString(s, "")

	// Bare branch names alias to their dev- form before the dev- passthrough.
	if l := strings.ToLower(s); l == "master" || l == "trunk" || l == "default" {
		s = "dev-" + s
	}
	// A dev- branch passes through verbatim past the prefix: only "dev-" is
	// lowercased, the branch name keeps its case (DEV-FOOBAR -> dev-FOOBAR).
	if len(s) >= 4 && strings.EqualFold(s[:4], "dev-") {
		return "dev-" + s[4:], nil
	}

	// Build metadata never orders; a "+" followed by whitespace is invalid,
	// not metadata, which the [^\s]+ in the pattern enforces.
	if m := composerMeta.FindStringSubmatch(s); m != nil {
		s = m[1]
	}

	if m := composerClassic.FindStringSubmatch(s); m != nil {
		// Four-part padding is what makes 1.0 == 1.0.0.0 — and what the real
		// laravel sentinel "<=4.1.99999" leans on: 99999 is exactly the
		// five-digit major cap, so the shape stays inside this branch.
		out := m[1]
		for _, part := range []string{m[2], m[3], m[4]} {
			if part == "" {
				out += ".0"
			} else {
				out += part
			}
		}
		return out + composerExpandMod(m[5], m[6], m[7]), nil
	}
	if m := composerDate.FindStringSubmatch(s); m != nil {
		// Date versions are NOT padded, so 2010-01-02 (three segments) and
		// 2010.01.02.0 (a classical parse) are two spellings of one date
		// that compare unequal. Faithful to upstream, trap and all.
		return composerNonDigit.ReplaceAllString(m[1], ".") + composerExpandMod(m[2], m[3], m[4]), nil
	}

	// Branch fallback: "1.x-dev" and friends. x/X/* become 9999999, so
	// 1.x-dev sorts above every real 1.* and below 2.0.0.
	if m := composerDevTail.FindStringSubmatch(s); m != nil {
		if bm := composerBranchNr.FindStringSubmatch(m[1]); bm != nil {
			out := bm[1]
			for _, part := range []string{bm[2], bm[3], bm[4]} {
				if part == "" {
					out += ".x"
				} else {
					out += part
				}
			}
			out = strings.NewReplacer("x", "9999999", "X", "9999999", "*", "9999999").Replace(out)
			return out + "-dev", nil
		}
	}

	return "", fmt.Errorf("%w: %q is not a composer version", ErrInvalid, v)
}

// composerExpandMod renders the stability tail. stab/tail/dev are the three
// MOD capture groups.
func composerExpandMod(stab, tail, dev string) string {
	out := ""
	if stab != "" {
		// "stable" is elided — but by a CASE-SENSITIVE comparison upstream,
		// so "-STABLE" escapes, lowercases below, and lands in the compare
		// table's unmatched slot BELOW dev. Encoded faithfully; flagged in
		// the tests as upstream-source-derived rather than oracle-run.
		if stab != "stable" {
			switch l := strings.ToLower(stab); l {
			case "a":
				out += "-alpha"
			case "b":
				out += "-beta"
			case "p", "pl":
				out += "-patch"
			case "rc":
				out += "-RC"
			default:
				out += "-" + l
			}
			// Only the LEADING separator of the numeric tail is trimmed;
			// inner ones survive (alpha-2.1-3 -> alpha2.1-3).
			out += strings.TrimLeft(tail, ".-")
		}
	}
	if dev != "" {
		out += "-dev"
	}
	return out
}

// phpVersionCompare is php_version_compare over canonicalized segment lists.
func phpVersionCompare(a, b string) int {
	as, bs := phpSegments(a), phpSegments(b)
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if c := phpSegmentCompare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	// Leftover on the longer side: a digit segment (even "0") makes it
	// greater; a qualifier compares against the stable slot, so "-dev"
	// loses to the shorter string and "-patch1" beats it.
	longer, sign := as, 1
	if len(bs) > len(as) {
		longer, sign = bs, -1
	}
	for i := n; i < len(longer); i++ {
		s := longer[i]
		if s[0] >= '0' && s[0] <= '9' {
			return sign
		}
		if c := phpSpecialOrder(s) - 4; c != 0 {
			if c > 0 {
				return sign
			}
			return -sign
		}
	}
	return 0
}

// phpSegments canonicalizes: -, _, + become separators alongside ".", and a
// dot is inserted at every digit<->non-digit transition, then the string
// splits on the separators.
func phpSegments(s string) []string {
	var segs []string
	i := 0
	for i < len(s) {
		c := s[i]
		if c == '.' || c == '-' || c == '_' || c == '+' {
			i++
			continue
		}
		j := i
		if c >= '0' && c <= '9' {
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
		} else {
			for j < len(s) && s[j] != '.' && s[j] != '-' && s[j] != '_' && s[j] != '+' && !(s[j] >= '0' && s[j] <= '9') {
				j++
			}
		}
		segs = append(segs, s[i:j])
		i = j
	}
	return segs
}

// phpForms is versioning.c's special_forms table, in ITS order — the order is
// load-bearing because lookup is by prefix and "pl" must be tried before "p"
// (composer's expandStability writes the literal "patch", which only ever
// matches here because "p" is a PREFIX of it).
var phpForms = []struct {
	name  string
	order int
}{
	{"dev", 0}, {"alpha", 1}, {"a", 1}, {"beta", 2}, {"b", 2},
	{"RC", 3}, {"rc", 3}, {"#", 4}, {"pl", 5}, {"p", 5},
}

// phpSpecialOrder ranks a non-numeric segment. Unmatched is -1 — BELOW dev —
// which is where "-STABLE"'s lowercased survivor lands.
func phpSpecialOrder(s string) int {
	for _, f := range phpForms {
		if strings.HasPrefix(s, f.name) {
			return f.order
		}
	}
	return -1
}

func phpSegmentCompare(a, b string) int {
	aNum := a[0] >= '0' && a[0] <= '9'
	bNum := b[0] >= '0' && b[0] <= '9'
	switch {
	case aNum && bNum:
		// int64 on purpose: date normalizations reach 12+ digits, past int32.
		// The classical branch caps the major at 5 digits and every other
		// numeric part comes from \d+ runs short enough in practice; a
		// hypothetical overflow falls back to length-then-lex, which orders
		// the same for equal-signed decimals.
		x, xerr := strconv.ParseInt(a, 10, 64)
		y, yerr := strconv.ParseInt(b, 10, 64)
		if xerr != nil || yerr != nil {
			ta, tb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
			if len(ta) != len(tb) {
				if len(ta) < len(tb) {
					return -1
				}
				return 1
			}
			return strings.Compare(ta, tb)
		}
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case aNum != bNum:
		// The numeric side sits in the stable slot ("#N#" in the C source).
		ao, bo := 4, phpSpecialOrder(b)
		if !aNum {
			ao, bo = phpSpecialOrder(a), 4
		}
		switch {
		case ao < bo:
			return -1
		case ao > bo:
			return 1
		}
		return 0
	default:
		ao, bo := phpSpecialOrder(a), phpSpecialOrder(b)
		switch {
		case ao < bo:
			return -1
		case ao > bo:
			return 1
		}
		return 0
	}
}
