package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Deb orders Debian and Ubuntu package versions.
//
// This is a transliteration of dpkg's own `verrevcmp` and `parseversion`
// (lib/dpkg/version.c and lib/dpkg/parsehelp.c), not an interpretation of the
// prose in deb-version(7). The two agree, but the algorithm is the normative
// artefact and it has properties the prose states loosely — the character
// ordering below is the clearest example.
//
// D9 applies with full force here. Debian is the ecosystem where a subtle
// ordering bug is most likely and most costly: `~` sorts BELOW the end of a
// string, which no other ecosystem does, and getting it backwards makes every
// backport and every release candidate compare on the wrong side of its own
// base version. A backport reading as newer than the release it was built from
// is a silent false negative on exactly the systems that took the security fix.
type Deb struct{}

// debVersion is a parsed [epoch:]upstream[-revision].
type debVersion struct {
	epoch    int
	upstream string
	revision string
}

func (Deb) Compare(a, b string) (int, error) {
	pa, err := parseDeb(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseDeb(b)
	if err != nil {
		return 0, err
	}
	// Three independent comparisons, short-circuiting in order. The revision is
	// never appended to the upstream string and compared as one — dpkg compares
	// them separately, and concatenating would let a long upstream version
	// swallow the boundary.
	if c := cmpInt(pa.epoch, pb.epoch); c != 0 {
		return c, nil
	}
	if c := verrevcmp(pa.upstream, pb.upstream); c != 0 {
		return sign(c), nil
	}
	return sign(verrevcmp(pa.revision, pb.revision)), nil
}

// debOrder is dpkg's own order(): the rank of one byte when comparing a
// non-digit run.
//
// This is NOT ASCII order, and the deviation is the whole point:
//
//	'~'                 -> -1    below everything, including the end of a string
//	end of string (NUL) ->  0
//	digit               ->  0    same rank as end-of-string; see verrevcmp
//	letter              ->  c    65..90 then 97..122
//	other punctuation   ->  c+256
//
// So `~` < "" < letters < punctuation. Two consequences worth stating because
// they are easy to get wrong and expensive when wrong:
//
//   - `1.0~rc1 < 1.0`, which is why `~` exists at all. It is the only way to
//     express a version that sorts below its own base, and Debian relies on it
//     for pre-releases (`1.0~rc1`) and for backports (`1.2.3-4~bpo11+1`, a
//     rebuild for an older release that must sort below the real `1.2.3-4` so
//     a machine upgrades cleanly off it).
//   - `1.0z < 1.0.0`, because every letter (122 at most) ranks below every
//     other punctuation mark (302 for '.'). ASCII order says the opposite.
func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	}
	return 0
}

// verrevcmp compares one part (upstream, or revision) exactly as dpkg does.
//
// Returned as a magnitude, not a sign, because that is what dpkg returns and
// keeping it identical makes the transliteration checkable line by line against
// the C. Callers pass it through sign().
func verrevcmp(a, b string) int {
	i, j := 0, 0
	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0 // the end of a string participates in the comparison, ranked 0
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }

	for i < len(a) || j < len(b) {
		firstDiff := 0
		// Non-digit run. The loop continues while EITHER side is at a
		// non-digit, so a shorter string is compared against debOrder(0) rather
		// than simply ending — that is how "~" gets to sort below "".
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := debOrder(at(a, i)), debOrder(at(b, j))
			if ac != bc {
				return ac - bc
			}
			i++
			j++
		}
		// Digit run. Leading zeros are stripped from both sides first, so
		// "1.09" and "1.9" are the same version.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		// Only the FIRST difference is recorded; whichever side still has
		// digits afterwards is numerically longer and therefore greater. This
		// compares runs of any length without parsing them into a fixed-width
		// integer, which would overflow on real input.
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
		// firstDiff is reset at the top of every iteration, so a digit
		// difference never leaks across segment boundaries.
	}
	return 0
}

// parseDeb splits [epoch:]upstream[-revision], applying dpkg's own rules.
//
// dpkg downgrades the character-set violations to warnings and carries on with
// a usable parse. This does not: D9 says an unparseable version must surface as
// ErrInvalid so the package is reported as skipped, and accepting a string dpkg
// itself calls malformed would mean ordering something neither tool can vouch
// for. A loud skip is the right answer; a quiet guess is not.
func parseDeb(v string) (debVersion, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return debVersion{}, fmt.Errorf("deb %q: empty version: %w", v, ErrInvalid)
	}
	// An interior space is a hard error in dpkg, and TrimSpace above cannot
	// reach it.
	if strings.ContainsAny(s, " \t\n\r") {
		return debVersion{}, fmt.Errorf("deb %q: embedded whitespace: %w", v, ErrInvalid)
	}

	var out debVersion
	// The epoch ends at the FIRST colon, and everything before it must be a
	// decimal integer. A colon may therefore appear inside the upstream version
	// only when a valid epoch precedes it: "1:1.2:3-4" parses, "1.2:3-4" does
	// not.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		n, err := strconv.Atoi(s[:i])
		if err != nil || n < 0 {
			return debVersion{}, fmt.Errorf("deb %q: epoch %q is not a number: %w", v, s[:i], ErrInvalid)
		}
		if i+1 == len(s) {
			return debVersion{}, fmt.Errorf("deb %q: nothing after the epoch colon: %w", v, ErrInvalid)
		}
		out.epoch = n
		s = s[i+1:]
	}
	// The revision starts at the LAST hyphen, so "1.2-3-4" is upstream "1.2-3"
	// with revision "4". A version with no hyphen has revision "", which
	// compares below any real revision — the correct reading, since "1.2" is
	// the same source as "1.2-1" before it was packaged.
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		if i+1 == len(s) {
			return debVersion{}, fmt.Errorf("deb %q: revision is empty: %w", v, ErrInvalid)
		}
		out.revision = s[i+1:]
		s = s[:i]
	}
	out.upstream = s

	if out.upstream == "" {
		return debVersion{}, fmt.Errorf("deb %q: upstream version is empty: %w", v, ErrInvalid)
	}
	if c := out.upstream[0]; c < '0' || c > '9' {
		return debVersion{}, fmt.Errorf("deb %q: upstream version does not start with a digit: %w", v, ErrInvalid)
	}
	if bad, ok := firstNotIn(out.upstream, ".-+~:"); !ok {
		return debVersion{}, fmt.Errorf("deb %q: upstream version contains %q: %w", v, bad, ErrInvalid)
	}
	// The revision's character set is narrower than the upstream one: no '-'
	// (it is the separator) and no ':' (it belongs to the epoch).
	if bad, ok := firstNotIn(out.revision, ".+~"); !ok {
		return debVersion{}, fmt.Errorf("deb %q: revision contains %q: %w", v, bad, ErrInvalid)
	}
	return out, nil
}

// firstNotIn reports the first byte of s that is neither alphanumeric nor in
// extra, and whether every byte was legal.
func firstNotIn(s, extra string) (string, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9',
			c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			strings.IndexByte(extra, c) >= 0:
			continue
		}
		return string(c), false
	}
	return "", true
}

// sign narrows dpkg's magnitude to the -1/0/1 the Comparer contract requires.
// dpkg's own return can be ±300, and a caller comparing against -1 would read
// "less" as "not less".
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
