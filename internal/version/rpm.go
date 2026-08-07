package version

import (
	"fmt"
	"strconv"
	"strings"
)

// RPM orders Red Hat, Fedora, SUSE and Amazon Linux package versions.
//
// This is a transliteration of rpm's own rpmvercmp() and parseEVR()
// (rpmio/rpmvercmp.cc and lib/rpmds.c), not a reading of any prose about them.
// D9 applies with full force: it looks like the Debian scheme and is not one.
//
//   - `~` sorts below everything, as in Debian. `^` has no Debian counterpart
//     at all: it sorts ABOVE the end of a string and below any alphanumeric, so
//     `1.0 < 1.0^git1 < 1.01`, which is how a post-release snapshot is spelled.
//   - Everything that is not alphanumeric, `~` or `^` is a SEPARATOR and is
//     skipped, so `1.0.2`, `1.0_2` and `1.0-2` are one version. Debian ranks
//     those characters against each other instead.
//   - A numeric segment always sorts above an alphabetic one, so `1.1 > 1.a`.
//     Debian says the opposite, because its letters rank below its punctuation
//     rather than against digits.
//
// Getting `^` backwards, or ranking separators the Debian way, moves a whole
// class of real versions to the wrong side of their own fix — a silent false
// negative, and the exact failure the per-ecosystem design exists to prevent.
type RPM struct{}

// rpmEVR is a parsed epoch:version-release.
type rpmEVR struct {
	epoch   int
	version string
	release string
}

func (RPM) Compare(a, b string) (int, error) {
	pa, err := parseEVR(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseEVR(b)
	if err != nil {
		return 0, err
	}
	// Three comparisons in rpm's own order. The release is never appended to
	// the version and compared as one string: rpm compares them separately,
	// and `1.0-2` against `1.0.2-1` would otherwise come out backwards.
	if c := cmpInt(pa.epoch, pb.epoch); c != 0 {
		return c, nil
	}
	if c := rpmvercmp(pa.version, pb.version); c != 0 {
		return c, nil
	}
	return rpmvercmp(pa.release, pb.release), nil
}

// rpmvercmp is rpm's segment-by-segment ordering, transliterated.
//
// The C works by writing NUL bytes into copies of the strings to terminate
// each segment; this slices instead, which is why the indices are carried
// explicitly rather than the code reading like the original. Every branch
// below is in the same order as the C, so the two can be checked line by line.
func rpmvercmp(a, b string) int {
	// rpm's own first line, kept so the transliteration stays checkable line by
	// line against the C.
	//
	// It is a TRUE EQUIVALENT, and that is recorded rather than left for
	// someone to rediscover: deleting it survives the whole test table, because
	// the loop below reaches the same answer for every identical pair. Checked
	// exhaustively over all 7,380 strings of length 1-4 drawn from
	// {a,b,1,2,.,~,^,_,+} — every one of them compares equal to itself with
	// this line removed. An unexplained survivor reads as an untested branch
	// forever; a documented one reads as a decision.
	if a == b {
		return 0
	}

	at := func(s string, k int) byte {
		if k < len(s) {
			return s[k]
		}
		return 0 // the end of a string, which participates in the ~ and ^ tests
	}

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Separators. ANY byte that is not alphanumeric, `~` or `^` is one, so
		// the dot in "1.0" and the underscore in "el9_8" are equally invisible.
		for i < len(a) && !isRPMAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isRPMAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ac, bc := at(a, i), at(b, j)

		// The tilde: below everything, including the end of the string. This
		// is the one rule shared with Debian, and it is what makes a
		// pre-release sort under its own base version.
		if ac == '~' || bc == '~' {
			if ac != '~' {
				return 1
			}
			if bc != '~' {
				return -1
			}
			i++
			j++
			continue
		}

		// The caret: the tilde's mirror, and Debian has nothing like it. It is
		// ABOVE the end of the string and below any alphanumeric, so a
		// post-release snapshot sorts above the release it followed and below
		// the next version. The two end-of-string tests come FIRST, and that
		// order is the whole difference from the tilde block above.
		if ac == '^' || bc == '^' {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if ac != '^' {
				return 1
			}
			if bc != '^' {
				return -1
			}
			i++
			j++
			continue
		}

		// One side ran out. The tail of the function decides.
		if i >= len(a) || j >= len(b) {
			break
		}

		// One segment: entirely digits or entirely letters, and which of the
		// two is decided by the FIRST string alone. The second string's run is
		// taken in the same class, so a digit run meeting a letter run leaves
		// the second empty.
		si, sj := i, j
		isnum := isRPMDigit(a[i])
		if isnum {
			for si < len(a) && isRPMDigit(a[si]) {
				si++
			}
			for sj < len(b) && isRPMDigit(b[sj]) {
				sj++
			}
		} else {
			for si < len(a) && isRPMAlpha(a[si]) {
				si++
			}
			for sj < len(b) && isRPMAlpha(b[sj]) {
				sj++
			}
		}
		one, two := a[i:si], b[j:sj]
		if two == "" {
			// Different classes. A numeric segment is always newer than an
			// alphabetic one, which is why `1.1` beats `1.a` — the opposite of
			// Debian, where a letter ranks below punctuation and never against
			// a digit at all.
			if isnum {
				return 1
			}
			return -1
		}
		if isnum {
			// Leading zeros are not part of the number, so "10.0001" and
			// "10.1" are one version. Compared by length and then
			// lexically rather than by parsing into an integer, because a
			// date-stamped release like 20260807143000 overflows anything
			// fixed-width.
			one = strings.TrimLeft(one, "0")
			two = strings.TrimLeft(two, "0")
			if len(one) != len(two) {
				return sign(len(one) - len(two))
			}
		}
		if c := strings.Compare(one, two); c != 0 {
			return c
		}
		i, j = si, sj
	}

	// Every segment compared equal. Whichever string still has bytes left is
	// the greater one; if neither does, the versions differ only in their
	// separators and are equal.
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// parseEVR splits [epoch:]version[-release], applying rpm's own rules, which
// are not dpkg's:
//
//   - The epoch terminator is found by scanning DIGITS from the start. So
//     "1:2.3" has epoch 1, and "1a:2.3" has NO epoch — the colon is just part
//     of the version, where dpkg would call the same string malformed.
//   - ":1.0" has an epoch of 0, because rpm reads an empty epoch as zero
//     rather than as an error.
//   - The release starts at the LAST hyphen, so "1.2-3-4" is version "1.2-3"
//     with release "4".
//
// An ABSENT epoch is zero, on both sides, and that is D46's highest-risk row:
// AlmaLinux omits it when it is zero (52,290 of 67,076 fixed events) while Red
// Hat and Rocky always write it, and on the installed side 145 of 158 real
// packages in almalinux:9 carry no EPOCH tag at all. Treating absent as
// anything but zero is wrong in whichever direction the data happens to fall.
func parseEVR(v string) (rpmEVR, error) {
	if v == "" {
		return rpmEVR{}, fmt.Errorf("rpm %q: empty version: %w", v, ErrInvalid)
	}
	// rpm itself would happily compare a string with a space in it, treating
	// the space as a separator. Refused here because it is not a version — it
	// is a sign the caller handed over a whole line, or a field that failed to
	// parse upstream, and ordering it would vouch for something neither tool
	// can.
	if strings.ContainsAny(v, " \t\n\r") {
		return rpmEVR{}, fmt.Errorf("rpm %q: embedded whitespace: %w", v, ErrInvalid)
	}
	s := v

	var out rpmEVR
	// The epoch ends at the first colon AND ONLY IF every byte before it is a
	// digit. This scan is rpm's, and it is the reason "1a:2.3" parses as a
	// version rather than as a bad epoch.
	d := 0
	for d < len(s) && isRPMDigit(s[d]) {
		d++
	}
	if d < len(s) && s[d] == ':' {
		if d == 0 {
			out.epoch = 0 // ":1.0" — an empty epoch is zero, not an error
		} else {
			n, err := strconv.Atoi(s[:d])
			if err != nil {
				// Only reachable for a digit run too long for an int, which is
				// not an epoch anybody wrote on purpose.
				return rpmEVR{}, fmt.Errorf("rpm %q: epoch %q is out of range: %w", v, s[:d], ErrInvalid)
			}
			out.epoch = n
		}
		s = s[d+1:]
	}

	// The release starts at the LAST hyphen. A version with no hyphen has no
	// release, which is correct rather than a gap: OSV's "0" sentinel is one,
	// and so is any bound written without a release.
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		if i+1 == len(s) {
			return rpmEVR{}, fmt.Errorf("rpm %q: release is empty: %w", v, ErrInvalid)
		}
		out.release = s[i+1:]
		s = s[:i]
	}
	out.version = s
	if out.version == "" {
		return rpmEVR{}, fmt.Errorf("rpm %q: version is empty: %w", v, ErrInvalid)
	}
	return out, nil
}

// The character classes are ASCII-only, matching rpm's rpmstring.h, which
// defines them for the C locale rather than deferring to the current one. A
// version is bytes, not text: folding a Turkish dotless i into the alphabetic
// class would change an ordering depending on where the scan ran.
func isRPMDigit(c byte) bool { return c >= '0' && c <= '9' }
func isRPMAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isRPMAlnum(c byte) bool { return isRPMDigit(c) || isRPMAlpha(c) }
