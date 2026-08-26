package version

import (
	"fmt"
	"strings"
)

// Pacman orders Arch Linux package versions.
//
// This is a transliteration of libalpm's own alpm_pkg_vercmp(), parseEVR()
// and rpmvercmp() (lib/libalpm/version.c), not a reading of prose about
// them, and NOT an alias for this package's RPM{} even though libalpm's own
// source says it was "adopted from the rpm source" — the two have since
// diverged in exactly the places that decide whether a package is inside
// its own fix range (D9). Measured against the live Arch advisory feed
// before this type existed: reusing RPM{} disagrees with pacman on real
// (affected, fixed) pairs — tensorflow "2.4.0rc4-2" vs "2.4.0-1" — and the
// disagreement is a silent false negative, the exact class the
// per-ecosystem design exists to prevent. The three load-bearing
// differences:
//
//   - A REMAINING ALPHA TAIL LOSES. libalpm's "final showdown" comment says
//     it plainly: a remaining alpha string never beats an empty one, so
//     `1.0rc < 1.0` (and `1.0a < 1.0b < 1.0beta < 1.0p < 1.0pre < 1.0rc <
//     1.0 < 1.0.a < 1.0.1`, vercmp(8)'s own documented chain). rpm rules
//     the other way — its `2.0.1a > 2.0.1` is a row in rpm_test.go — which
//     is precisely what put tensorflow's rc build on the wrong side of its
//     fix under RPM{}.
//   - SEPARATOR RUN LENGTH DECIDES when it differs. libalpm compares how
//     many non-alphanumeric bytes each side skipped before a segment and
//     the LONGER run is newer (`1..0 > 1.0`), a clause rpm simply does not
//     have. Equal-length runs of different characters still compare equal
//     (`1.0` == `1_0`), as in rpm.
//   - `~` AND `^` ARE ORDINARY SEPARATORS. pacman never adopted rpm's
//     tilde-sorts-below-everything or caret-post-release rules. The tilde
//     flips direction outright: `1.0~1 > 1.0` and `1.0~rc1 > 1.0` here —
//     the tail's first byte is `~`, not a letter, so the remaining-alpha
//     rule does not fire and the longer side wins — where rpm puts any
//     tilde suffix BELOW the bare version. The caret happens to agree with
//     rpm on `1.0^git1 > 1.0`, but by the same generic tail rule rather
//     than a post-release clause, so the agreement is coincidence, not
//     shared semantics.
//
// The [epoch:]pkgver[-pkgrel] frame differs from rpm in one more way: the
// pkgrel is compared ONLY when both sides carry one (alpm_pkg_vercmp's own
// `rel1 && rel2` guard), so `1.0-2` equals a bare `1.0` — rpm compares an
// absent release as the empty string instead. An advisory bound written
// without a pkgrel therefore matches every rebuild of that pkgver, which is
// how the Arch security tracker itself spells "the fix is this upstream
// version, any packaging of it".
type Pacman struct{}

func (Pacman) Compare(a, b string) (int, error) {
	pa, err := parsePacmanEVR(a)
	if err != nil {
		return 0, err
	}
	pb, err := parsePacmanEVR(b)
	if err != nil {
		return 0, err
	}
	if c := alpmVercmp(pa.epoch, pb.epoch); c != 0 {
		return c, nil
	}
	if c := alpmVercmp(pa.version, pb.version); c != 0 {
		return c, nil
	}
	// libalpm's own guard, not an optimization: the release leg runs only
	// when BOTH sides have one. hasRelease and not release != "" because a
	// trailing hyphen ("1.0-") is a present-but-empty release, and libalpm
	// would compare that empty string (and lose to any non-empty one).
	if pa.hasRelease && pb.hasRelease {
		return alpmVercmp(pa.release, pb.release), nil
	}
	return 0, nil
}

// pacmanEVR is a parsed [epoch:]pkgver[-pkgrel].
type pacmanEVR struct {
	epoch      string // kept as the digit string: libalpm compares epochs via rpmvercmp, not atoi
	version    string
	release    string
	hasRelease bool
}

// parsePacmanEVR is libalpm's parseEVR. The epoch ends at the first colon
// and only if every byte before it is a digit (":1.0" is epoch zero, not an
// error — same as rpm); the release starts at the LAST hyphen; an absent
// epoch is "0" on both sides. Refusals follow parseEVR (rpm.go): an empty
// string and embedded whitespace are not versions, and ordering either
// would vouch for a value some upstream field failed to produce (D9 —
// unparseable must surface as skipped, never as "not vulnerable").
func parsePacmanEVR(v string) (pacmanEVR, error) {
	if v == "" {
		return pacmanEVR{}, fmt.Errorf("pacman %q: empty version: %w", v, ErrInvalid)
	}
	if strings.ContainsAny(v, " \t\n\r") {
		return pacmanEVR{}, fmt.Errorf("pacman %q: embedded whitespace: %w", v, ErrInvalid)
	}
	s := v
	out := pacmanEVR{epoch: "0"}

	d := 0
	for d < len(s) && s[d] >= '0' && s[d] <= '9' {
		d++
	}
	if d < len(s) && s[d] == ':' {
		if d > 0 {
			out.epoch = s[:d]
		}
		s = s[d+1:]
	}

	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		out.version, out.release, out.hasRelease = s[:i], s[i+1:], true
	} else {
		out.version = s
	}
	return out, nil
}

func isAlpmDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpmAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isAlpmAlnum(c byte) bool { return isAlpmDigit(c) || isAlpmAlpha(c) }

// alpmVercmp is libalpm's rpmvercmp, transliterated. The C mutates copies
// of its inputs with NUL terminators; this walks indexes instead, but the
// decisions are the C's, in the C's order, including the two it does not
// share with rpm's own rpmvercmp (the separator-length clause and the
// remaining-alpha-loses tail).
func alpmVercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		// Skip separators, remembering how many were skipped on each side.
		si, sj := i, j
		for i < len(a) && !isAlpmAlnum(a[i]) {
			i++
		}
		for j < len(b) && !isAlpmAlnum(b[j]) {
			j++
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		// libalpm: "If the separator lengths were different, we are also
		// finished" — the side that skipped MORE is newer.
		if i-si != j-sj {
			if i-si < j-sj {
				return -1
			}
			return 1
		}

		// One segment per iteration, typed by the FIRST side's first byte:
		// a digit run if it is a digit, an alpha run otherwise.
		isnum := isAlpmDigit(a[i])
		ei, ej := i, j
		if isnum {
			for ei < len(a) && isAlpmDigit(a[ei]) {
				ei++
			}
			for ej < len(b) && isAlpmDigit(b[ej]) {
				ej++
			}
		} else {
			for ei < len(a) && isAlpmAlpha(a[ei]) {
				ei++
			}
			for ej < len(b) && isAlpmAlpha(b[ej]) {
				ej++
			}
		}
		// Type mismatch: b's segment is empty because its first byte is the
		// other class. The numeric side is newer (libalpm: "ret = isnum ? 1
		// : -1"). The symmetric a-side case is unreachable — the segment
		// type was chosen FROM a's first byte, so a's run is never empty —
		// and libalpm's own comment on that branch says "arbitrary".
		segA, segB := a[i:ei], b[j:ej]
		if len(segB) == 0 {
			if isnum {
				return 1
			}
			return -1
		}

		if isnum {
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			// More significant digits wins; equal lengths fall through to
			// the byte compare, which on equal-length digit runs IS numeric
			// order. Never converted to an integer, so a 30-digit date-time
			// version cannot overflow anything.
			if len(segA) > len(segB) {
				return 1
			}
			if len(segA) < len(segB) {
				return -1
			}
		}
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
		i, j = ei, ej
	}

	// Both exhausted (possibly through different separators): equal.
	iRest, jRest := i < len(a), j < len(b)
	if !iRest && !jRest {
		return 0
	}
	// libalpm's "final showdown": a remaining alpha string never beats an
	// empty one. If a is exhausted and b's remainder is not alpha, b is
	// newer; if a's remainder is alpha, b is newer; otherwise a is newer.
	if (!iRest && !isAlpmAlpha(b[j])) || (iRest && isAlpmAlpha(a[i])) {
		return -1
	}
	return 1
}
