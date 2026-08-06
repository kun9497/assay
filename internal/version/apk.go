package version

import (
	"fmt"
	"strings"
)

// APK orders Alpine package versions the way apk-tools does
// (apk-tools/src/version.c). It is deliberately a transliteration of that
// algorithm rather than an interpretation: the token-kind ordering and the
// leading-zero rule both produce results that look wrong until you check them
// against the source, and a "cleaner" rewrite is how false negatives get in.
type APK struct{}

// Token kinds in apk-tools' declaration order. The numeric order is
// load-bearing: when two versions diverge in shape, the comparison falls back to
// comparing kinds, and a HIGHER kind means a LOWER version. apkEnd sitting near
// the top is what makes "1.0" sort below "1.0-r0".
type apkKind int

const (
	apkInitialDigit apkKind = iota
	apkDigit
	apkLetter
	apkSuffix
	apkSuffixNo
	apkCommitHash
	apkRevisionNo
	apkEnd
)

// Ascending suffix order, with the empty string — meaning "no suffix" — sitting
// in the middle at apkSuffixNone. Everything below it is a pre-release and
// everything above it is a post-release, so 1.0_rc1 < 1.0 < 1.0_p1. Reversing
// the upper half would silently clear every _p package.
var apkSuffixOrder = []string{
	"alpha", "beta", "pre", "rc",
	"", // apkSuffixNone
	"cvs", "svn", "git", "hg", "p",
}

const apkSuffixNone = 4

type apkPart struct {
	kind apkKind
	num  uint64 // digits, suffix numbers, revision
	str  string // raw text, for the string-sort path and letters/hashes
	sfx  int    // index into apkSuffixOrder, for apkSuffix
	// postLetter marks the digits of a letter patch level (the "1" of 3.3.3p1).
	// They are apkDigit so the kind ordering comes out right, but they must not
	// take apkDigit's leading-zero string-sort path: in apk-tools 2.x that rule
	// belongs to TOKEN_DIGIT_OR_ZERO, the state entered after '.', and the
	// post-letter token is a plain TOKEN_DIGIT. See D31.
	postLetter bool
}

// parseAPK turns a version into its token stream. It rejects rather than
// guesses: an unparseable version must reach the caller as ErrInvalid so the
// package is reported as skipped (D9).
func parseAPK(v string) ([]apkPart, error) {
	if v == "" {
		return nil, fmt.Errorf("%w: empty version", ErrInvalid)
	}

	var parts []apkPart
	i := 0

	readNum := func() (uint64, string, bool) {
		start := i
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			i++
		}
		if i == start {
			return 0, "", false
		}
		raw := v[start:i]
		var n uint64
		for _, c := range []byte(raw) {
			// Saturate rather than wrap. A version number long enough to
			// overflow is not a real one, but wrapping would silently reorder
			// it, which is the failure mode this package exists to avoid.
			if n > (1<<63)/10 {
				n = 1 << 63
				break
			}
			n = n*10 + uint64(c-'0')
		}
		return n, raw, true
	}

	n, raw, ok := readNum()
	if !ok {
		return nil, fmt.Errorf("%w: %q does not start with a digit", ErrInvalid, v)
	}
	parts = append(parts, apkPart{kind: apkInitialDigit, num: n, str: raw})

	for i < len(v) && v[i] == '.' {
		i++
		n, raw, ok := readNum()
		if !ok {
			return nil, fmt.Errorf("%w: %q has an empty component", ErrInvalid, v)
		}
		parts = append(parts, apkPart{kind: apkDigit, num: n, str: raw})
	}

	if i < len(v) && v[i] >= 'a' && v[i] <= 'z' {
		parts = append(parts, apkPart{kind: apkLetter, str: v[i : i+1]})
		i++
		// D31: a letter may carry a numeric patch level — libretls 3.3.3p1-r3,
		// sudo 1.7.4p6-r0, python 0.12.5a0-r0. apk-tools 2.x parses these
		// (next_token has an explicit TOKEN_LETTER-then-digit clause, and its
		// demotion whitelist names that transition); apk-tools 3.x rejects them
		// and asserts so in its own vectors. Every released Alpine ships 2.14.x,
		// and 3.x answers EQUAL for 3.3.3p1-r3 against 3.3.3p1-r2 — it would
		// call an unpatched host fixed — so 2.x is the behaviour to follow here.
		//
		// Only ONE production is added: digits, once, immediately after the
		// letter. A second letter (1.0a1b2) and a dot after these digits
		// (1.0a1.2, which 3.x rejects outright) still fall through to the
		// trailing-input check below and stay errors.
		//
		// apkDigit is the kind apk-tools 2.x uses (next_token sets n =
		// TOKEN_DIGIT here), and the ordinal is load-bearing against apkSuffix
		// and apkRevisionNo — both of those substitutions turn the table red.
		// Substituting apkInitialDigit does NOT, and that one is a true
		// equivalent rather than a gap: this token sits at index 2 or later,
		// apkInitialDigit only ever sits at index 0, and a dotted apkDigit can
		// never align with it either because the letter position resolves the
		// comparison first. Ordinals 0 and 1 both sit below every kind it can
		// actually meet, so the two answer alike everywhere reachable.
		if n, raw, ok := readNum(); ok {
			parts = append(parts, apkPart{kind: apkDigit, num: n, str: raw, postLetter: true})
		}
	}

	for i < len(v) && v[i] == '_' {
		i++
		start := i
		for i < len(v) && v[i] >= 'a' && v[i] <= 'z' {
			i++
		}
		name := v[start:i]
		sfx := -1
		for idx, s := range apkSuffixOrder {
			if s != "" && s == name {
				sfx = idx
				break
			}
		}
		if sfx < 0 {
			return nil, fmt.Errorf("%w: %q has unknown suffix %q", ErrInvalid, v, name)
		}
		parts = append(parts, apkPart{kind: apkSuffix, sfx: sfx, str: name})
		// The number is optional: "_git" with no digits is legal.
		if n, raw, ok := readNum(); ok {
			parts = append(parts, apkPart{kind: apkSuffixNo, num: n, str: raw})
		}
	}

	if i < len(v) && v[i] == '~' {
		i++
		start := i
		for i < len(v) && isAPKHex(v[i]) {
			i++
		}
		if i == start {
			return nil, fmt.Errorf("%w: %q has an empty commit hash", ErrInvalid, v)
		}
		parts = append(parts, apkPart{kind: apkCommitHash, str: v[start:i]})
	}

	if i < len(v) && v[i] == '-' {
		i++
		if i >= len(v) || v[i] != 'r' {
			return nil, fmt.Errorf("%w: %q has a '-' that is not '-r'", ErrInvalid, v)
		}
		i++
		n, raw, ok := readNum()
		if !ok {
			return nil, fmt.Errorf("%w: %q has '-r' with no number", ErrInvalid, v)
		}
		parts = append(parts, apkPart{kind: apkRevisionNo, num: n, str: raw})
	}

	if i != len(v) {
		return nil, fmt.Errorf("%w: %q has trailing %q", ErrInvalid, v, v[i:])
	}
	return parts, nil
}

func isAPKHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// Compare orders two apk versions. It reports an error rather than an ordering
// when either side is unparseable, because treating garbage as "not vulnerable"
// is a miss (D9).
func (APK) Compare(a, b string) (int, error) {
	pa, err := parseAPK(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseAPK(b)
	if err != nil {
		return 0, err
	}

	at := func(p []apkPart, i int) apkPart {
		if i < len(p) {
			return p[i]
		}
		return apkPart{kind: apkEnd}
	}

	for i := 0; ; i++ {
		ta, tb := at(pa, i), at(pb, i)

		if ta.kind != tb.kind {
			// A pre-release suffix loses to whatever the other side has,
			// including nothing at all: 1.0_rc1 < 1.0.
			if ta.kind == apkSuffix && ta.sfx < apkSuffixNone {
				return -1, nil
			}
			if tb.kind == apkSuffix && tb.sfx < apkSuffixNone {
				return 1, nil
			}
			// Otherwise the higher kind is the lower version. apkEnd is near the
			// top, so the stream that ran out first sorts below.
			if ta.kind > tb.kind {
				return -1, nil
			}
			return 1, nil
		}

		switch ta.kind {
		case apkEnd:
			return 0, nil

		case apkInitialDigit:
			// The leading-zero rule below does NOT apply here. That is why
			// apk-tools gives the first component its own token kind, and it is
			// checkable against upstream's own vectors: "006" > "1.0.0" and
			// "021109-r3" > "3.0.0-r2", both of which a string sort gets
			// backwards. Date-stamped versions like 021109 are real.
			if c := cmpAPKUint(ta.num, tb.num); c != 0 {
				return c, nil
			}

		case apkDigit:
			// apk-tools: "if either of the digits have a leading zero, use raw
			// string comparison similar to Gentoo spec". So 1.01 < 1.1, which
			// numeric comparison would call equal.
			//
			// D31: a letter's patch level is exempt. In apk-tools 2.x that rule
			// lives in TOKEN_DIGIT_OR_ZERO — the state entered after '.' — and a
			// post-letter digit is a plain TOKEN_DIGIT, so 1.0a01 == 1.0a1 there
			// while a string sort would call them different. The two flags can
			// never disagree: for a post-letter digit to align with a dotted one,
			// one stream would have to carry apkLetter where the other carries
			// apkDigit, and the kind check above returns before reaching here.
			// A mutation flipping || to && therefore survives, and is equivalent.
			if !(ta.postLetter || tb.postLetter) &&
				(strings.HasPrefix(ta.str, "0") || strings.HasPrefix(tb.str, "0")) {
				if c := strings.Compare(ta.str, tb.str); c != 0 {
					return c, nil
				}
				continue
			}
			if c := cmpAPKUint(ta.num, tb.num); c != 0 {
				return c, nil
			}

		case apkLetter, apkCommitHash:
			if c := strings.Compare(ta.str, tb.str); c != 0 {
				return c, nil
			}

		case apkSuffix:
			if c := cmpAPKInt(ta.sfx, tb.sfx); c != 0 {
				return c, nil
			}

		case apkSuffixNo, apkRevisionNo:
			if c := cmpAPKUint(ta.num, tb.num); c != 0 {
				return c, nil
			}
		}
	}
}

func cmpAPKUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpAPKInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
