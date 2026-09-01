package version

import (
	"fmt"
	"regexp"
	"strings"
)

type PEP440 struct{}

// pep440Pattern is the reference grammar from PEP 440's appendix, translated
// for RE2: possessive quantifiers dropped (a CPython performance detail with no
// semantic effect) and (?a:) dropped (Go has no equivalent).
//
// Deliberately NOT compiled with (?i). Go's case-insensitive flag folds
// Unicode, so [a-z] would match U+212A KELVIN SIGN — accepting input the
// reference implementation rejects. Input is ASCII-checked and lowercased by
// the caller instead.
var pep440Pattern = regexp.MustCompile(`\A` +
	`v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[._-]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[._-]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[._-]?(?P<post_l>post|rev|r)[._-]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[._-]?(?P<dev_l>dev)[._-]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[._-][a-z0-9]+)*))?` +
	`\z`)

// pep440Idx maps every named subexpression of pep440Pattern to its index,
// computed once at init. SubexpIndex is a linear scan of the pattern's name
// list, and parsePEP440 used to call it 8-11 times per parse — measured
// 2026-09-01 as part of PEP 440 parsing being 6.6x the cost of SemVer and
// regexp work being a fifth of the whole matcher's allocation. The map costs
// one hash lookup where the scan cost a walk, and cannot change behavior:
// the indices are the same numbers SubexpIndex returned, fixed at compile
// time by the pattern literal above.
var pep440Idx = func() map[string]int {
	idx := make(map[string]int)
	for i, name := range pep440Pattern.SubexpNames() {
		if name != "" {
			idx[name] = i
		}
	}
	return idx
}()

// pep440Key is the comparison key. Field order is the comparison order.
type pep440Key struct {
	epoch    string   // digit string
	release  []string // trailing zeros already stripped
	preRank  int      // -1 dev-only, 0 a, 1 b, 2 rc, 3 none
	preN     string
	postRank int // 0 absent, 1 present
	postN    string
	devRank  int // 0 present, 1 absent
	devN     string
	hasLocal bool
	local    []string
}

func (PEP440) Compare(a, b string) (int, error) {
	ka, err := parsePEP440(a)
	if err != nil {
		return 0, err
	}
	kb, err := parsePEP440(b)
	if err != nil {
		return 0, err
	}
	if c := compareNumeric(ka.epoch, kb.epoch); c != 0 {
		return c, nil
	}
	// Release components compare numerically; when one is a prefix of the
	// other the shorter is smaller. Trailing zeros were stripped at parse
	// time, which is what makes 1.0 == 1.0.0 == 1.
	for i := 0; i < len(ka.release) && i < len(kb.release); i++ {
		if c := compareNumeric(ka.release[i], kb.release[i]); c != 0 {
			return c, nil
		}
	}
	if c := cmpInt(len(ka.release), len(kb.release)); c != 0 {
		return c, nil
	}
	if c := cmpInt(ka.preRank, kb.preRank); c != 0 {
		return c, nil
	}
	if c := compareNumeric(ka.preN, kb.preN); c != 0 {
		return c, nil
	}
	if c := cmpInt(ka.postRank, kb.postRank); c != 0 {
		return c, nil
	}
	if c := compareNumeric(ka.postN, kb.postN); c != 0 {
		return c, nil
	}
	if c := cmpInt(ka.devRank, kb.devRank); c != 0 {
		return c, nil
	}
	if c := compareNumeric(ka.devN, kb.devN); c != 0 {
		return c, nil
	}
	// A version carrying a local label outranks the same version without one.
	if ka.hasLocal != kb.hasLocal {
		if kb.hasLocal {
			return -1, nil
		}
		return 1, nil
	}
	for i := 0; i < len(ka.local) && i < len(kb.local); i++ {
		x, y := ka.local[i], kb.local[i]
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
		case nx: // a numeric segment always outranks an alphanumeric one
			return 1, nil
		default:
			return -1, nil
		}
	}
	// Unlike the release segment, local labels are not trailing-zero trimmed:
	// the shorter prefix sorts first.
	return cmpInt(len(ka.local), len(kb.local)), nil
}

func parsePEP440(s string) (pep440Key, error) {
	var k pep440Key
	if len(s) > maxVersionLen {
		return k, fmt.Errorf("pep440 %q: %w", s, ErrInvalid)
	}
	// Only ASCII whitespace is stripped. Python's \s also matches U+00A0 and
	// friends; being stricter here is the safe direction.
	t := strings.Trim(s, " \t\n\r\f\v")
	for i := 0; i < len(t); i++ {
		if t[i] >= 0x80 {
			return k, fmt.Errorf("pep440 %q: non-ASCII: %w", s, ErrInvalid)
		}
	}
	t = strings.ToLower(t)

	m := pep440Pattern.FindStringSubmatch(t)
	if m == nil {
		return k, fmt.Errorf("pep440 %q: %w", s, ErrInvalid)
	}
	g := func(name string) string { return m[pep440Idx[name]] }

	k.epoch = trimZeros(orZero(g("epoch")))

	rel := strings.Split(g("release"), ".")
	for i := range rel {
		rel[i] = trimZeros(rel[i])
	}
	for len(rel) > 0 && rel[len(rel)-1] == "0" {
		rel = rel[:len(rel)-1]
	}
	k.release = rel

	preL, hasPre := g("pre_l"), g("pre") != ""
	postPresent := g("post") != ""
	devPresent := g("dev") != ""

	switch {
	case devPresent && !hasPre && !postPresent:
		// A dev-only release sorts before every pre-release of the same
		// version, not between rc and final. This rank is the whole reason
		// the field is signed.
		k.preRank = -1
	case hasPre:
		switch preL {
		case "a", "alpha":
			k.preRank = 0
		case "b", "beta":
			k.preRank = 1
		default: // c, pre, preview, rc
			k.preRank = 2
		}
	default:
		k.preRank = 3
	}
	k.preN = trimZeros(orZero(g("pre_n")))

	if postPresent {
		k.postRank = 1
		n := g("post_n1")
		if n == "" {
			n = g("post_n2")
		}
		k.postN = trimZeros(orZero(n))
	} else {
		k.postN = "0"
	}

	if devPresent {
		k.devRank = 0
		k.devN = trimZeros(orZero(g("dev_n")))
	} else {
		k.devRank = 1
		k.devN = "0"
	}

	if loc := g("local"); loc != "" {
		k.hasLocal = true
		loc = strings.NewReplacer("-", ".", "_", ".").Replace(loc)
		segs := strings.Split(loc, ".")
		for i, seg := range segs {
			if isNumericID(seg) {
				segs[i] = trimZeros(seg)
			}
		}
		k.local = segs
	}
	return k, nil
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func trimZeros(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
