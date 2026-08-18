package version

import (
	"fmt"
	"strings"
)

// Maven orders versions the way org.apache.maven.artifact.versioning's
// ComparableVersion does (D9) — the 3.9.x line, which is what GHSA/OSV Maven
// ranges were authored against. Maven 4 is a rewrite with different
// tokenization; the POM reference website documents THAT, not this, so the
// port follows the 3.9.x source, validated by replaying its entire
// ComparableVersionTest (~600 assertions) through an oracle.
//
// The shape is nested lists: '-' opens a sub-list, '.' separates, and a
// digit<->letter transition splits AND (since MNG-7644) behaves like '-' for
// the letter side, which is what makes 2-abc == 2.0.abc. Qualifiers rank
// alpha < beta < milestone < rc < snapshot < release < sp, and an UNKNOWN
// qualifier ranks above sp — "1.0-x" is newer than "1.0". Single-letter
// a/b/m expand to alpha/beta/milestone only when a digit follows: "1.0-a1"
// is an alpha, "1.0-a" is an unknown qualifier NEWER than 1.0.
type Maven struct{}

// mvnItem is one parsed node. Exactly one of the three shapes is active:
// digits != "" or isNum (a number), list != nil (a sub-list), else a string
// qualifier. Numbers keep their digit string because Maven types them by
// LENGTH — <=9 int, <=18 long, else BigInteger — and the three types order
// int < long < BigInteger regardless of value, so a 19-zeros token outranks
// a plain 0. An all-zeros token keeps its zeros for typing (upstream returns
// it unstripped) while comparing as zero.
type mvnItem struct {
	isNum  bool
	digits string // as written, leading zeros kept only when all zeros
	str    string // aliased qualifier text
	list   []*mvnItem
}

func (Maven) Compare(a, b string) (int, error) {
	// ComparableVersion itself never throws — "", "-", "..." all parse and
	// equal "0". assay refuses only the empty string: it is a missing value,
	// not a version, and Maven's answer (equal to 0) would mark the package
	// clean. Everything else must parse; inventing failures here produces
	// false negatives.
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return 0, fmt.Errorf("%w: empty version", ErrInvalid)
	}
	return mvnListCompare(mvnParse(a), mvnParse(b)), nil
}

// mvnParse is parseVersion, port for port: a stack of open lists, '-' and
// digit-transitions descending, '.' flushing, normalization popped
// innermost-first at the end.
func mvnParse(v string) []*mvnItem {
	v = strings.ToLower(v)
	root := &mvnItem{list: []*mvnItem{}}
	cur := root
	stack := []*mvnItem{root}
	push := func() {
		next := &mvnItem{list: []*mvnItem{}}
		cur.list = append(cur.list, next)
		cur = next
		stack = append(stack, next)
	}
	isDigit := false
	start := 0

	flush := func(end int) {
		if end == start {
			cur.list = append(cur.list, &mvnItem{isNum: true, digits: "0"})
		} else {
			cur.list = append(cur.list, mvnParseItem(isDigit, v[start:end], false))
		}
	}

	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.':
			flush(i)
			start = i + 1
		case c == '-':
			flush(i)
			start = i + 1
			push()
		case c >= '0' && c <= '9':
			if !isDigit && i > start {
				// Letter run ends at a digit (MNG-7644): the letters become
				// a followedByDigit string in a sub-list of their own, and
				// the digits start another — "1.0.0.X1" tokenizes exactly
				// like "1.0.0-X-1".
				if len(cur.list) > 0 {
					push()
				}
				cur.list = append(cur.list, mvnParseItem(false, v[start:i], true))
				start = i
				push()
			}
			isDigit = true
		default:
			if isDigit && i > start {
				cur.list = append(cur.list, mvnParseItem(true, v[start:i], false))
				start = i
				push()
			}
			isDigit = false
		}
	}
	if len(v) > start {
		if !isDigit && len(cur.list) > 0 {
			// A trailing string token also opens a sub-list first —
			// the other half of MNG-7644 (".X" behaves like "-X").
			push()
		}
		cur.list = append(cur.list, mvnParseItem(isDigit, v[start:], false))
	}

	// Innermost lists normalize first: an outer trim asks inner lists
	// whether they emptied, so the order is load-bearing.
	for i := len(stack) - 1; i >= 0; i-- {
		mvnNormalize(stack[i])
	}
	return root.list
}

func mvnParseItem(isDigit bool, s string, followedByDigit bool) *mvnItem {
	if isDigit {
		stripped := strings.TrimLeft(s, "0")
		if stripped == "" {
			// All zeros keeps its length — a 19-zero token types as
			// BigInteger and outranks int zero (upstream's exact, odd
			// behaviour; two versions can share a canonical rendering and
			// still not compare equal).
			return &mvnItem{isNum: true, digits: s}
		}
		return &mvnItem{isNum: true, digits: stripped}
	}
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return &mvnItem{str: s}
}

// mvnNormalize trims from the END: null items are removed; a non-null
// NON-list stops the walk; a non-null sub-list keeps it going left
// (MNG-6964 — stopping there leaves a null stranded behind the sub-list).
func mvnNormalize(it *mvnItem) {
	for i := len(it.list) - 1; i >= 0; i-- {
		last := it.list[i]
		if mvnIsNull(last) {
			it.list = append(it.list[:i], it.list[i+1:]...)
		} else if last.list == nil {
			break
		}
	}
}

func mvnIsNull(it *mvnItem) bool {
	switch {
	case it.isNum:
		return strings.Trim(it.digits, "0") == ""
	case it.list != nil:
		return len(it.list) == 0
	default:
		return it.str == ""
	}
}

// mvnQualifierKey is comparableQualifier: known qualifiers rank by index,
// unknown ones become "7-<text>" — which sorts lexically ABOVE "6" (sp), so
// every unknown qualifier is newer than a release, and unknowns order among
// themselves by their raw text.
func mvnQualifierKey(s string) string {
	switch s {
	case "alpha":
		return "0"
	case "beta":
		return "1"
	case "milestone":
		return "2"
	case "rc":
		return "3"
	case "snapshot":
		return "4"
	case "":
		return "5"
	case "sp":
		return "6"
	}
	return "7-" + s
}

// mvnItemCompare orders two items, either possibly nil (the padding when one
// list runs out). Cross-type: String < List < Number.
func mvnItemCompare(a, b *mvnItem) int {
	if a == nil {
		if b == nil {
			return 0
		}
		return -mvnItemCompare(b, nil)
	}
	switch {
	case a.isNum:
		switch {
		case b == nil:
			if mvnIsNull(a) {
				return 0
			}
			return 1
		case b.isNum:
			return mvnNumCompare(a.digits, b.digits)
		default:
			return 1 // number beats string and list alike
		}
	case a.list != nil:
		switch {
		case b == nil:
			// Every element weighs in, not only the first: a list is null-
			// equal only if all of its items are.
			for _, it := range a.list {
				if c := mvnItemCompare(it, nil); c != 0 {
					return c
				}
			}
			return 0
		case b.isNum:
			return -1
		case b.list != nil:
			return mvnListCompare(a.list, b.list)
		default:
			return 1 // list beats string
		}
	default:
		switch {
		case b == nil:
			return strings.Compare(mvnQualifierKey(a.str), mvnQualifierKey(""))
		case b.list != nil, b.isNum:
			return -1
		default:
			return strings.Compare(mvnQualifierKey(a.str), mvnQualifierKey(b.str))
		}
	}
}

func mvnListCompare(a, b []*mvnItem) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var l, r *mvnItem
		if i < len(a) {
			l = a[i]
		}
		if i < len(b) {
			r = b[i]
		}
		if c := mvnItemCompare(l, r); c != 0 {
			return c
		}
	}
	return 0
}

// mvnNumCompare: type first (by kept-length buckets <=9 / <=18 / larger),
// then value. Within a type both strings are leading-zero-free unless all
// zeros, so trimmed length-then-lex is exact integer ordering.
func mvnNumCompare(a, b string) int {
	ta, tb := mvnNumType(a), mvnNumType(b)
	if ta != tb {
		if ta < tb {
			return -1
		}
		return 1
	}
	va, vb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(va) != len(vb) {
		if len(va) < len(vb) {
			return -1
		}
		return 1
	}
	return strings.Compare(va, vb)
}

func mvnNumType(s string) int {
	switch {
	case len(s) <= 9:
		return 0
	case len(s) <= 18:
		return 1
	}
	return 2
}
