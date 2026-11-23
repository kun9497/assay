package amazon

import (
	"fmt"
	"sort"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/version"
)

// collected is one converted advisory and the repository it came from.
type collected struct {
	adv  advisory.Advisory
	repo int
}

// span is the versions one repository has published fixes for under a name,
// first to last.
type span struct{ lo, hi string }

// separateLines narrows the ranges of one release's advisories where its
// repositories carry different version lines of one package name (D174).
//
// AL2 core and its extras topics ship kernel 4.14, 5.4, 5.10 and 5.15 under
// the one name, and postgresql, php, ruby and tomcat likewise, and every
// advisory was stored as [0, fixed). A fully patched core kernel is below
// every 5.10 fix, so it was reported for 367 advisories of other lines, each
// naming a fix that is not a build of its own line (QA 2026-11-20).
//
// A repository that publishes advisories for a name is the judge of its own
// builds of it. So the span of every other such repository lying wholly below
// this one's is cut out of this one's range. A repository that publishes none
// for the name (kernel-ng, php7.4, postgresql10) is nobody's line here: its
// builds keep the reports of the lines above, with no fixed version, since
// none exists in their line.
//
// Only a span wholly below. Repositories that ship one line side by side
// (docker, ecs and aws-nitro-enclaves-cli all carry docker 25) overlap, and
// neither says the other's builds are fixed.
func separateLines(recs []collected) (narrowed int, err error) {
	cmp := version.RPM{}
	type key struct{ eco, name string }
	spans := map[key]map[int]span{}
	for _, r := range recs {
		for _, a := range r.adv.Affected {
			fixed := fixedOf(a)
			if fixed == "" {
				continue
			}
			k := key{a.Ecosystem, a.Name}
			if spans[k] == nil {
				spans[k] = map[int]span{}
			}
			s, ok := spans[k][r.repo]
			if !ok {
				spans[k][r.repo] = span{fixed, fixed}
				continue
			}
			lo, err := cmp.Compare(fixed, s.lo)
			if err != nil {
				return 0, fmt.Errorf("%s: compare %q and %q: %w", a.Name, fixed, s.lo, err)
			}
			hi, err := cmp.Compare(fixed, s.hi)
			if err != nil {
				return 0, fmt.Errorf("%s: compare %q and %q: %w", a.Name, fixed, s.hi, err)
			}
			if lo < 0 {
				s.lo = fixed
			}
			if hi > 0 {
				s.hi = fixed
			}
			spans[k][r.repo] = s
		}
	}
	// Every bound below was compared above, so these cannot fail.
	less := func(a, b string) bool { c, _ := cmp.Compare(a, b); return c < 0 }
	for i := range recs {
		for j, a := range recs[i].adv.Affected {
			byRepo := spans[key{a.Ecosystem, a.Name}]
			own, ok := byRepo[recs[i].repo]
			// A range already opened above 0 was bounded by its own rule
			// (introducedVersion).
			if !ok || len(byRepo) < 2 || a.Ranges[0].Events[0].Introduced != "0" {
				continue
			}
			var below []span
			for repo, s := range byRepo {
				if repo != recs[i].repo && less(s.hi, own.lo) {
					below = append(below, s)
				}
			}
			if len(below) == 0 {
				continue
			}
			sort.Slice(below, func(x, y int) bool { return less(below[x].lo, below[y].lo) })
			recs[i].adv.Affected[j].Ranges[0].Events = windows(below, fixedOf(a), less)
			narrowed++
		}
	}
	return narrowed, nil
}

// windows is [0, fixed) less the spans, which are in order of lo. In rpm
// ordering "v~" is below v and above everything before it, and "v^" is above
// v and below everything after it, so a span is cut with both its ends. A gap
// closes with last_affected, not fixed: the next line's first fix is not a
// fix for a build under it.
func windows(spans []span, fixed string, less func(a, b string) bool) []advisory.Event {
	var out []advisory.Event
	from, hi := "0", ""
	for _, s := range spans {
		if hi == "" || less(hi, s.lo) {
			out = append(out, advisory.Event{Introduced: from}, advisory.Event{LastAffected: s.lo + "~"})
		}
		if hi == "" || less(hi, s.hi) {
			hi = s.hi
		}
		from = hi + "^"
	}
	return append(out, advisory.Event{Introduced: from}, advisory.Event{Fixed: fixed})
}

// fixedOf is the fixed version of the one range buildAffected writes.
func fixedOf(a advisory.Affected) string {
	for _, e := range a.Ranges[0].Events {
		if e.Fixed != "" {
			return e.Fixed
		}
	}
	return ""
}
