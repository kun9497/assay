package version

import (
	"fmt"
	"sort"

	"github.com/kun9497/assay/internal/advisory"
)

// introducedSentinel is OSV's "sorts before any other version" marker. It is
// NOT a version: coercing it to 0.0.0 (semver) or 0 (PEP 440) puts it ABOVE
// real prerelease builds such as 0.0.0-experimental-abc and Go pseudo-versions,
// which then fall outside the range and are silently missed.
const introducedSentinel = "0"

// Evidence records why a comparison decided what it decided (D10). It exists on
// the type rather than in a log line because explainability is goal #1, and
// anything left to logging effectively does not exist.
type Evidence struct {
	RangeType    advisory.RangeType
	Introduced   string
	Fixed        string
	LastAffected string
	Reason       string
	// FixState is the matched range's own statement about why no fix exists,
	// carried through UNRESOLVED (D13). A range whose upper bound this walk
	// actually reached is fixed regardless of what it stores, and only the
	// caller — which can see whether Fixed came back populated — is in a
	// position to say so. Resolving it here would bake a derivation into the
	// evidence and leave no way to tell a stored state from an inferred one.
	FixState advisory.FixState
}

// AffectsVersion reports whether v falls within any range of a, falling back to
// the enumerated Versions list. The returned slice names the listed versions
// that could not be read; it is empty on the ranges path and on a clean list.
//
// Versions is not redundant with Ranges even when both are present, which the
// earlier comment here asserted and the data denies: measured over the v7
// database, 1,390 enumerated entries across 19,939 affected entries are not
// covered by that entry's own ranges. Some of those are upstream over-breadth
// and some correct a range this walk cannot follow — PYSEC-2009-17 carries one
// `introduced` and five `last_affected` events, so the window closes at the
// first of them and only the enumerated list still names plone 3.2 and 3.3.
// Dropping the list to dodge the parse problem would buy false negatives.
func AffectsVersion(c Comparer, v string, a advisory.Affected) (bool, Evidence, []string, error) {
	for _, r := range a.Ranges {
		hit, ev, err := InRange(c, v, r)
		if err != nil {
			return false, Evidence{}, nil, err
		}
		if hit {
			return true, ev, nil, nil
		}
	}
	if len(a.Versions) == 0 {
		return false, Evidence{}, nil, nil
	}

	// D30. Two operands can fail here and they mean opposite things, which the
	// earlier version of this function conflated: it blamed the left one in a
	// comment and then failed the whole advisory whichever one was at fault.
	//
	// The left operand is the installed version, constant across the loop, so
	// an unreadable one really does fail every entry — skipping on that would
	// turn a total failure into a silent clean verdict. It is checked once,
	// here, and still aborts.
	if _, err := c.Compare(v, v); err != nil {
		// Same distinction as D35 draws in the ranges path: this is the
		// installed version, not the advisory's list.
		return false, Evidence{}, nil, withCause(CauseTargetVersion,
			fmt.Errorf("this package's own version %q could not be read: %w", v, err))
	}
	// The right operand is upstream data, and 0.184% of it does not parse
	// (2,411 of 1,309,665 entries measured). One such entry aborted the whole
	// advisory, so a package whose own version is perfectly readable was
	// reported unevaluable because some *other* release in the list was not.
	// A listed version we cannot parse cannot be shown equal to a v we can, so
	// nothing is concluded either way by skipping it — but it may denote the
	// same release, so it is returned rather than discarded and the caller
	// records it. Dropping that record silently is what turns this from a loud
	// miss into a quiet one.
	var unreadable []string
	for _, known := range a.Versions {
		cmp, err := c.Compare(v, known)
		if err != nil {
			unreadable = append(unreadable, known)
			continue
		}
		if cmp == 0 {
			return true, Evidence{
				Reason: fmt.Sprintf("version %s is listed as affected", v),
			}, unreadable, nil
		}
	}
	return false, Evidence{}, unreadable, nil
}

// InRange walks an OSV range's events in ascending version order, tracking
// whether v is currently inside an open window. Windows are half-open
// [introduced, fixed), with the exception of last_affected, which is inclusive.
func InRange(c Comparer, v string, r advisory.Range) (bool, Evidence, error) {
	// GIT ranges carry commit SHAs, not versions. Skipping is correct; parsing
	// would error on data that was never meant for a Comparer.
	if r.Type == advisory.RangeGit {
		return false, Evidence{}, nil
	}

	// A range whose events carry no bound at all cannot be evaluated. Walking
	// it opens no window and returns "not affected" — indistinguishable from a
	// real miss, so the caller has no signal that anything went wrong. Malformed
	// input must surface.
	var actionable bool
	for _, e := range r.Events {
		if eventVersion(e) != "" {
			actionable = true
			break
		}
	}
	if !actionable {
		return false, Evidence{}, fmt.Errorf(
			"range of type %q carries no introduced, fixed, or last_affected event: %w",
			r.Type, ErrInvalid)
	}

	// OSV only *recommends* that events arrive sorted, and its reference
	// algorithm sorts before walking. An advisory that lists a later window
	// first is well-formed, and walking it in file order returns "not
	// vulnerable" with no error — a silent miss on valid input.
	//
	// A window that closes at the version it opens at is taken out first and
	// judged on its own (A7, D154): the sort orders a close before an open at
	// the same version, which is what two windows meeting at a version need,
	// and would turn [X,X) and [X,X] into windows that never close.
	walked, taken := splitDegenerate(c, r.Events)
	events, err := sortEvents(c, walked)
	if err != nil {
		return false, Evidence{}, err
	}

	var (
		inside bool
		ev     Evidence
	)
	ev.RangeType = r.Type
	ev.FixState = r.FixState

	for _, e := range events {
		switch {
		case e.Introduced != "":
			ge, err := atLeast(c, v, e.Introduced)
			if err != nil {
				return false, Evidence{}, err
			}
			if ge {
				inside = true
				ev.Introduced = e.Introduced
				ev.Fixed, ev.LastAffected = "", ""
			}

		case e.Fixed != "":
			// D88: Chainguard/Wolfi pair introduced:"0" with fixed:"0" on 20.2%
			// of affected entries — the OSV shape their build uses to assert a
			// package was NEVER affected, rather than omitting the affected
			// entry outright (verified 99.5% against Wolfi's own secdb
			// secfixes["0"], measured 2026-08-22). "0" is not treated as a
			// sentinel here the way it is in atLeast below: it is compared as
			// an ordinary version, and it works out safe for an unrelated
			// reason rather than by a special case. "0" parses as a real,
			// minimal version under every comparer currently registered for an
			// ecosystem OSV publishes it in (APK's leading apkInitialDigit
			// token, zero), so cmp is always >= 0 against any real installed
			// version and the branch below always fires: the window opened by
			// introduced:"0" closes again on the very same version, [0, 0) is
			// empty, and InRange reports no hit — never a false positive, and
			// ev.Fixed is never set to "0" either, since that only happens in
			// the untaken branch. TestMatch_ChainguardFixedZeroSentinelNever-
			// YieldsAFinding (matcher package) pins this end to end; if a
			// future ecosystem's comparer ever fails to parse "0" the failure
			// mode is still safe (an advisory-data skip, D30), never a match.
			cmp, err := c.Compare(v, e.Fixed)
			if err != nil {
				return false, Evidence{}, unreadablePackageVersion(v, "fixed", e.Fixed, err)
			}
			if inside && cmp >= 0 {
				inside = false // exclusive upper bound
			} else if inside && ev.Fixed == "" && ev.LastAffected == "" {
				// Only the bound closing the window v actually sits in. A
				// later window's bound would name the wrong fix version, and
				// wrong remediation advice is worse than none.
				ev.Fixed = e.Fixed
			}

		case e.LastAffected != "":
			cmp, err := c.Compare(v, e.LastAffected)
			if err != nil {
				return false, Evidence{}, unreadablePackageVersion(v, "last_affected", e.LastAffected, err)
			}
			if inside && cmp > 0 {
				inside = false // inclusive upper bound: equal is still affected
			} else if inside && ev.Fixed == "" && ev.LastAffected == "" {
				ev.LastAffected = e.LastAffected
			}
		}
	}

	// The windows taken out above, each judged on both of its own bounds.
	// Bounds that compare equal usually make [X,X) empty and [X,X] one
	// version, but not under every comparer: Bitnami's bare "1.0.0" equals
	// every revision of it while "1.0.0-1" sorts below "1.0.0-3", so
	// [1.0.0, 1.0.0-3) holds 1.0.0-1 (branch review wf_6ce5dff7-2de).
	// Consulted only when the walk found nothing, so a version inside an
	// ordinary window keeps that window's evidence; and when every window was
	// taken out, this is what still compares v, so an unreadable installed
	// version is an error here as it was in the walk.
	for _, w := range taken {
		if inside {
			break
		}
		ge, err := atLeast(c, v, w.open)
		if err != nil {
			return false, Evidence{}, err
		}
		if !ge {
			continue
		}
		cmp, err := c.Compare(v, w.close)
		if err != nil {
			bound := "fixed"
			if w.inclusive {
				bound = "last_affected"
			}
			return false, Evidence{}, unreadablePackageVersion(v, bound, w.close, err)
		}
		if cmp < 0 || (w.inclusive && cmp == 0) {
			inside = true
			ev.Introduced, ev.Fixed, ev.LastAffected = w.open, "", ""
			if w.inclusive {
				ev.LastAffected = w.close
			} else {
				ev.Fixed = w.close
			}
		}
	}

	if inside {
		ev.Reason = describe(v, ev)
	}
	return inside, ev, nil
}

// takenWindow is one window splitDegenerate took out of the walk, with the
// advisory's own spelling of both bounds.
type takenWindow struct {
	open, close string
	inclusive   bool // closed by last_affected rather than fixed
}

// splitDegenerate takes out every window whose close compares equal to its
// open -- an empty [X,X) or a single-version [X,X] under a comparer whose
// equality is transitive -- and returns the events left to walk and the
// windows taken out, which InRange judges on their own bounds.
//
// A window is the run of events from one introduced to the next, in file
// order, and its close is the first fixed or last_affected in that run --
// file order is the only thing that says which close belongs to which open.
// By this rule the published database held 888 such windows on 2026-10-27:
// 244 empty (Bitnami 239, fifteen of them spelled differently, such as
// golang's 1.24.0-0 / 1.24.0; crates.io 5) and 644 single-version (Bitnami
// 624, Packagist 20). Taking them out is what lets sortEvents put a close
// before an open at the same version without reopening them.
//
// A pair that cannot be compared is left in the walk rather than guessed
// at, and sortEvents then refuses the range with the advisory named as the
// cause; a pair taken out was readable by construction.
//
// Only a window with one close, at or above its open, is well-formed. On
// anything else -- two closes before the next introduced, or a close below
// its open -- which close pairs with the open is a guess. The published
// database held both on 2026-10-27 (392 closes below their open, 380 of them
// Alpine; 123 windows with two or more closes, Alpine 100 and PyPI 23), and
// no judgment at any bound of a tied range changed against the walk before
// A7.
func splitDegenerate(c Comparer, in []advisory.Event) (walk []advisory.Event, taken []takenWindow) {
	drop := make([]bool, len(in))
	closeOf := func(e advisory.Event) string {
		if e.Introduced != "" {
			return ""
		}
		if e.Fixed != "" {
			return e.Fixed
		}
		return e.LastAffected
	}
	take := func(i, j int) bool {
		if drop[j] {
			return false
		}
		closeAt := closeOf(in[j])
		if closeAt == "" {
			return false
		}
		if cmp, err := c.Compare(in[i].Introduced, closeAt); err != nil || cmp != 0 {
			return false
		}
		drop[i], drop[j] = true, true
		taken = append(taken, takenWindow{open: in[i].Introduced, close: closeAt, inclusive: in[j].Fixed == ""})
		return true
	}
	// First the window as file order writes it: the first close after an
	// open, before the next introduced.
	//
	// A window the sentinel opens may be taken out too (PEP 440 compares
	// "0" equal to "0.0"): it is judged with atLeast like any other, and
	// atLeast reads the sentinel as negative infinity.
	for i, e := range in {
		if e.Introduced == "" {
			continue
		}
		for j := i + 1; j < len(in); j++ {
			if in[j].Introduced != "" {
				break
			}
			if closeOf(in[j]) != "" {
				take(i, j)
				break
			}
		}
	}
	pairByVersion(c, in, drop, take)
	for i, e := range in {
		if !drop[i] {
			walk = append(walk, e)
		}
	}
	return walk, taken
}

// pairByVersion takes out, in version order, the windows file order did not
// pair (QA 2026-10-30). OSV only recommends sorted events, and pairing by file
// order alone left [introduced 1, introduced 3, last_affected 1,
// last_affected 3] in the walk, which the sort read as [1, 3]: 2.0.0 was
// affected, and 4.0.0 in another order.
//
// At each version X, with the opens and closes still in the walk there, a
// close has to end something. If no window is open just below X, a close at X
// can end only an open at X, so each such open takes one: the empty [X,X) or
// the one version [X,X]. If a window is open below X, one close is left in the
// walk to end it -- which is D154's tie rule for two windows that meet at X,
// unchanged, evidence and all -- and only the closes beyond it take opens.
// Without that reservation the outer window would close at X in one order of
// the events and run on in another.
//
// Ties are grouped by comparing neighbours in sorted order, so under
// Bitnami's equality, which is not transitive, a group can chain two
// versions that do not compare equal; take still compares each pair it takes
// out. A range with an unreadable bound is left alone: sortEvents refuses it
// with the advisory named.
func pairByVersion(c Comparer, in []advisory.Event, drop []bool, take func(i, j int) bool) {
	var idx []int
	for i, e := range in {
		v := eventVersion(e)
		if v == "" || drop[i] {
			continue
		}
		if v != introducedSentinel {
			if _, err := c.Compare(v, v); err != nil {
				return
			}
		}
		idx = append(idx, i)
	}
	sort.SliceStable(idx, func(a, b int) bool { return eventLess(c, in[idx[a]], in[idx[b]]) })

	sameVersion := func(a, b advisory.Event) bool {
		va, vb := eventVersion(a), eventVersion(b)
		if va == introducedSentinel || vb == introducedSentinel {
			return va == vb
		}
		cmp, _ := c.Compare(va, vb) // both validated above
		return cmp == 0
	}

	inside := false // whether a window is open just below the current group
	for start := 0; start < len(idx); {
		end := start + 1
		for end < len(idx) && sameVersion(in[idx[end-1]], in[idx[end]]) {
			end++
		}
		group := idx[start:end]
		var closes []int
		for _, i := range group {
			if closesWindow(in[i]) {
				closes = append(closes, i)
			}
		}
		reserve := 0
		if inside {
			reserve = 1
		}
		for _, i := range group {
			if in[i].Introduced == "" || drop[i] {
				continue
			}
			for k := reserve; k < len(closes); k++ {
				if take(i, closes[k]) {
					break
				}
			}
		}
		// The state just above X: sorted, a group's closes come before its
		// opens, so the last event still in the walk decides it.
		for _, i := range group {
			if !drop[i] {
				inside = in[i].Introduced != ""
			}
		}
		start = end
	}
}

// eventVersion returns whichever bound an event carries, or "" for an event
// this slice does not act on (a bare `limit`, or a malformed empty event).
func eventVersion(e advisory.Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return ""
}

// sortEvents orders events by the version each carries, with the introduced
// sentinel first and, at the same version, a close before an open.
//
// Every bound is validated before sorting so the comparator cannot fail. A
// comparator that swallowed errors would silently produce an arbitrary order,
// and an arbitrary order here is a wrong verdict with no error attached —
// strictly worse than refusing to evaluate the range.
func sortEvents(c Comparer, in []advisory.Event) ([]advisory.Event, error) {
	out := append([]advisory.Event(nil), in...)
	for _, e := range out {
		ver := eventVersion(e)
		if ver == "" || ver == introducedSentinel {
			continue
		}
		if _, err := c.Compare(ver, ver); err != nil {
			// D35: say whose data is at fault. This is the advisory's own
			// bound, and nothing the person running the scan can act on —
			// the opposite of the walk's failures below, which are always the
			// installed version. Both used to render as "not evaluated" with
			// the cause left to be worked out from which operand the wrapped
			// error happened to name.
			return nil, withCause(CauseAdvisoryData,
				fmt.Errorf("the advisory's range bound %q could not be read: %w", ver, err))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return eventLess(c, out[i], out[j]) })
	return out, nil
}

// eventLess is sortEvents' order. Every non-empty, non-sentinel bound must
// already have been validated: it cannot report a comparison error.
func eventLess(c Comparer, a, b advisory.Event) bool {
	vi, vj := eventVersion(a), eventVersion(b)
	// Events carrying no bound at all — a bare `limit`, or a malformed
	// empty event — are parked at the end. They must not reach Compare:
	// it would error, the error would be discarded, and every such event
	// would report as equal to everything. That is a violated strict weak
	// ordering, which can leave the whole slice unsorted and silently
	// undo the sort this function exists to perform.
	if vi == "" || vj == "" {
		return vi != "" && vj == ""
	}
	// The sentinel is negative infinity, so it sorts before everything.
	// Decided by string identity rather than by Compare, because PEP 440
	// parses "0" as a real version that would otherwise sort above 0.dev0
	// and 0a1 — reintroducing the bug the sentinel exists to prevent.
	if vi == introducedSentinel {
		return vj != introducedSentinel
	}
	if vj == introducedSentinel {
		return false
	}
	// Cannot fail: the caller validated every non-empty, non-sentinel bound.
	cmp, _ := c.Compare(vi, vj)
	if cmp != 0 {
		return cmp < 0
	}
	// A7 (D154): at the same version a close goes before an open. Two
	// windows meeting at X -- one fixed or last_affected at X, the next
	// introduced at X -- were ordered by file order, so a range listing
	// the later window first opened it and shut it again at X, and every
	// version inside it was clean. A window that opens and closes at the
	// same X never gets here: splitDegenerate took it out. Ranking by kind
	// keeps this a strict weak ordering whenever the comparer's equality
	// is transitive, which a rule that looked at which window each event
	// belongs to would not be. Bitnami's equality is not (a bare core
	// equals every revision of it), and no tie rule restores an order
	// that the comparer itself does not have; that was so before A7.
	return closesWindow(a) && !closesWindow(b)
}

// closesWindow reports whether an event is a fixed or last_affected bound.
func closesWindow(e advisory.Event) bool {
	return e.Introduced == "" && (e.Fixed != "" || e.LastAffected != "")
}

// unreadablePackageVersion names the installed version as the cause, which by
// this point it must be.
//
// sortEvents validates every bound before the walk begins, and it selects the
// field to validate with the same introduced/fixed/last_affected precedence the
// walk uses to select the field to compare (eventVersion mirrors InRange's
// switch). So the bound reaching Compare here is always one that already
// parsed, and the only operand left that can fail is v. **Those two orderings
// have to stay identical**: give eventVersion a different precedence and an
// unvalidated bound reaches this function, which would then blame the package
// for the advisory's defect — the exact confusion D35 exists to remove.
//
// The bound is still named, as context for which comparison was being made, not
// as a suspect.
func unreadablePackageVersion(v, role, bound string, err error) error {
	return withCause(CauseTargetVersion,
		fmt.Errorf("this package's own version %q could not be read, comparing it against the advisory's %s bound %q: %w",
			v, role, bound, err))
}

// atLeast reports whether v >= bound, resolving the OSV sentinel first.
func atLeast(c Comparer, v, bound string) (bool, error) {
	if bound == introducedSentinel {
		return true, nil // negative infinity: everything is at or above it
	}
	cmp, err := c.Compare(v, bound)
	if err != nil {
		return false, unreadablePackageVersion(v, "introduced", bound, err)
	}
	return cmp >= 0, nil
}

func describe(v string, ev Evidence) string {
	lower := ev.Introduced
	if lower == introducedSentinel {
		lower = "any earlier version"
	}
	switch {
	case ev.Fixed != "":
		return fmt.Sprintf("%s is at or above %s and below the fix %s", v, lower, ev.Fixed)
	case ev.LastAffected != "":
		return fmt.Sprintf("%s is at or above %s and at or below %s", v, lower, ev.LastAffected)
	default:
		return fmt.Sprintf("%s is at or above %s, with no fixed version recorded", v, lower)
	}
}
