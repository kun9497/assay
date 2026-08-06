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
	events, err := sortEvents(c, r.Events)
	if err != nil {
		return false, Evidence{}, err
	}

	var (
		inside bool
		ev     Evidence
	)
	ev.RangeType = r.Type

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

	if inside {
		ev.Reason = describe(v, ev)
	}
	return inside, ev, nil
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
// sentinel first.
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
	sort.SliceStable(out, func(i, j int) bool {
		vi, vj := eventVersion(out[i]), eventVersion(out[j])
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
		// Cannot fail: every non-empty, non-sentinel bound was validated above.
		cmp, _ := c.Compare(vi, vj)
		return cmp < 0
	})
	return out, nil
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
