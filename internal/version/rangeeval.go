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
// the enumerated Versions list when a carries no usable ranges.
func AffectsVersion(c Comparer, v string, a advisory.Affected) (bool, Evidence, error) {
	for _, r := range a.Ranges {
		hit, ev, err := InRange(c, v, r)
		if err != nil {
			return false, Evidence{}, err
		}
		if hit {
			return true, ev, nil
		}
	}
	// Versions is redundant with Ranges when both are present, but it is the
	// only data when Ranges is absent, so it cannot be dropped.
	for _, known := range a.Versions {
		cmp, err := c.Compare(v, known)
		if err != nil {
			// Surface it. The left operand is the installed version and is
			// identical on every iteration, so an unparseable one fails every
			// entry — skipping would turn a 100% failure rate into a silent
			// clean verdict, which is the exact false negative this package
			// exists to prevent.
			return false, Evidence{}, fmt.Errorf("compare %q to listed version %q: %w", v, known, err)
		}
		if cmp == 0 {
			return true, Evidence{
				Reason: fmt.Sprintf("version %s is listed as affected", v),
			}, nil
		}
	}
	return false, Evidence{}, nil
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
				return false, Evidence{}, fmt.Errorf("compare %q to fixed %q: %w", v, e.Fixed, err)
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
				return false, Evidence{}, fmt.Errorf("compare %q to last_affected %q: %w", v, e.LastAffected, err)
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
			return nil, fmt.Errorf("range event bound %q: %w", ver, err)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		vi, vj := eventVersion(out[i]), eventVersion(out[j])
		// The sentinel is negative infinity, so it sorts before everything.
		if vi == introducedSentinel {
			return vj != introducedSentinel
		}
		if vj == introducedSentinel {
			return false
		}
		cmp, _ := c.Compare(vi, vj) // cannot fail: validated above
		return cmp < 0
	})
	return out, nil
}

// atLeast reports whether v >= bound, resolving the OSV sentinel first.
func atLeast(c Comparer, v, bound string) (bool, error) {
	if bound == introducedSentinel {
		return true, nil // negative infinity: everything is at or above it
	}
	cmp, err := c.Compare(v, bound)
	if err != nil {
		return false, fmt.Errorf("compare %q to introduced %q: %w", v, bound, err)
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
