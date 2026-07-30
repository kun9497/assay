package version

import (
	"fmt"

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
			continue // an unorderable entry in the list is not a reason to fail the whole check
		}
		if cmp == 0 {
			return true, Evidence{
				Reason: fmt.Sprintf("version %s is listed as affected", v),
			}, nil
		}
	}
	return false, Evidence{}, nil
}

// InRange walks an OSV range's events in order, tracking whether v is currently
// inside an open window. Events are half-open [introduced, fixed) with the
// exception of last_affected, which is inclusive.
func InRange(c Comparer, v string, r advisory.Range) (bool, Evidence, error) {
	// GIT ranges carry commit SHAs, not versions. Skipping is correct; parsing
	// would error on data that was never meant for a Comparer.
	if r.Type == advisory.RangeGit {
		return false, Evidence{}, nil
	}

	var (
		inside bool
		ev     Evidence
	)
	ev.RangeType = r.Type

	for _, e := range r.Events {
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
			} else if inside {
				ev.Fixed = e.Fixed
			}

		case e.LastAffected != "":
			cmp, err := c.Compare(v, e.LastAffected)
			if err != nil {
				return false, Evidence{}, fmt.Errorf("compare %q to last_affected %q: %w", v, e.LastAffected, err)
			}
			if inside && cmp > 0 {
				inside = false // inclusive upper bound: equal is still affected
			} else if inside {
				ev.LastAffected = e.LastAffected
			}
		}
	}

	if inside {
		ev.Reason = describe(v, ev)
	}
	return inside, ev, nil
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
