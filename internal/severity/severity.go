// Package severity turns a stored CVSS vector into a band a verdict can be
// built on. Bands are derived at query time from the vector (D13) rather than
// read from a value baked in at database build time, so a scoring correction
// ships as a code change instead of a rebuild.
package severity

import (
	"fmt"
	"strings"
)

// Band is a severity class. The ordering is None < Low < Medium < High <
// Critical, with Unknown deliberately outside it (D17).
//
// Unknown is declared LAST, above Critical, and that is not cosmetic. If it
// were zero-valued and sorted below None, every accidental bare `>=`
// comparison would quietly agree with AtOrAbove's explicit guard, so deleting
// the guard would leave the suite green — the guard would be decorative.
// Placed above Critical, a bare comparison disagrees loudly: dropping the
// guard makes Unknown clear every threshold and the test goes red.
//
// It also picks the safer direction for any comparison that escapes this
// package. An unrated finding treated as the worst is a false positive
// somebody notices; treated as the least, it is a false negative nobody does.
type Band int

const (
	None Band = iota
	Low
	Medium
	High
	Critical
	Unknown
)

func (b Band) String() string {
	switch b {
	case None:
		return "none"
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	case Unknown:
		return "unknown"
	}
	// Not reachable through ParseBand or Of, but a band rendered as "" reads
	// in a table as "not rated", which is a real and different state.
	return fmt.Sprintf("Band(%d)", int(b))
}

// AtOrAbove reports whether b meets a --fail-on threshold.
//
// Unknown never does, against any threshold including None. Half of all
// advisories carry no severity (D17); if `--fail-on none` swept them in, the
// flag would fire on nearly every scan and be switched off, which is how a
// gate stops gating. `--fail-on-unknown` is the flag for that intent, and it
// is separate so that asking for it has to be deliberate.
func (b Band) AtOrAbove(threshold Band) bool {
	if b == Unknown || threshold == Unknown {
		return false
	}
	return b >= threshold
}

// bandOf maps a base score to its band using the CVSS v3.1/v4.0 qualitative
// ratings, which are the same in both versions.
//
// The boundaries are inclusive at the bottom: 7.0 is High, not Medium. Scores
// arrive already rounded up to one decimal by the scorers, so they land
// exactly on these values often rather than rarely.
func bandOf(score float64) Band {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score >= 0.1:
		return Low
	default:
		return None
	}
}

// bandNames is the accepted spelling of each threshold, in ascending order so
// the error message reads as the scale it is.
var bandNames = []struct {
	name string
	band Band
}{
	{"none", None},
	{"low", Low},
	{"medium", Medium},
	{"high", High},
	{"critical", Critical},
}

// ParseBand resolves a --fail-on argument.
//
// "unknown" is rejected on purpose: accepting it would give one flag two
// meanings, since Unknown is not in the ordering and could not act as a
// threshold. Case is folded because which case a band name takes is not
// something a user should have to get right; surrounding whitespace is not,
// because a shell that produced it did something the user did not intend.
func ParseBand(s string) (Band, error) {
	lower := strings.ToLower(s)
	for _, b := range bandNames {
		if lower == b.name {
			return b.band, nil
		}
	}
	names := make([]string, 0, len(bandNames))
	for _, b := range bandNames {
		names = append(names, b.name)
	}
	// The accepted set is spelled out rather than described. grype calls the
	// bottom band `negligible` (D18), so someone arriving from it types a
	// name that does not exist here and needs to be shown the one that does.
	return Unknown, fmt.Errorf("invalid severity band %q: want one of %s",
		s, strings.Join(names, ", "))
}
