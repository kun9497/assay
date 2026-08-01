// Package severity turns a stored CVSS vector into a band a verdict can be
// built on. Bands are derived at query time from the vector (D13) rather than
// read from a value baked in at database build time, so a scoring correction
// ships as a code change instead of a rebuild.
package severity

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnscorable marks a vector this package cannot turn into a score. It is a
// sentinel so a caller can tell "we could not rate this" from a real failure
// and count it, rather than treating an unrated finding as an absent one.
var ErrUnscorable = errors.New("unscorable severity vector")

// Of scores one CVSS vector and returns its band.
//
// It takes the vector and nothing else. The record's own declared type is not
// a parameter because it is not reliable: one advisory in the live database
// files a `CVSS:3.1/...` vector under `CVSS_V4`. Dispatching on the label
// would hand that vector to the wrong scorer, and there is no arrangement of
// the two scorers under which that produces an error rather than a plausible
// wrong number. The version inside the vector is the only trustworthy source,
// so it is the only one consulted.
//
// An unscorable vector is (Unknown, 0, error). It is never a band: guessing
// is the same failure as coercing absent severity to low (D17), and the
// caller needs to count it, which it cannot do if the guess looks like data.
func Of(vector string) (Band, float64, error) {
	var (
		score float64
		err   error
	)
	switch {
	case strings.HasPrefix(vector, "CVSS:3."):
		score, err = scoreV3(vector)
	case strings.HasPrefix(vector, "CVSS:4."):
		score, err = scoreV4(vector)
	default:
		return Unknown, 0, fmt.Errorf("%w: %q is not a version this scores", ErrUnscorable, vector)
	}
	if err != nil {
		return Unknown, 0, err
	}
	return bandOf(score), score, nil
}

// Highest returns the worst band across a record's vectors, and that band's
// score.
//
// A finding is as severe as its worst rating. Taking the first vector instead
// would make the band depend on the order OSV happens to serialize them in,
// which is not a property of the vulnerability.
//
// Vectors that cannot be scored are skipped rather than allowed to suppress
// their scorable siblings; only when nothing at all scores is the result
// Unknown. That is a different claim from None — "we could not tell" versus
// "rated zero" — and D17 turns on the difference.
func Highest(vectors []string) (Band, float64) {
	best, bestScore := Unknown, 0.0
	for _, v := range vectors {
		band, score, err := Of(v)
		if err != nil {
			continue
		}
		if best == Unknown || score > bestScore {
			best, bestScore = band, score
		}
	}
	return best, bestScore
}

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
