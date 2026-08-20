package severity

import (
	"errors"
	"testing"
)

// TestOf_VendorWord pins the RHSA word->band mapping D72 added to Of's
// default branch, directly at the unit the matcher-level caller test
// (matcher.TestMatch_AlmaVendorWordSeverityIsDerivedAndGates) already drove
// through Match first. Both the band and the representative score are
// checked: the score matters because severity.Highest picks the winner
// across a mix of CVSS-derived and word-derived entries by comparing scores,
// so a word that did not land on bandOf's own boundary would silently
// mis-rank against a real CVSS vector landing just inside the same band.
func TestOf_VendorWord(t *testing.T) {
	for _, tt := range []struct {
		word  string
		band  Band
		score float64
	}{
		{"Critical", Critical, 9.0},
		{"Important", High, 7.0},
		{"Moderate", Medium, 4.0},
		{"Low", Low, 0.1},
	} {
		b, score, err := Of(tt.word)
		if err != nil {
			t.Errorf("Of(%q): %v", tt.word, err)
			continue
		}
		if b != tt.band {
			t.Errorf("Of(%q) band = %v, want %v", tt.word, b, tt.band)
		}
		if score != tt.score {
			t.Errorf("Of(%q) score = %v, want %v", tt.word, score, tt.score)
		}
		// The representative score must land exactly on bandOf's own
		// boundary for that band, or a word-derived rating would compare
		// unequal to a CVSS vector that scores the same nominal severity.
		if bandOf(score) != tt.band {
			t.Errorf("bandOf(Of(%q)'s score %v) = %v, want %v -- the vendor-word "+
				"score must agree with bandOf, not just assert its own band",
				tt.word, score, bandOf(score), tt.band)
		}
	}
}

// TestOf_UnrecognizedVendorWordIsUnscorable is the other half: a word that is
// not one of the four RHSA severities must not be guessed at (D17). Case
// matters too -- "critical" (lowercase) is deliberately NOT recognized here,
// unlike ParseBand's case-folding for --fail-on values: this is a value
// osv.Convert extracts verbatim from a vendor's own summary text, not
// something a user typed, and the RHSA convention capitalizes it
// consistently, so silently folding case would risk matching a coincidental
// lowercase word in an unrelated sentence fragment.
func TestOf_UnrecognizedVendorWordIsUnscorable(t *testing.T) {
	for _, word := range []string{"Sev4", "critical", "IMPORTANT", "Info", ""} {
		b, score, err := Of(word)
		if err == nil {
			t.Errorf("Of(%q) returned no error, want ErrUnscorable", word)
		}
		if !errors.Is(err, ErrUnscorable) {
			t.Errorf("Of(%q) err = %v, want one wrapping ErrUnscorable", word, err)
		}
		if b != Unknown || score != 0 {
			t.Errorf("Of(%q) = %v/%v, want unknown/0", word, b, score)
		}
	}
}

// TestHighest_MixesVendorWordsAndCVSSVectors proves severity.Highest -- the
// function the matcher actually calls -- picks correctly across a mix of the
// two kinds of value D72 lets one advisory carry in principle (a distro
// record with both an NVD-joined CVSS rating and its own vendor word,
// D71 decision 2's "both, not either"). A vendor word must be able to win
// against a lower-scoring CVSS vector, and lose against a higher-scoring one.
func TestHighest_MixesVendorWordsAndCVSSVectors(t *testing.T) {
	// "Important" (7.0) beats a CVSS vector that scores lower.
	if b, score := Highest([]string{
		"Important",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", // 6.5, medium
	}); b != High || score != 7.0 {
		t.Errorf("Highest(Important, medium-CVSS) = %v/%v, want high/7.0", b, score)
	}
	// A real critical CVSS vector still beats "Important".
	if b, score := Highest([]string{
		"Important",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8, critical
	}); b != Critical || score != 9.8 {
		t.Errorf("Highest(Important, critical-CVSS) = %v/%v, want critical/9.8", b, score)
	}
}
