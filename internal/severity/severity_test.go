package severity

import (
	"strings"
	"testing"
)

// The bands and their CVSS boundaries. An off-by-one here moves findings
// between bands, which moves builds between passing and failing.
func TestBandOrdering(t *testing.T) {
	for _, tt := range []struct {
		score float64
		want  Band
	}{
		{0.0, None},
		{0.1, Low}, {3.9, Low},
		{4.0, Medium}, {6.9, Medium},
		{7.0, High}, {8.9, High},
		{9.0, Critical}, {10.0, Critical},
	} {
		if got := bandOf(tt.score); got != tt.want {
			t.Errorf("bandOf(%.1f) = %v, want %v", tt.score, got, tt.want)
		}
	}
}

// D17: unknown is outside the ordering, not at the bottom of it.
//
// If it sorted below None, `--fail-on none` would sweep in every unrated
// finding — the coercion D17 forbids, arrived at from the other side.
func TestUnknownIsOutsideTheOrdering(t *testing.T) {
	for _, threshold := range []Band{None, Low, Medium, High, Critical} {
		if Unknown.AtOrAbove(threshold) {
			t.Errorf("Unknown.AtOrAbove(%v) = true; unknown never trips --fail-on", threshold)
		}
	}
	// ...and a threshold of Unknown is not a thing a user can ask for.
	if _, err := ParseBand("unknown"); err == nil {
		t.Error(`ParseBand("unknown") succeeded; --fail-on-unknown is the flag for that`)
	}
}

// The rest of the ordering still has to work, or the test above passes on a
// type where nothing is ever at or above anything.
func TestAtOrAbove(t *testing.T) {
	for _, tt := range []struct {
		b, threshold Band
		want         bool
	}{
		{None, None, true},
		{None, Low, false},
		{Critical, None, true},
		{Critical, Critical, true},
		{High, Critical, false},
		{Medium, Low, true},
		// A threshold of Unknown is unreachable through ParseBand, but a
		// zero-value Band must not become a threshold that everything clears.
		{Critical, Unknown, false},
	} {
		if got := tt.b.AtOrAbove(tt.threshold); got != tt.want {
			t.Errorf("%v.AtOrAbove(%v) = %v, want %v", tt.b, tt.threshold, got, tt.want)
		}
	}
}

func TestParseBand(t *testing.T) {
	for in, want := range map[string]Band{
		"none": None, "low": Low, "medium": Medium,
		"high": High, "critical": Critical,
		"HIGH": High, // case is not what a user should have to get right
	} {
		got, err := ParseBand(in)
		if err != nil {
			t.Errorf("ParseBand(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseBand(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"", "negligible", "moderate", "HIGH ", "9.0"} {
		if got, err := ParseBand(bad); err == nil {
			t.Errorf("ParseBand(%q) = %v, want an error", bad, got)
		}
	}
	// The error has to name what IS accepted. Someone arriving from grype
	// types `negligible` (D18: the names diverge here) and needs to be told
	// the name is `none`, not merely that theirs was wrong.
	_, err := ParseBand("negligible")
	if err == nil {
		t.Fatal("ParseBand(negligible) succeeded")
	}
	// Read only the list of accepted names, not the whole message: the
	// rejected input is echoed back in the same string, so asserting over
	// the message as a whole would pass on the wrong column.
	_, accepted, ok := strings.Cut(err.Error(), "want one of ")
	if !ok {
		t.Fatalf("ParseBand error %q does not list what it accepts", err)
	}
	for _, want := range []string{"none", "low", "medium", "high", "critical"} {
		if !strings.Contains(accepted, want) {
			t.Errorf("accepted bands %q does not name %q", accepted, want)
		}
	}
	// And the list must not advertise the one band ParseBand rejects.
	if strings.Contains(accepted, "unknown") {
		t.Errorf("accepted bands %q offers `unknown`, which ParseBand rejects", accepted)
	}
}

// Bands are printed in the table and in JSON, so their names are contract.
func TestBandString(t *testing.T) {
	for b, want := range map[Band]string{
		Unknown: "unknown", None: "none", Low: "low",
		Medium: "medium", High: "high", Critical: "critical",
	} {
		if got := b.String(); got != want {
			t.Errorf("Band(%d).String() = %q, want %q", int(b), got, want)
		}
	}
	// A band from outside the set must be visibly wrong rather than blank:
	// an empty severity column reads as "not rated", which is a real state.
	if got := Band(99).String(); !strings.Contains(got, "99") {
		t.Errorf("Band(99).String() = %q, want something naming the value", got)
	}
}
