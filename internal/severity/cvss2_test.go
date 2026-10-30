package severity

import "testing"

// CVSS v2 base scores (D156), from the v2 specification's own worked
// examples and the vectors NVD most often publishes, each a value NVD shows
// for that vector. The bands are NVD's v2 table: Low 0.0-3.9, Medium 4.0-6.9,
// High 7.0-10.0; v2 has no Critical, and 0.0 is Low there, not None.
func TestScoreV2(t *testing.T) {
	for _, tc := range []struct {
		vector string
		score  float64
		band   Band
	}{
		{"AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8, High},   // CVE-2002-0392, the spec's example
		{"AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0, High},  // CVE-2003-0818
		{"AV:L/AC:H/Au:N/C:C/I:C/A:C", 6.2, Medium}, // CVE-2003-0062
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, High},
		{"AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8, Medium},
		{"AV:N/AC:M/Au:N/C:C/I:C/A:C", 9.3, High},
		{"AV:N/AC:H/Au:N/C:P/I:P/A:P", 5.1, Medium},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:P", 5.0, Medium},
		{"AV:N/AC:L/Au:S/C:N/I:N/A:P", 4.0, Medium},
		{"AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3, Medium},
		{"AV:N/AC:M/Au:S/C:N/I:P/A:N", 3.5, Low},
		{"AV:L/AC:L/Au:N/C:C/I:C/A:C", 7.2, High},
		{"AV:L/AC:L/Au:N/C:P/I:N/A:N", 2.1, Low},
		{"AV:L/AC:M/Au:N/C:N/I:N/A:P", 1.9, Low},
		{"AV:N/AC:L/Au:N/C:N/I:N/A:N", 0.0, Low},
	} {
		score, band, ok := scoreV2(tc.vector)
		if !ok || score != tc.score || band != tc.band {
			t.Errorf("scoreV2(%q) = %.1f %v %v, want %.1f %v", tc.vector, score, band, ok, tc.score, tc.band)
		}
	}
	for _, bad := range []string{
		"",
		"AV:N/AC:L/Au:N/C:P/I:P",              // a metric missing
		"AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F",      // temporal metrics: not the base vector NVD stores
		"AV:X/AC:L/Au:N/C:P/I:P/A:P",          // an undefined value
		"av:n/ac:l/au:n/c:p/i:p/a:p",          // the spec's letters are upper-case
		"AC:L/AV:N/Au:N/C:P/I:P/A:P",          // out of order
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", // a prefix no source writes
		"(AV:N/AC:L/Au:N/C:P/I:P/A:P)",
	} {
		if s, b, ok := scoreV2(bad); ok {
			t.Errorf("scoreV2(%q) = %.1f %v, want refused", bad, s, b)
		}
	}
}

// v2 is a fallback, never a peer (D156): it bands a record only when nothing
// else in it scores, and Of itself still refuses a v2 vector so no caller can
// put it in a max beside v3 by accident.
func TestHighestFallsBackToV2(t *testing.T) {
	const v2High = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
	const v3Low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
	for _, tc := range []struct {
		name    string
		vectors []string
		band    Band
		fromV2  bool
	}{
		{"v2 alone", []string{v2High}, High, true},
		{"v3 beats a higher v2", []string{v2High, v3Low}, Low, false},
		{"v3 first beats a higher v2", []string{v3Low, v2High}, Low, false},
		{"a vendor word beats v2", []string{v2High, "Moderate"}, Medium, false},
		{"an unscorable vector does not block v2", []string{"garbage", v2High}, High, true},
		{"the higher of two v2 vectors", []string{"AV:L/AC:L/Au:N/C:P/I:N/A:N", v2High}, High, true},
		{"nothing", nil, Unknown, false},
	} {
		band, _, fromV2 := HighestDetail(tc.vectors)
		if band != tc.band || fromV2 != tc.fromV2 {
			t.Errorf("%s: HighestDetail = %v fromV2=%v, want %v fromV2=%v", tc.name, band, fromV2, tc.band, tc.fromV2)
		}
		if b, _ := Highest(tc.vectors); b != tc.band {
			t.Errorf("%s: Highest = %v, want %v (the same answer as HighestDetail)", tc.name, b, tc.band)
		}
	}
	if _, _, err := Of(v2High); err == nil {
		t.Error("Of(v2) scored; it must stay unscorable so v2 can only ever be a fallback")
	}
}
