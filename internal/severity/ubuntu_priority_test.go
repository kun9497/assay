package severity

import "testing"

// QA 2026-11-20. Canonical's word stands in for a vector, never beside one.
func TestHighest_UbuntuPriorityOnlyWhereNothingElseScores(t *testing.T) {
	const low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
	const v2 = "AV:L/AC:H/Au:M/C:P/I:N/A:N"
	for _, tc := range []struct {
		in   []string
		want Band
	}{
		{[]string{"critical"}, Critical},
		{[]string{"high"}, High},
		{[]string{"medium"}, Medium},
		{[]string{"low"}, Low},
		{[]string{"negligible"}, Low},
		{[]string{"untriaged"}, Unknown},
		{[]string{"low", "high"}, High},
		{[]string{"critical", low}, Low},
		{[]string{low, "critical"}, Low},
		{[]string{"critical", v2}, Low},
	} {
		if got, _ := Highest(tc.in); got != tc.want {
			t.Errorf("Highest(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
