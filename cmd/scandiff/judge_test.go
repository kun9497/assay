package main

import "testing"

func TestJudge_AllFloorsHeldExactlyAtBoundary(t *testing.T) {
	// Boundary values themselves must hold, not just values comfortably
	// inside them: minAgree/minFindings are >=, maxFindings/maxNotEvaluated
	// are <=.
	target := Target{Name: "boundary", MinAgree: 3, MinFindings: 3, MaxFindings: 3, MaxNotEvaluated: 3}
	if breaches := judge(target, 3, 3, 3); len(breaches) != 0 {
		t.Errorf("judge at exact boundaries = %v, want no breaches", breaches)
	}
}

func TestJudge_OneUnderEachFloorBreachesOnlyThatFloor(t *testing.T) {
	target := Target{Name: "t", MinAgree: 5, MinFindings: 5, MaxFindings: 5, MaxNotEvaluated: 5}

	if b := judge(target, 4, 5, 5); len(b) != 1 || b[0].Floor != "minAgree" {
		t.Errorf("agree=4: judge = %v, want exactly one minAgree breach", b)
	}
	if b := judge(target, 5, 4, 5); len(b) != 1 || b[0].Floor != "minFindings" {
		t.Errorf("findings=4: judge = %v, want exactly one minFindings breach", b)
	}
	if b := judge(target, 5, 6, 5); len(b) != 1 || b[0].Floor != "maxFindings" {
		t.Errorf("findings=6: judge = %v, want exactly one maxFindings breach", b)
	}
	if b := judge(target, 5, 5, 6); len(b) != 1 || b[0].Floor != "maxNotEvaluated" {
		t.Errorf("notEvaluated=6: judge = %v, want exactly one maxNotEvaluated breach", b)
	}
}

func TestJudge_MultipleFloorsCanBreachTogether(t *testing.T) {
	target := Target{Name: "multi", MinAgree: 10, MinFindings: 10, MaxFindings: 20, MaxNotEvaluated: 0}
	breaches := judge(target, 0, 0, 5)
	if len(breaches) != 3 {
		t.Fatalf("judge = %v, want 3 simultaneous breaches (minAgree, minFindings, maxNotEvaluated)", breaches)
	}
}

func TestBreach_StringNamesTargetFloorWantGot(t *testing.T) {
	b := breach{Target: "alpine319", Floor: "minAgree", Want: ">=42", Got: 10}
	got := b.String()
	want := "breach: target=alpine319 floor=minAgree want=>=42 got=10"
	if got != want {
		t.Errorf("breach.String() = %q, want %q", got, want)
	}
}

// --- D105: judgeTrivy --------------------------------------------------

func TestJudgeTrivy_NilBlockNeverBreaches(t *testing.T) {
	target := Target{Name: "no-trivy"} // Trivy is nil: no block at all
	if b := judgeTrivy(target, 0, 0); len(b) != 0 {
		t.Errorf("judgeTrivy with nil Trivy = %v, want no breaches (nil-safe)", b)
	}
}

func TestJudgeTrivy_InformationalBlockNeverBreachesRegardlessOfMeasurement(t *testing.T) {
	target := Target{Name: "info", Trivy: &TrivyFloors{}} // every floor zero
	// Even numbers that would trip a real floor of the same shape must not
	// breach an all-zero (informational) block.
	if b := judgeTrivy(target, 0, 999); len(b) != 0 {
		t.Errorf("judgeTrivy on an informational block = %v, want no breaches", b)
	}
}

func TestJudgeTrivy_AllFloorsHeldExactlyAtBoundary(t *testing.T) {
	target := Target{Name: "boundary", Trivy: &TrivyFloors{MinAgree: 3, MinFindings: 3, MaxFindings: 3}}
	if b := judgeTrivy(target, 3, 3); len(b) != 0 {
		t.Errorf("judgeTrivy at exact boundaries = %v, want no breaches", b)
	}
}

func TestJudgeTrivy_OneUnderEachFloorBreachesOnlyThatFloor(t *testing.T) {
	target := Target{Name: "t", Trivy: &TrivyFloors{MinAgree: 5, MinFindings: 5, MaxFindings: 5}}

	if b := judgeTrivy(target, 4, 5); len(b) != 1 || b[0].Floor != "trivy.minAgree" {
		t.Errorf("agree=4: judgeTrivy = %v, want exactly one trivy.minAgree breach", b)
	}
	if b := judgeTrivy(target, 5, 4); len(b) != 1 || b[0].Floor != "trivy.minFindings" {
		t.Errorf("findings=4: judgeTrivy = %v, want exactly one trivy.minFindings breach", b)
	}
	if b := judgeTrivy(target, 5, 6); len(b) != 1 || b[0].Floor != "trivy.maxFindings" {
		t.Errorf("findings=6: judgeTrivy = %v, want exactly one trivy.maxFindings breach", b)
	}
}

func TestJudgeTrivy_MultipleFloorsCanBreachTogether(t *testing.T) {
	target := Target{Name: "multi", Trivy: &TrivyFloors{MinAgree: 10, MinFindings: 10, MaxFindings: 20}}
	breaches := judgeTrivy(target, 0, 0)
	if len(breaches) != 2 {
		t.Fatalf("judgeTrivy = %v, want 2 simultaneous breaches (trivy.minAgree, trivy.minFindings)", breaches)
	}
}

func TestJudgeTrivy_BreachMessageNamesTargetAndFloor(t *testing.T) {
	target := Target{Name: "named-target", Trivy: &TrivyFloors{MinAgree: 5}}
	breaches := judgeTrivy(target, 2, 0)
	if len(breaches) != 1 {
		t.Fatalf("judgeTrivy = %v, want exactly 1 breach", breaches)
	}
	want := "breach: target=named-target floor=trivy.minAgree want=>=5 got=2"
	if got := breaches[0].String(); got != want {
		t.Errorf("breach.String() = %q, want %q", got, want)
	}
}

func TestTrivyFloors_IsZero(t *testing.T) {
	cases := []struct {
		name string
		f    TrivyFloors
		want bool
	}{
		{"all zero", TrivyFloors{}, true},
		{"minAgree set", TrivyFloors{MinAgree: 1}, false},
		{"minFindings set", TrivyFloors{MinFindings: 1}, false},
		{"maxFindings set", TrivyFloors{MaxFindings: 1}, false},
		{"all set", TrivyFloors{MinAgree: 1, MinFindings: 1, MaxFindings: 5}, false},
	}
	for _, c := range cases {
		if got := c.f.isZero(); got != c.want {
			t.Errorf("%s: isZero() = %v, want %v", c.name, got, c.want)
		}
	}
}
