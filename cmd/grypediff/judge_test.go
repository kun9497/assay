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
