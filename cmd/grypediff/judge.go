package main

import "fmt"

// breach is one floor a target failed to hold. Kept as a struct rather than
// a preformatted string so a test can assert on the fields (target, floor,
// want, got) instead of parsing prose back out of a message -- the same
// reasoning D10's Evidence type gives for Finding.
type breach struct {
	Target string
	Floor  string
	Want   string
	Got    int
}

// String is the one stderr line a breach prints (D93's contract: "every
// breach prints one line to stderr naming target, floor, want, got").
func (b breach) String() string {
	return fmt.Sprintf("breach: target=%s floor=%s want=%s got=%d", b.Target, b.Floor, b.Want, b.Got)
}

// judge compares one target's measured numbers against its committed
// floors. It never looks at the previous run and never looks at any other
// target -- purely a function of (Target, measured numbers) so it is
// testable without a scan, a capture, or a file on disk.
func judge(t Target, agree, findings, notEvaluated int) []breach {
	var out []breach
	if agree < t.MinAgree {
		out = append(out, breach{t.Name, "minAgree", fmt.Sprintf(">=%d", t.MinAgree), agree})
	}
	if findings < t.MinFindings {
		out = append(out, breach{t.Name, "minFindings", fmt.Sprintf(">=%d", t.MinFindings), findings})
	}
	if findings > t.MaxFindings {
		out = append(out, breach{t.Name, "maxFindings", fmt.Sprintf("<=%d", t.MaxFindings), findings})
	}
	if notEvaluated > t.MaxNotEvaluated {
		out = append(out, breach{t.Name, "maxNotEvaluated", fmt.Sprintf("<=%d", t.MaxNotEvaluated), notEvaluated})
	}
	return out
}
