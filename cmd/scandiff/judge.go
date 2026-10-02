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
	// Ceiling marks an upper bound on a finding count (maxFindings,
	// trivy.maxFindings) as opposed to a regression floor. judge sets it
	// rather than leaving the caller to recognise floor names, so the one
	// place that decides which floors a mode may skip (demoteCeilings) cannot
	// drift from the place that produces them.
	Ceiling bool
}

// String is the one stderr line a breach prints (D93's contract: "every
// breach prints one line to stderr naming target, floor, want, got").
func (b breach) String() string {
	return fmt.Sprintf("breach: target=%s floor=%s want=%s got=%d", b.Target, b.Floor, b.Want, b.Got)
}

// infoString is the stderr line for a ceiling that -regressions-only did not
// judge. It names the same target/want/got a breach would, so the Monday
// reviewer reading a nightly log sees the number the weekly run will judge,
// but it never says "breach:" -- a grep for breaches in the gate's log must
// find only what actually failed it.
func (b breach) infoString() string {
	return fmt.Sprintf("info: target=%s ceiling=%s want=%s got=%d (not judged: -regressions-only)", b.Target, b.Floor, b.Want, b.Got)
}

// demoteCeilings splits a target's breaches into those that are judged and
// those only reported as information. Without regressionsOnly every breach is
// judged -- the weekly differential's behaviour, unchanged.
//
// With it (D114's publish gate), ceilings and only ceilings are demoted. A
// floor on the low side (minAgree, minFindings, minComponents, a trivy
// minimum) or on not-evaluated growth trips when the CANDIDATE lost
// something, which is exactly what the gate exists to stop before a push. A
// ceiling trips when upstream published more than the floors file expected:
// every such breach so far (wolfi, photon5, 2026-09-28) was benign growth a
// human re-banded on Monday, and letting it block the nightly would stop the
// database updating until someone edited a JSON file -- a review signal
// turned into an outage. The weekly run still judges ceilings, so the FP
// explosion maxFindings guards against is still caught, a week later at
// most, by a human.
func demoteCeilings(bs []breach, regressionsOnly bool) (judged, info []breach) {
	if !regressionsOnly {
		return bs, nil
	}
	for _, b := range bs {
		if b.Ceiling {
			info = append(info, b)
		} else {
			judged = append(judged, b)
		}
	}
	return judged, info
}

// judge compares one target's measured numbers against its committed
// floors. It never looks at the previous run and never looks at any other
// target -- purely a function of (Target, measured numbers) so it is
// testable without a scan, a capture, or a file on disk.
//
// It reports every floor that tripped, ceilings included, whatever mode the
// tool runs in: which of them a mode judges is demoteCeilings' decision, so
// judge stays one pure function both the weekly run and the gate share.
func judge(t Target, agree, findings, notEvaluated, components int) []breach {
	var out []breach
	if components < t.MinComponents {
		out = append(out, breach{t.Name, "minComponents", fmt.Sprintf(">=%d", t.MinComponents), components, false})
	}
	if agree < t.MinAgree {
		out = append(out, breach{t.Name, "minAgree", fmt.Sprintf(">=%d", t.MinAgree), agree, false})
	}
	if findings < t.MinFindings {
		out = append(out, breach{t.Name, "minFindings", fmt.Sprintf(">=%d", t.MinFindings), findings, false})
	}
	if findings > t.MaxFindings {
		out = append(out, breach{t.Name, "maxFindings", fmt.Sprintf("<=%d", t.MaxFindings), findings, true})
	}
	if notEvaluated > t.MaxNotEvaluated {
		out = append(out, breach{t.Name, "maxNotEvaluated", fmt.Sprintf("<=%d", t.MaxNotEvaluated), notEvaluated, false})
	}
	return out
}

// judgeTrivy is judge's D105 counterpart for the optional trivy comparison.
// It is a separate function rather than a parameterized call into judge:
// there is no notEvaluated counterpart (trivy carries no such concept), and
// an all-zero TrivyFloors block is INFORMATIONAL rather than a committed
// floor -- see TrivyFloors.isZero -- which judge itself has no notion of. A
// nil t.Trivy (the block is absent from the file) and an informational
// block both produce no breaches; the caller is expected not to call this
// at all when t.Trivy is nil, since there is nothing to have measured, but
// it is nil-safe regardless so a caller cannot forget the check and panic.
//
// agree and findings are the caller's to compute (run.go: agree =
// |assay tuples ∩ trivy tuples|, findings = len(trivy tuples) -- see
// TrivyFloors' own doc comment for why findings is trivy's own count and
// not assay's).
func judgeTrivy(t Target, agree, findings int) []breach {
	if t.Trivy == nil || t.Trivy.isZero() {
		return nil
	}
	f := *t.Trivy
	var out []breach
	if agree < f.MinAgree {
		out = append(out, breach{t.Name, "trivy.minAgree", fmt.Sprintf(">=%d", f.MinAgree), agree, false})
	}
	if findings < f.MinFindings {
		out = append(out, breach{t.Name, "trivy.minFindings", fmt.Sprintf(">=%d", f.MinFindings), findings, false})
	}
	if findings > f.MaxFindings {
		out = append(out, breach{t.Name, "trivy.maxFindings", fmt.Sprintf("<=%d", f.MaxFindings), findings, true})
	}
	return out
}
