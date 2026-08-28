package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Target is one row of the committed floors file
// (.github/scanner-diff-targets.json). Floors, not snapshots (D93): a floor is
// a one-way ratchet against regression, so a database update that finds one
// MORE real vulnerability than last week does not itself fail the build the
// way an exact-match comparison would have.
type Target struct {
	Name string `json:"name"`
	// Tag is the human-readable form (e.g. "alpine:3.19"), carried alongside
	// Ref purely for a reader -- the tool itself never resolves or scans it.
	Tag string `json:"tag"`
	// Ref is what actually gets scanned, pinned by digest (image@sha256:...)
	// so a weekly run compares against the same bytes the floors were
	// measured against, and a moving tag cannot silently widen or narrow
	// what "this target" means out from under the floors file.
	Ref string `json:"ref"`
	// MinAgree is the floor on |assay tuples ∩ grype tuples|: the two tools
	// must still agree on at least this many (package, CVE) pairs. This is
	// the D90 guard -- that regression was findings still present but agree
	// collapsing toward the other tool, which minFindings alone would not
	// have caught (assay's own count could stay flat while it silently
	// stopped matching what grype also sees).
	MinAgree int `json:"minAgree"`
	// MinFindings floors assay's own tuple count, independent of agreement --
	// a source dropping out of the database can shrink this while agree
	// stays in range (the pairs that remain still agree).
	MinFindings int `json:"minFindings"`
	// MaxFindings catches the inverse failure: an FP explosion. A regression
	// that makes assay report everything as vulnerable would pass minAgree
	// and minFindings both.
	MaxFindings int `json:"maxFindings"`
	// MaxNotEvaluated floors assay's summary.notEvaluated count. Omitted
	// (zero value) means "must be exactly 0" for most targets; a nonzero
	// floor is set only where a target's current run genuinely reports
	// not-evaluated packages on purpose (e.g. Oracle's Ksplice/FIPS lineage
	// skip, D79) -- an exact number rather than a boolean "allowed" flag, so
	// growth past what was measured still trips (see Target's own doc
	// comment history: a boolean here would let the count grow without
	// limit once any not-evaluated packages were expected at all).
	MaxNotEvaluated int `json:"maxNotEvaluated,omitempty"`
	// MinComponents floors assay's summary.components -- how much of the
	// image the scan actually cataloged. It exists for targets whose
	// EXPECTED finding count is zero (cleanstart): there, minFindings 0 and
	// minAgree 0 enforce nothing, so a cataloger that silently saw an empty
	// inventory would still report "ok". Findings can honestly be zero;
	// an inventory of a real image cannot. Omitted means 0, which keeps
	// every pre-existing target's judgement byte-identical.
	MinComponents int `json:"minComponents,omitempty"`
	// Trivy is D105's second comparison, OPTIONAL per target: nil means the
	// key is absent from the file, and trivy is simply not run for this
	// target at all -- not run-and-ignored, not run-and-zero-floored. Trivy
	// does not cover every distro assay does (see scanner-diff-targets.json's
	// own comment for the list), so absence has to be distinguishable from a
	// committed all-zero floor, which is why this is a pointer and not a
	// plain TrivyFloors value.
	Trivy *TrivyFloors `json:"trivy,omitempty"`
}

// TrivyFloors is the trivy counterpart to Target's own MinAgree/MinFindings/
// MaxFindings, kept as a separate type (rather than three more fields
// directly on Target) so a target with no `"trivy"` key round-trips through
// Trivy == nil instead of a Target that merely happens to have every trivy
// floor at its zero value -- see Target.Trivy's own comment.
//
// MinAgree floors |assay tuples ∩ trivy tuples|, the same role grype's
// MinAgree plays in the primary comparison. MinFindings and MaxFindings,
// though, floor TRIVY's OWN tuple count, not assay's -- assay's own count is
// already floored by Target's MinFindings/MaxFindings regardless of which
// second scanner is configured, so re-checking it here a second time would
// only duplicate that guard with a second, independently-drifting number.
// Bounding trivy's own count instead catches trivy itself degrading: a
// stale or empty cached vulnerability DB reporting suspiciously few (or a
// broken one reporting suspiciously many) findings, the same failure mode
// the DB-dir cache in scanner-diff.yml exists to make LESS likely but not
// impossible.
//
// All three floors at zero (an EMPTY `"trivy": {}` block) is INFORMATIONAL,
// not a committed floor: measure and print the numbers, never breach. This
// is what lets a `workflow_dispatch` run seed real floors for a target
// before anyone commits them -- see judgeTrivy.
type TrivyFloors struct {
	MinAgree    int `json:"minAgree"`
	MinFindings int `json:"minFindings"`
	MaxFindings int `json:"maxFindings"`
}

// isZero reports whether every floor in f is at its zero value -- D105's
// definition of "informational" (see TrivyFloors' own doc comment). A block
// this evaluates true for never produces a breach, no matter what gets
// measured.
func (f TrivyFloors) isZero() bool {
	return f.MinAgree == 0 && f.MinFindings == 0 && f.MaxFindings == 0
}

// loadTargets reads and validates the floors file. Every failure here is
// reported with the path so a CI log names the file, not just "json: ...".
func loadTargets(path string) ([]Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file %s: %w", path, err)
	}
	var targets []Target
	if err := json.Unmarshal(data, &targets); err != nil {
		return nil, fmt.Errorf("parse targets file %s: %w", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("targets file %s: no targets", path)
	}
	seen := make(map[string]bool, len(targets))
	for i, t := range targets {
		if t.Name == "" {
			return nil, fmt.Errorf("targets file %s: entry %d has no name", path, i)
		}
		if seen[t.Name] {
			return nil, fmt.Errorf("targets file %s: duplicate target name %q", path, t.Name)
		}
		seen[t.Name] = true
		if t.Ref == "" {
			return nil, fmt.Errorf("targets file %s: target %q has no ref", path, t.Name)
		}
	}
	return targets, nil
}
