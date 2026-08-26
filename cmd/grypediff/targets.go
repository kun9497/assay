package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Target is one row of the committed floors file
// (.github/grype-diff-targets.json). Floors, not snapshots (D93): a floor is
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
