package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runOfflineMode is runOfflineGate for either mode: weekly (no flag) or the
// nightly publish gate (-regressions-only).
func runOfflineMode(t *testing.T, target Target, assayBytes []byte, regressionsOnly bool) (int, string) {
	t.Helper()
	targetsPath := writeTargetsFile(t, []Target{target})
	dir := t.TempDir()
	writeOffline(t, dir, map[string][]byte{
		target.Name + ".assay.json": assayBytes,
		target.Name + ".grype.json": grypeDoc(nil),
	})
	args := []string{"-targets", targetsPath, "-offline", dir}
	if regressionsOnly {
		args = append(args, "-regressions-only")
	}
	var stdout, stderr bytes.Buffer
	got := run(args, &stdout, &stderr, noExec(t))
	return got, stderr.String()
}

// QA 2026-11-10 ⑤ against the floors file CI reads: every target that names
// a minApplicationPackages floor holds it with the coverage its 2026-11-09
// weekly capture measured, and breaches it in BOTH modes once the npm and Go
// rows are gone -- the QA's "without-go-npm" variant, which the gate judged
// ok in both modes before D167. Only this floor's line is asserted: the
// synthetic document holds no findings, so the finding floors breach on
// their own, which is not what this test is about.
func TestCommittedTargets_ApplicationPackageFloors(t *testing.T) {
	measured := map[string][]assayCoverage{
		"ubi8n18":             {{Ecosystem: "npm", Packages: 236}, {Ecosystem: "Red Hat:8", Packages: 289}},
		"bci156":              {{Ecosystem: "Go", Packages: 1}, {Ecosystem: "SUSE:15.6", Packages: 120}},
		"archlinux":           {{Ecosystem: "Go", Packages: 3}, {Ecosystem: "Arch:rolling", Packages: 130}},
		"cleanstart-postgres": {{Ecosystem: "Go", Packages: 3}, {Ecosystem: "CleanStart", Packages: 40}},
	}
	targets, err := loadTargets("../../.github/scanner-diff-targets.json")
	if err != nil {
		t.Fatal(err)
	}
	floored := 0
	for _, tg := range targets {
		if len(tg.MinApplicationPackages) == 0 {
			continue
		}
		floored++
		cov, ok := measured[tg.Name]
		if !ok {
			t.Errorf("%s names a minApplicationPackages floor with no measurement in this test; add its capture's coverage", tg.Name)
			continue
		}
		tg.Trivy = nil
		var osOnly []assayCoverage
		for _, c := range cov {
			if c.Ecosystem != "npm" && c.Ecosystem != "Go" {
				osOnly = append(osOnly, c)
			}
		}
		for _, mode := range []bool{false, true} {
			original, _ := json.Marshal(assayDocument{SchemaVersion: 20, Coverage: cov})
			if _, stderr := runOfflineMode(t, tg, original, mode); strings.Contains(stderr, "floor=minApplicationPackages") {
				t.Errorf("%s (regressions-only=%v): the measured capture breaches its own floor:\n%s", tg.Name, mode, stderr)
			}
			removed, _ := json.Marshal(assayDocument{SchemaVersion: 20, Coverage: osOnly})
			got, stderr := runOfflineMode(t, tg, removed, mode)
			if got != exitFindings || !strings.Contains(stderr, "breach: target="+tg.Name+" floor=minApplicationPackages.") {
				t.Errorf("%s (regressions-only=%v): exit %d with every application package removed, want a minApplicationPackages breach:\n%s", tg.Name, mode, got, stderr)
			}
		}
	}
	if floored != len(measured) {
		t.Errorf("%d targets carry a minApplicationPackages floor, want %d (ubi8n18 npm, and the three Go targets)", floored, len(measured))
	}
}

// The floor reads the spelling assay writes (coverage[].ecosystem and
// .packages), sums one key's rows, and counts an absent key as 0; a target
// holding every finding floor still breaches on this one alone, and the
// floor's own value is the boundary.
func TestRun_ApplicationPackagesFromAssaySpelling(t *testing.T) {
	target := Target{Name: "app", Ref: "unused", MaxFindings: 50, MinApplicationPackages: map[string]int{"npm": 118, "Go": 1}}
	for _, tc := range []struct {
		name, coverage string
		want           []string
		code           int
	}{
		{"at the floor", `[{"ecosystem":"npm","packages":118},{"ecosystem":"Go","packages":1}]`, nil, exitOK},
		{"one under", `[{"ecosystem":"npm","packages":117},{"ecosystem":"Go","packages":1}]`, []string{"breach: target=app floor=minApplicationPackages.npm want=>=118 got=117"}, exitFindings},
		{"rows sum", `[{"ecosystem":"npm","packages":100},{"ecosystem":"npm","packages":18},{"ecosystem":"Go","packages":1}]`, nil, exitOK},
		{"absent keys are 0", `[{"ecosystem":"Red Hat:8","packages":289}]`, []string{
			"breach: target=app floor=minApplicationPackages.Go want=>=1 got=0",
			"breach: target=app floor=minApplicationPackages.npm want=>=118 got=0",
		}, exitFindings},
		{"no coverage at all", `null`, []string{"floor=minApplicationPackages.Go", "floor=minApplicationPackages.npm"}, exitFindings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := []byte(`{"schemaVersion":20,"findings":[],"summary":{},"coverage":` + tc.coverage + `}`)
			for _, mode := range []bool{false, true} {
				code, stderr := runOfflineMode(t, target, doc, mode)
				if code != tc.code {
					t.Errorf("regressions-only=%v: exit %d, want %d\n%s", mode, code, tc.code, stderr)
				}
				for _, w := range tc.want {
					if !strings.Contains(stderr, w) {
						t.Errorf("regressions-only=%v: stderr lacks %q:\n%s", mode, w, stderr)
					}
				}
				if len(tc.want) == 0 && strings.Contains(stderr, "minApplicationPackages") {
					t.Errorf("regressions-only=%v: unexpected floor line:\n%s", mode, stderr)
				}
			}
			// Sorted: Go's line before npm's on every run.
			if _, stderr := runOfflineMode(t, target, doc, false); len(tc.want) == 2 && strings.Index(stderr, tc.want[0]) > strings.Index(stderr, tc.want[1]) {
				t.Errorf("breach lines out of order:\n%s", stderr)
			}
		})
	}
}

func TestLoadTargets_ApplicationPackagesValidated(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"npm":118,"Go":1}`, ""},
		{`{"go":1}`, `minApplicationPackages key "go" is not an ecosystem an image scan probes`},
		{`{"PyPI":3}`, `key "PyPI" is not an ecosystem`},
		{`{"npm":0}`, "minApplicationPackages.npm must be at least 1 (got 0)"},
		{`{"Go":-1}`, "minApplicationPackages.Go must be at least 1 (got -1)"},
	} {
		path := filepath.Join(t.TempDir(), "targets.json")
		if err := os.WriteFile(path, []byte(`[{"name":"n","ref":"r","minApplicationPackages":`+tc.body+`}]`), 0o644); err != nil {
			t.Fatal(err)
		}
		targets, err := loadTargets(path)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.body, err)
		case tc.want == "" && (targets[0].MinApplicationPackages["npm"] != 118 || targets[0].MinApplicationPackages["Go"] != 1):
			t.Errorf("%s parsed as %v", tc.body, targets[0].MinApplicationPackages)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want %q", tc.body, err, tc.want)
		}
	}
}
