package ciguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// QA 2026-11-20. Without always() the alert job is skipped exactly when the
// job it watches failed, and no failed nightly ever opens an issue.
func TestAlertJobsRunAlways(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	alerts := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf gateWorkflow
		if err := yaml.Unmarshal(b, &wf); err != nil {
			t.Fatal(err)
		}
		for id, j := range wf.Jobs {
			for _, s := range j.Steps {
				if !strings.Contains(s.Run, "scripts/ops-alert.sh") {
					continue
				}
				alerts++
				if strings.TrimSpace(j.If) != "always()" || !s.required() {
					t.Errorf("%s: job %s: if %q, step if %q; want always() and an unconditional step", filepath.Base(f), id, j.If, s.If)
				}
			}
		}
	}
	if alerts < 5 {
		t.Errorf("%d alert jobs found, want at least five", alerts)
	}
}
