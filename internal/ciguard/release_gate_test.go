package ciguard

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type gateStep struct {
	Run             string `yaml:"run"`
	Uses            string `yaml:"uses"`
	If              string `yaml:"if"`
	ContinueOnError string `yaml:"continue-on-error"`
}

func (s gateStep) required() bool {
	return s.If == "" && (s.ContinueOnError == "" || s.ContinueOnError == "false")
}

type gateWorkflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions     map[string]string `yaml:"permissions"`
		Steps           []gateStep        `yaml:"steps"`
		If              string            `yaml:"if"`
		ContinueOnError string            `yaml:"continue-on-error"`
	} `yaml:"jobs"`
}

const releaseCICommand = `python3 scripts/check-release-ci.py "$(git rev-parse HEAD)"`

// Read YAML steps, not occurrences in comments or an unused job. The gate
// must run in the same job before each publisher, and its failure must stop
// publication. Keep it a dedicated command so `|| true` cannot disguise it.
func releaseGateProblems(src string) []string {
	var wf gateWorkflow
	if err := yaml.Unmarshal([]byte(src), &wf); err != nil {
		return []string{err.Error()}
	}
	var problems []string
	publishers := 0
	for id, job := range wf.Jobs {
		gate := false
		for _, step := range job.Steps {
			if step.required() && strings.TrimSpace(step.Run) == releaseCICommand {
				gate = true
			}
			if !strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@") {
				continue
			}
			publishers++
			if !gate || !step.required() {
				problems = append(problems, fmt.Sprintf("job %s: publisher must follow an unconditional, failure-propagating main CI gate", id))
			}
			permissions := wf.Permissions
			if job.Permissions != nil {
				permissions = job.Permissions
			}
			if permissions["actions"] != "read" {
				problems = append(problems, fmt.Sprintf("job %s: main CI gate requires actions: read", id))
			}
		}
	}
	if publishers == 0 {
		problems = append(problems, "release has no GoReleaser publisher to guard")
	}
	return problems
}

func TestReleaseMainCIGateIsWiredBeforePublishing(t *testing.T) {
	for _, p := range releaseGateProblems(readRepoFile(t, ".github/workflows/release.yml")) {
		t.Error(p)
	}
}

// The root invocation detects tar restoring the build runner's owner. A
// nonroot harness passes that regression because tar cannot restore owners.
func TestCIRunsReleaseGateTestsAndRootInstallerHarness(t *testing.T) {
	var wf gateWorkflow
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".github/workflows/ci.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"python3 scripts/test-release-ci.py", "sudo sh scripts/install_test.sh"} {
		found := false
		for _, job := range wf.Jobs {
			if job.If != "" || (job.ContinueOnError != "" && job.ContinueOnError != "false") {
				continue
			}
			for _, step := range job.Steps {
				if step.required() && strings.TrimSpace(step.Run) == command {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("CI does not require %q", command)
		}
	}
}

func TestReleaseGateGuardRejectsDisconnectedOrOptionalChecks(t *testing.T) {
	const before = "permissions:\n  actions: read\njobs:\n  release:\n    steps:\n"
	const gate = "      - run: " + releaseCICommand + "\n"
	const publish = "      - uses: goreleaser/goreleaser-action@commit\n"
	for _, tc := range []struct {
		name, src string
		bad       bool
	}{
		{"required before publication", before + gate + publish, false},
		{"missing", before + publish, true},
		{"comment only", before + "      # run: " + releaseCICommand + "\n" + publish, true},
		{"too late", before + publish + gate, true},
		{"conditional", before + gate + "        if: false\n" + publish, true},
		{"ignored error", before + gate + "        continue-on-error: true\n" + publish, true},
		{"shell ignores error", before + strings.TrimSuffix(gate, "\n") + " || true\n" + publish, true},
		{"publisher ignores failed gate", before + gate + publish + "        if: always()\n", true},
		{"different job", before + gate + "  other:\n    steps:\n" + publish, true},
		{"job removes permission", strings.Replace(before, "    steps:", "    permissions:\n      contents: write\n    steps:", 1) + gate + publish, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if problems := releaseGateProblems(tc.src); (len(problems) > 0) != tc.bad {
				t.Fatalf("problems = %v, want rejected=%v", problems, tc.bad)
			}
		})
	}
}
