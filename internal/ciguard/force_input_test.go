package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// QA 2026-11-04 nightly follow-up: db-publish.yml passes `--force` to
// `db push` only when dispatched with its boolean `force` input. The 11-03
// and 11-04 nightlies were refused by D157 over a real upstream change
// (Canonical's resolute kernel SRU), and the workflow had no way to carry an
// operator's decision, so the override was added. What this test holds is
// that it stays an override: `--force` must appear in exactly one run block
// across the workflows, behind a test of the FORCE env that the Publish step
// maps from `inputs.force`, and the input must be a boolean defaulting to
// false. A hardcoded `--force`, a second site, or a string input whose
// default is anything but false fails here before it fails a nightly.

type ghForceWorkflow struct {
	On struct {
		Dispatch struct {
			Inputs map[string]struct {
				Type    string `yaml:"type"`
				Default any    `yaml:"default"`
			} `yaml:"inputs"`
		} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Jobs map[string]struct {
		Steps []ghStep `yaml:"steps"`
	} `yaml:"jobs"`
}

// forceFlag is the flag as a word: `--force` inside `db push ... $force` is
// the site, `force=""` and `$force` are not. It is matched against the
// script with its comment lines removed, because the Build step's comment
// says "never --force" and a comment is not a site.
var forceFlag = regexp.MustCompile(`(^|[^A-Za-z0-9_-])--force($|[^A-Za-z0-9_-])`)

func uncommented(run string) string {
	var keep []string
	for _, l := range strings.Split(run, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n")
}

func TestDBPublishForceIsADispatchInputOnly(t *testing.T) {
	dir := filepath.Join(repoRoot, ".github", "workflows")
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var sites []string
	var publish *ghStep
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf ghForceWorkflow
		if err := yaml.Unmarshal(src, &wf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for j, job := range wf.Jobs {
			for i := range job.Steps {
				s := &job.Steps[i]
				if !forceFlag.MatchString(uncommented(s.Run)) {
					continue
				}
				sites = append(sites, filepath.Base(f)+":"+j+":"+s.ID)
				if filepath.Base(f) == "db-publish.yml" && s.ID == "push" {
					publish = s
				}
			}
		}
		if filepath.Base(f) != "db-publish.yml" {
			continue
		}
		in, ok := wf.On.Dispatch.Inputs["force"]
		if !ok {
			t.Fatal("db-publish.yml: workflow_dispatch declares no `force` input")
		}
		if in.Type != "boolean" {
			t.Errorf("db-publish.yml: `force` input is type %q, want boolean", in.Type)
		}
		if d, _ := in.Default.(bool); d || in.Default == nil {
			t.Errorf("db-publish.yml: `force` input default is %v, want false", in.Default)
		}
	}
	if len(sites) != 1 || publish == nil {
		t.Fatalf("`--force` sites in workflow run blocks: %v, want exactly db-publish.yml:publish:push", sites)
	}
	if got := publish.Env["FORCE"]; got != "${{ inputs.force }}" {
		t.Errorf("db-publish.yml Publish step maps FORCE=%q, want ${{ inputs.force }}", got)
	}
	// The flag is set only inside the test of FORCE: the test comes first,
	// and the `db push` line carries the variable, never the literal.
	script := uncommented(publish.Run)
	guard := strings.Index(script, `[ "$FORCE" = "true" ]`)
	flag := forceFlag.FindStringIndex(script)
	if guard < 0 || flag == nil || guard > flag[0] {
		t.Errorf("db-publish.yml Publish step: `--force` (at %v) is not behind a `[ \"$FORCE\" = \"true\" ]` test (at %d)", flag, guard)
	}
	push := regexp.MustCompile(`(?m)^.*\./bin/assay db push.*$`).FindString(script)
	if push == "" || forceFlag.MatchString(push) || !strings.Contains(push, "$force") {
		t.Errorf("db-publish.yml Publish step: the db push line is %q, want it to carry $force and not the literal flag", push)
	}
}
