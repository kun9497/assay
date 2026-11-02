package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The seed shape check itself (QA 2026-11-02 #16, #17). inputs_in_run_test.go
// only says the input reaches the shell as data; this holds that
// db-publish.yml refuses, before anything is built, every seed that is not
// one of the two reference forms the D110 recovery can use -- in particular
// the bare `sha256:<hex>` the input's old description invited, which
// go-containerregistry reads as the Docker Hub tag
// index.docker.io/library/sha256:<hex>. The regular expression is read out
// of the workflow and run here (RE2 reads this ERE as grep -E does), so the
// rows judge the check as it is spelled, not a copy of it.
func TestDBPublish_QA1102_TheSeedInputIsShapeCheckedBeforeTheBuild(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "db-publish.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf ghWorkflow
	if err := yaml.Unmarshal(src, &wf); err != nil {
		t.Fatal(err)
	}
	steps := wf.Jobs["publish"].Steps
	check, build := -1, -1
	for i, s := range steps {
		if strings.Contains(s.Run, "db build --seed") {
			build = i
		}
		if _, ok := s.Env["SEED"]; ok && strings.Contains(s.Run, "grep -Eq") && check < 0 {
			check = i
		}
	}
	switch {
	case build < 0:
		t.Fatal("db-publish.yml: no step runs `db build --seed`")
	case check < 0:
		t.Fatal("db-publish.yml: no step maps SEED into env and judges it with grep -Eq")
	case check > build:
		t.Fatalf("db-publish.yml: the seed shape check (step %d) comes after the build (step %d)", check, build)
	}
	run := steps[check].Run
	if !strings.Contains(run, "exit 2") {
		t.Errorf("the shape check does not exit 2 on a refused seed:\n%s", run)
	}
	if !strings.Contains(run, "ghcr.io/kun9497/assay-db@sha256:<64 hex> or ghcr.io/kun9497/assay-db:<tag>") {
		t.Error("the refusal does not name the two forms a seed may take")
	}
	m := regexp.MustCompile(`grep -Eq '([^']+)'`).FindStringSubmatch(run)
	if m == nil {
		t.Fatalf("no grep -Eq '<pattern>' in the shape check:\n%s", run)
	}
	re, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("the shape check's pattern does not compile: %v", err)
	}
	// grep judges lines, so the step refuses a value holding a newline
	// before the pattern is consulted; the rows model that first.
	if !strings.Contains(run, "wc -l") {
		t.Error("the shape check does not refuse a seed holding a newline: grep -Eq judges lines, so the first line alone would pass it")
	}
	hex := strings.Repeat("a", 64)
	for _, c := range []struct {
		seed string
		ok   bool
	}{
		{"ghcr.io/kun9497/assay-db@sha256:" + hex, true},
		{"ghcr.io/kun9497/assay-db:v9", true},
		{"ghcr.io/kun9497/assay-db:sha256-" + hex + ".sig", true},
		{"sha256:" + hex, false}, // the #17 shape
		{"ghcr.io/kun9497/assay-db@sha256:" + hex[:63], false},
		{"ghcr.io/kun9497/assay-db@sha256:" + strings.ToUpper(hex), false},
		{"ghcr.io/kun9497/assay-db", false},
		{"ghcr.io/kun9497/assay-db:", false},
		{"ghcr.io/kun9497/assay-db:.v9", false},
		{"ghcr.io/kun9497/assay-db:v9 --force", false},
		{"ghcr.io/kun9497/assay-db:v9; rm -rf /", false},
		{"docker.io/kun9497/assay-db:v9", false},
		{"ghcr.io/kun9497/assay-db-evil:v9", false},
		{"ghcr.io/kun9497/assay-db@sha256:" + hex + "\nghcr.io/x:y", false},
	} {
		got := !strings.Contains(c.seed, "\n") && re.MatchString(c.seed)
		if got != c.ok {
			t.Errorf("seed %q: accepted=%v, want %v", c.seed, got, c.ok)
		}
	}
}
