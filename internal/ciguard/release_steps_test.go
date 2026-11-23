package ciguard

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// QA 2026-11-20. The steps a release rests on were held as substrings, so a
// trailing `|| true`, an `if: false`, or deleting one left this suite green.

// requiredStep is the job and position of the one required step whose run is
// exactly command, or an error.
func requiredStep(src, command string) (job string, at int, err error) {
	var wf gateWorkflow
	if err := yaml.Unmarshal([]byte(src), &wf); err != nil {
		return "", 0, err
	}
	for id, j := range wf.Jobs {
		if j.If != "" || (j.ContinueOnError != "" && j.ContinueOnError != "false") {
			continue
		}
		for n, s := range j.Steps {
			if s.required() && strings.TrimSpace(s.Run) == command {
				return id, n, nil
			}
		}
	}
	return "", 0, fmt.Errorf("no unconditional, failure-propagating step runs exactly %q", command)
}

func TestRelease_CriticalStepsAreExactAndRequired(t *testing.T) {
	release := readRepoFile(t, ".github/workflows/release.yml")
	var wf gateWorkflow
	if err := yaml.Unmarshal([]byte(release), &wf); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"sh scripts/check-go-toolchain.sh", `sh scripts/prepare-release.sh --check "$GITHUB_REF_NAME"`} {
		job, at, err := requiredStep(release, command)
		if err != nil {
			t.Errorf("release.yml: %v", err)
			continue
		}
		published := -1
		for n, s := range wf.Jobs[job].Steps {
			if strings.HasPrefix(s.Uses, "goreleaser/goreleaser-action@") {
				published = n
			}
		}
		if published < at {
			t.Errorf("release.yml: %q is not before GoReleaser in its job", command)
		}
	}
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	for _, command := range []string{
		"sh scripts/check-go-toolchain.sh", "python3 scripts/test-release-ci.py", "sudo sh scripts/install_test.sh",
		"sh scripts/ops_alert_test.sh", "go vet ./...", "go test -race ./...", "go build ./...",
	} {
		if _, _, err := requiredStep(ci, command); err != nil {
			t.Errorf("ci.yml: %v", err)
		}
	}
}

func TestRelease_ChecksumsAreSigned(t *testing.T) {
	var config struct {
		Signs []struct {
			Cmd       string   `yaml:"cmd"`
			Artifacts string   `yaml:"artifacts"`
			Signature string   `yaml:"signature"`
			Args      []string `yaml:"args"`
		} `yaml:"signs"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".goreleaser.yaml")), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Signs) != 1 {
		t.Fatalf("%d signs entries, want the checksums one", len(config.Signs))
	}
	s := config.Signs[0]
	if s.Cmd != "cosign" || s.Artifacts != "checksum" || s.Signature != "${artifact}.sig" ||
		!strings.Contains(" "+strings.Join(s.Args, " ")+" ", " sign-blob --key env://COSIGN_PRIVATE_KEY ") {
		t.Errorf("signs = %+v, want cosign sign-blob over the checksums file with the project key", s)
	}
}
