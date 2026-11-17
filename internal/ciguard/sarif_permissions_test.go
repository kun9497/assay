package ciguard

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

// A public-repository upload can succeed even when the token cannot read
// the workflow run in a private repository.
func TestCustomerGitHubScanHasPrivateSARIFPermissions(t *testing.T) {
	src, err := os.ReadFile(repoRoot + "/docs/ci/github-actions.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Permissions map[string]string
		Jobs        map[string]struct{ Permissions map[string]string }
	}
	if err := yaml.Unmarshal(src, &workflow); err != nil {
		t.Fatal(err)
	}
	scan, ok := workflow.Jobs["scan"]
	if !ok {
		t.Fatal("GitHub Actions example has no scan job")
	}
	permissions := workflow.Permissions
	if scan.Permissions != nil {
		permissions = scan.Permissions
	}
	for scope, want := range map[string]string{"actions": "read", "contents": "read", "security-events": "write"} {
		if got := permissions[scope]; got != want {
			t.Errorf("scan job permission %q = %q, want %q for private SARIF uploads", scope, got, want)
		}
	}
}
