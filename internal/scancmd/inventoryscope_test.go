package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// D141: an image scan says, on every run, that it did not read the
// application packages installed inside the image. Before this the gap
// (D70) reached only the JSON's inventoryScope field: the table said "No
// known vulnerabilities found" and SARIF said nothing, while measured
// Criticals sat in /usr/lib/node_modules and in a compiled Go binary.
const scopeLine = "note: an image scan reads OS packages"

func TestRun_D141_ImageScanDisclosesTheApplicationPackageGap(t *testing.T) {
	out, errOut, code := scanImage(t, testDB(t), alpine319Files(), Options{})
	if code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut)
	}
	if !strings.Contains(errOut, scopeLine) {
		t.Fatalf("stderr does not disclose the inventory scope:\n%s", errOut)
	}
	for _, want := range []string{"npm", "Python", "Java", "Go", "lockfile", "SBOM"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("the disclosure does not mention %q:\n%s", want, errOut)
		}
	}
	if strings.Contains(out, scopeLine) {
		t.Errorf("the disclosure reached stdout:\n%s", out)
	}
}

// GitHub code scanning displays results, not notifications, so the SARIF
// carries the disclosure as a note-level result under a declared rule, and
// as a notification beside it -- the frozen-data block's shape (D111).
func TestRun_D141_ImageScanSARIFCarriesTheScopeResult(t *testing.T) {
	out, errOut, code := scanImage(t, testDB(t), alpine319Files(), Options{Output: "sarif"})
	if code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
			Invocations []struct {
				Notes []struct {
					Message struct{ Text string } `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	r := doc.Runs[0]
	declared := false
	for _, rule := range r.Tool.Driver.Rules {
		declared = declared || rule.ID == "assay/inventory-scope"
	}
	if !declared {
		t.Error("rule assay/inventory-scope is not declared in driver.rules")
	}
	found := false
	for _, res := range r.Results {
		if res.RuleID == "assay/inventory-scope" {
			found = true
			if res.Level != "note" || !strings.Contains(res.Message.Text, "application packages") {
				t.Errorf("scope result = %+v, want a note naming application packages", res)
			}
		}
	}
	if !found {
		t.Error("no assay/inventory-scope result")
	}
	noted := false
	for _, n := range r.Invocations[0].Notes {
		noted = noted || strings.Contains(n.Message.Text, "application packages")
	}
	if !noted {
		t.Error("no inventory-scope notification")
	}
}

// Only an image has a scope to disclose: a directory, an SBOM or a binary
// IS the application inventory, and a note there would be a false claim.
func TestRun_D141_NoDisclosureOutsideAnImage(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "go.mod", "module example.com/d141\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n")
	for _, output := range []string{"", "sarif"} {
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), testDB(t), "dir:"+dir, Options{Output: output}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
		}
		if strings.Contains(errOut.String(), scopeLine) || strings.Contains(out.String(), "assay/inventory-scope") {
			t.Errorf("output %q: a directory scan disclosed an image scope\nstdout: %s\nstderr: %s", output, out.String(), errOut.String())
		}
	}
}
