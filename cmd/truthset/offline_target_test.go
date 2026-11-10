package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// PR #268 review: -offline picked a capture by case name alone. A clean
// label at 1.36.1-r20, which a live scan judges FP, judged TN against the
// same case's capture of 1.36.1-r21. A capture is now held to the SBOM the
// label generates (its provenance target sha256, D120); one that scanned
// something else, or records no target, leaves the label UNEVALUATED -- out
// of TN and the metrics, exit 1. The capture of the label's own SBOM is
// judged as before.
func TestRun_OfflineCaptureMustBeTheCasesOwnScan(t *testing.T) {
	v1 := []Label{label("swap", "alpine", busyboxPURL, "busybox", "1.36.1-r20", "CVE-2024-58251", "clean", "")}
	v2 := []Label{label("swap", "alpine", busyboxFixedPURL, "busybox", "1.36.1-r21", "CVE-2024-58251", "clean", "")}
	exec, _ := fakeAssay(t, heldScans())

	// Live: v1 is a false positive, v2 is clean.
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, v1), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitFindings || !strings.Contains(out.String(), "FP") {
		t.Fatalf("live v1: exit %d, want 1 with an FP\n%s", code, out.String())
	}
	keep := filepath.Join(t.TempDir(), "keep")
	out.Reset()
	if code := run([]string{"-labels", writeLabels(t, v2), "-assay", "fake-assay", "-keep", keep}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("live v2 -keep: exit %d\n%s", code, out.String())
	}

	for _, tc := range []struct {
		name   string
		labels []Label
		edit   func(string) string
		code   int
		want   string
	}{
		{"the case's own capture is judged", v2, nil, exitOK, "TN"},
		{"another version's capture is not", v1, nil, exitFindings, "UNEVALUATED swap/CVE-2024-58251 -- the capture scanned a different target"},
		{"a capture with no target digest is not", v2, func(s string) string { return strings.Replace(s, `"target":`, `"targetGone":`, 1) }, exitFindings, "the capture records no target digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, f := range []string{"swap.scan.json", "swap.exit"} {
				b, err := os.ReadFile(filepath.Join(keep, f))
				if err != nil {
					t.Fatal(err)
				}
				if tc.edit != nil && strings.HasSuffix(f, ".json") {
					b = []byte(tc.edit(string(b)))
				}
				if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var out, errOut bytes.Buffer
			code := run([]string{"-labels", writeLabels(t, tc.labels), "-offline", dir}, &out, &errOut, nil)
			if code != tc.code || !strings.Contains(out.String(), tc.want) {
				t.Errorf("exit %d, want %d; stdout lacks %q:\n%s\n%s", code, tc.code, tc.want, out.String(), errOut.String())
			}
			if tc.code != exitOK && strings.Contains(out.String(), "alpine  1       0   1") {
				t.Errorf("an unproven capture was counted TN:\n%s", out.String())
			}
		})
	}
}
