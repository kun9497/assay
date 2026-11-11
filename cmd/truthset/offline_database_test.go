package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// QA 2026-11-11: two proven captures from two databases -- one scanned
// against a locally built database (no artifact digest), one against the
// published artifact -- are one run only if read in one order: the local
// one first set no digest, and the published one then set the run's, two
// TN and exit 0 attributed to the published database; the other order was
// exit 2. The run's database is now whatever the first trusted capture
// recorded, "" included, and a second that differs is an ERROR in either
// order. Two captures of one local database remain one run.
func TestRun_OfflineCapturesFromTwoDatabases_EitherOrder(t *testing.T) {
	exec, _ := fakeAssay(t, heldScans())
	// Two clean cases of the one fixed busybox, captured by a live run.
	labels := []Label{
		label("a-case", "alpine", busyboxFixedPURL, "busybox", "1.36.1-r21", "CVE-2024-58251", "clean", ""),
		label("b-case", "alpine", busyboxFixedPURL, "busybox", "1.36.1-r21", "CVE-2024-58251", "clean", ""),
	}
	keep := filepath.Join(t.TempDir(), "keep")
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay", "-keep", keep}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("keep: exit %d\n%s", code, out.String())
	}
	// A capture of the local database: the artifact digest removed.
	strip := func(b []byte) []byte {
		return []byte(strings.Replace(string(b), `"digest":"sha256:feed"`, `"digest":""`, 1))
	}
	for _, tc := range []struct {
		name  string
		local map[string]bool // which cases are the local-database capture
		code  int
		want  string
	}{
		{"local first, published second", map[string]bool{"a-case": true}, exitError, "database digest sha256:feed differs from the run's first, (none: a locally built database)"},
		{"published first, local second", map[string]bool{"b-case": true}, exitError, "database digest (none: a locally built database) differs from the run's first, sha256:feed"},
		{"both local", map[string]bool{"a-case": true, "b-case": true}, exitOK, ""},
		{"both published", map[string]bool{}, exitOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, c := range []string{"a-case", "b-case"} {
				for _, f := range []string{c + ".scan.json", c + ".exit"} {
					b, err := os.ReadFile(filepath.Join(keep, f))
					if err != nil {
						t.Fatal(err)
					}
					if tc.local[c] && strings.HasSuffix(f, ".json") {
						b = strip(b)
					}
					if err := os.WriteFile(filepath.Join(dir, f), b, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			}
			report := filepath.Join(t.TempDir(), "report.json")
			var out, errOut bytes.Buffer
			code := run([]string{"-labels", writeLabels(t, labels), "-offline", dir, "-out", report}, &out, &errOut, nil)
			if code != tc.code || (tc.want != "" && !strings.Contains(errOut.String(), tc.want)) {
				t.Errorf("exit %d, want %d; stderr lacks %q:\n%s\n%s", code, tc.code, tc.want, errOut.String(), out.String())
			}
			if tc.code == exitOK {
				rb, _ := os.ReadFile(report)
				// Two local captures name no published database at all.
				published := strings.Contains(string(rb), "sha256:feed")
				if published == (len(tc.local) == 2) || !strings.Contains(out.String(), "alpine  2       0   2") {
					t.Errorf("report/table: published database named = %v, want %v, and two TN:\n%s\n%s", published, len(tc.local) != 2, rb, out.String())
				}
			}
		})
	}
}
