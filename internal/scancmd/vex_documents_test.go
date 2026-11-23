package scancmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// QA 2026-11-20. Each --vex document was applied alone, so a newer "affected"
// in one never retracted an older "not_affected" in another.
func TestRun_TheLatestVEXStatementWinsAcrossDocuments(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	doc := func(name, date string, suppress bool) string {
		p := filepath.Join(dir, name)
		provVEX(t, p, "https://example.test/"+name, suppress)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Replace(string(b), "2026-10-13", date, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldNo, newYes := doc("old-no.json", "2026-01-01", true), doc("new-yes.json", "2026-06-01", false)
	oldYes, newNo := doc("old-yes.json", "2026-01-01", false), doc("new-no.json", "2026-06-01", true)
	sameYes := doc("same-yes.json", "2026-06-01", false)
	for _, tc := range []struct {
		name       string
		files      []string
		suppressed int
		by         string
	}{
		{"newer affected retracts", []string{oldNo, newYes}, 0, ""},
		{"in either order", []string{newYes, oldNo}, 0, ""},
		{"newer not_affected suppresses", []string{oldYes, newNo}, 1, newNo},
		{"and in either order", []string{newNo, oldYes}, 1, newNo},
		{"a tie goes to the last given", []string{newNo, sameYes}, 0, ""},
		{"the other way round", []string{sameYes, newNo}, 1, newNo},
	} {
		_, stderr, code := provRun(t, db, sbom, Options{VEXFiles: tc.files})
		if code != 0 {
			t.Fatalf("%s: exit %d\n%s", tc.name, code, stderr)
		}
		if got := strings.Count(stderr, "finding(s) suppressed by VEX"); got != tc.suppressed {
			t.Errorf("%s: %d suppression lines, want %d\n%s", tc.name, got, tc.suppressed, stderr)
		}
		if tc.by != "" && !strings.Contains(stderr, fmt.Sprintf("1 finding(s) suppressed by VEX (%s)", tc.by)) {
			t.Errorf("%s: the suppression is not credited to %s\n%s", tc.name, tc.by, stderr)
		}
		// Both statements matched the finding, whichever won.
		if !strings.Contains(stderr, "vex: 0 of 2 statement(s) matched no finding") {
			t.Errorf("%s: a losing statement is counted as unmatched\n%s", tc.name, stderr)
		}
	}
}
