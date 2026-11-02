package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// waiverDB holds one critical npm advisory on wv-lib below 2.0.0, with an ID
// (GHSA-wv01-...) that shares no substring with its CVE alias.
func waiverDB(t *testing.T, eco, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "GHSA-wv01-0000-0001", Kind: advisory.KindVulnerability, Database: "GHSA",
		Aliases:  []string{"CVE-2026-90001"},
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []advisory.Affected{{Ecosystem: eco, Name: name, Ranges: []advisory.Range{{
			Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
		}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{eco}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func waiverSBOM(t *testing.T) string {
	t.Helper()
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"wv-lib","version":"1.0.0","purl":"pkg:npm/wv-lib@1.0.0"}]}`
	p := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Audit P4, re-verified 2026-11-02: --explain on a finding that a waiver
// suppressed answered "no finding matches" with exit 2, as if the
// identifier were mistyped, although every other renderer shows the
// suppression with its source (D102). It now explains the finding and says
// first, by which waiver and why, that it is not counted. Both waiver
// sources, and both the advisory's ID and its alias.
func TestRun_ExplainShowsAWaivedFinding(t *testing.T) {
	db := waiverDB(t, "npm", "wv-lib")
	sbom := waiverSBOM(t)
	cfg := filepath.Join(t.TempDir(), ".assay.yaml")
	if err := os.WriteFile(cfg, []byte("ignore:\n  - vulnerability: CVE-2026-90001\n    reason: wv ignore reason\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	vex := writeVEX(t, stmt("CVE-2026-90001", product("pkg:npm/wv-lib@1.0.0")))
	for _, tc := range []struct {
		name   string
		opts   Options
		source string
	}{
		{"ignore file", Options{IgnoreFile: cfg}, "(ignore-file: wv ignore reason)"},
		{"vex", Options{VEXFiles: []string{vex}}, "(vex: VEX: not_affected (inline_mitigations_already_exist)"},
	} {
		for _, id := range []string{"GHSA-wv01-0000-0001", "CVE-2026-90001"} {
			t.Run(tc.name+"/"+id, func(t *testing.T) {
				opts := tc.opts
				opts.Explain = id
				var out, errOut bytes.Buffer
				code := Run(context.Background(), db, sbom, opts, &out, &errOut)
				if code != 0 || strings.Contains(errOut.String(), "no finding matches") {
					t.Fatalf("exit %d, stderr %q; want 0: the identifier names a finding, and a waived one does not count", code, errOut.String())
				}
				first, rest, _ := strings.Cut(out.String(), "\n")
				if !strings.HasPrefix(first, "suppressed: not counted toward the verdict ") || !strings.Contains(first, tc.source) {
					t.Errorf("first line %q, want the suppression and its source %q first", first, tc.source)
				}
				if !strings.Contains(rest, "advisory: GHSA-wv01-0000-0001") || !strings.Contains(rest, "package:  wv-lib 1.0.0 [npm]") {
					t.Errorf("explanation = %q, want the finding explained below the suppression line", rest)
				}
			})
		}
	}
}

// Audit P4: with every finding waived the table's headline said "No known
// vulnerabilities found", the same sentence a scan that found nothing
// prints. It now says the findings were suppressed and that they are listed.
func TestRun_TableHeadlineWhenEveryFindingIsWaived(t *testing.T) {
	db := waiverDB(t, "npm", "wv-lib")
	cfg := filepath.Join(t.TempDir(), ".assay.yaml")
	if err := os.WriteFile(cfg, []byte("ignore:\n  - vulnerability: CVE-2026-90001\n    reason: wv ignore reason\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, waiverSBOM(t), Options{IgnoreFile: cfg}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	first, _, _ := strings.Cut(out.String(), "\n")
	if want := "No unwaived vulnerabilities found in 1 package(s): 1 finding(s) suppressed, listed below."; first != want {
		t.Errorf("headline = %q, want %q", first, want)
	}
	if !strings.Contains(out.String(), "wv-lib  npm  GHSA-wv01-0000-0001  (ignore-file: wv ignore reason)") {
		t.Errorf("table = %q, want the suppressed block to list the finding", out.String())
	}
}

// Audit P4, re-verified 2026-11-02: a pinned requirements.txt package
// carried no PURL, type or location, unlike every other Python reader, so a
// VEX statement naming pkg:pypi/... never reached it -- the same package was
// suppressed from Pipfile.lock and kept from requirements.txt, with no
// "statement matched nothing" warning. The JSON report also could not say
// which file a finding came from.
func TestRun_RequirementsTxtPackageCarriesItsPURLAndLocation(t *testing.T) {
	db := waiverDB(t, "PyPI", "wv-lib")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("wv-lib==1.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, dir, Options{Output: "json"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	var r struct {
		Findings []struct {
			Package struct {
				PURL      string `json:"purl"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"package"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %d, want 1\n%s", len(r.Findings), out.String())
	}
	p := r.Findings[0].Package
	if p.PURL != "pkg:pypi/wv-lib@1.0.0" || len(p.Locations) != 1 || p.Locations[0].Path != "requirements.txt" {
		t.Errorf("package = %+v, want purl pkg:pypi/wv-lib@1.0.0, location requirements.txt", p)
	}

	vex := writeVEX(t, stmt("CVE-2026-90001", product("pkg:pypi/wv-lib@1.0.0")))
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), db, dir, Options{Output: "json", VEXFiles: []string{vex}}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %s", code, errOut.String())
	}
	var s struct {
		Findings   []json.RawMessage `json:"findings"`
		Suppressed []json.RawMessage `json:"suppressed"`
	}
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(s.Findings) != 0 || len(s.Suppressed) != 1 {
		t.Errorf("findings %d, suppressed %d, want 0 and 1: the statement names the package's purl\nstderr: %s",
			len(s.Findings), len(s.Suppressed), errOut.String())
	}
}
