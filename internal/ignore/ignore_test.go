package ignore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, DefaultFile)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func finding(id, cve, pkg, eco string) matcher.Finding {
	return matcher.Finding{
		Package:     pkgmeta.Package{Name: pkg, Ecosystem: eco},
		Advisory:    advisory.Advisory{ID: id},
		Identifiers: []string{id, cve},
	}
}

// TestLoad_RefusesARuleWithNoReason holds the reason-is-mandatory rule: an
// unexplained waiver is refused at load time, not silently accepted. This is
// the whole point of the feature over a bare suppress-list.
func TestLoad_RefusesARuleWithNoReason(t *testing.T) {
	p := writeConfig(t, "ignore:\n  - vulnerability: CVE-2024-1234\n")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "no reason") {
		t.Errorf("Load = %v, want an error about the missing reason", err)
	}
}

// TestLoad_RefusesARuleWithNoMatchField holds that a rule naming only a
// reason — which would waive the ENTIRE scan — is refused. Silently waiving
// everything is the worst possible reading of a config typo.
func TestLoad_RefusesARuleWithNoMatchField(t *testing.T) {
	p := writeConfig(t, "ignore:\n  - reason: \"accepted\"\n")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "whole scan") {
		t.Errorf("Load = %v, want an error that the rule would waive the whole scan", err)
	}
}

// TestLoad_RefusesAnUnknownKey holds KnownFields: a mistyped key
// ("vulnerabilty") is an error, not a rule that silently matches nothing.
func TestLoad_RefusesAnUnknownKey(t *testing.T) {
	p := writeConfig(t, "ignore:\n  - vulnerabilty: CVE-2024-1234\n    reason: typo\n")
	if _, err := Load(p); err == nil {
		t.Error("Load accepted a misspelled key; a typo'd field must fail, not silently match nothing")
	}
}

// TestLoad_RefusesAMalformedExpiry holds that a bad date fails loud rather
// than being read as "already expired" or "never".
func TestLoad_RefusesAMalformedExpiry(t *testing.T) {
	p := writeConfig(t, "ignore:\n  - vulnerability: CVE-2024-1234\n    reason: x\n    expires: 2026-13-40\n")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Errorf("Load = %v, want an error naming the unparseable expires", err)
	}
}

// TestApply_WaivesOnAllThreeFields drives the AND-within-a-rule matching:
// vulnerability + package + ecosystem must all match, and an alias CVE counts
// as the vulnerability (a rule naming the CVE waives a finding whose advisory
// only aliases it).
func TestApply_WaivesOnAllThreeFields(t *testing.T) {
	p := writeConfig(t, "ignore:\n"+
		"  - vulnerability: CVE-2024-1234\n    package: openssl\n    ecosystem: Alpine:v3.19\n    reason: not in our build path\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	findings := []matcher.Finding{
		finding("ALPINE-2024-0001", "CVE-2024-1234", "openssl", "Alpine:v3.19"), // matches all three
		finding("ALPINE-2024-0002", "CVE-2024-9999", "openssl", "Alpine:v3.19"), // wrong CVE
		finding("ALPINE-2024-0001", "CVE-2024-1234", "openssl", "Debian:12"),    // wrong ecosystem
	}
	kept, sup := cfg.Apply(findings, time.Now(), func(string) {})
	if len(sup) != 1 {
		t.Fatalf("suppressed %d, want 1 (only the finding matching all three fields)", len(sup))
	}
	if sup[0].Reason != "not in our build path" {
		t.Errorf("reason = %q, want the rule's reason", sup[0].Reason)
	}
	if len(kept) != 2 {
		t.Errorf("kept %d, want 2 (the two that did not match every field)", len(kept))
	}
}

// TestApply_CaseInsensitiveVulnerability: a user writing cve-2024-1234 waives
// CVE-2024-1234.
func TestApply_CaseInsensitiveVulnerability(t *testing.T) {
	p := writeConfig(t, "ignore:\n  - vulnerability: cve-2024-1234\n    reason: x\n")
	cfg, _ := Load(p)
	_, sup := cfg.Apply([]matcher.Finding{finding("A-1", "CVE-2024-1234", "p", "Go")}, time.Now(), func(string) {})
	if len(sup) != 1 {
		t.Errorf("suppressed %d, want 1 — the match must be case-insensitive", len(sup))
	}
}

// TestApply_ExpiredRuleStopsWaivingAndWarns is the expiry discipline: a rule
// whose date has passed no longer suppresses anything AND warns, so a waiver
// cannot outlive its justification in silence. The inclusive boundary (the
// named date is the last day it holds) is pinned in both directions.
func TestApply_ExpiredRuleStopsWaivingAndWarns(t *testing.T) {
	p := writeConfig(t, "ignore:\n  - vulnerability: CVE-2024-1234\n    reason: temporary\n    expires: 2026-06-30\n")
	cfg, _ := Load(p)
	f := []matcher.Finding{finding("A-1", "CVE-2024-1234", "p", "Go")}

	// On the last valid day: still waived, no warning.
	var warns []string
	_, sup := cfg.Apply(f, time.Date(2026, 6, 30, 23, 0, 0, 0, time.UTC), func(m string) { warns = append(warns, m) })
	if len(sup) != 1 || len(warns) != 0 {
		t.Errorf("on the expiry date itself: suppressed %d warns %d, want 1 and 0 — the named date is inclusive", len(sup), len(warns))
	}

	// The day after: no longer waived, and it warns.
	warns = nil
	kept, sup := cfg.Apply(f, time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), func(m string) { warns = append(warns, m) })
	if len(sup) != 0 || len(kept) != 1 {
		t.Errorf("day after expiry: suppressed %d kept %d, want 0 and 1 — an expired rule must stop waiving", len(sup), len(kept))
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "expired") {
		t.Errorf("warns = %v, want one that says the rule expired", warns)
	}
}

// TestApply_FirstRuleWins: a finding matched by two rules is waived for the
// first-listed reason, the one the file's author put first.
func TestApply_FirstRuleWins(t *testing.T) {
	p := writeConfig(t, "ignore:\n"+
		"  - vulnerability: CVE-2024-1234\n    reason: first\n"+
		"  - package: openssl\n    reason: second\n")
	cfg, _ := Load(p)
	_, sup := cfg.Apply([]matcher.Finding{finding("A-1", "CVE-2024-1234", "openssl", "Go")}, time.Now(), func(string) {})
	if len(sup) != 1 || sup[0].Reason != "first" {
		t.Errorf("reason = %+v, want the first-listed rule's reason", sup)
	}
}

// TestDiscover_FindsDefaultFile: the working-directory default is found when
// present and absent otherwise.
func TestDiscover_FindsDefaultFile(t *testing.T) {
	dir := t.TempDir()
	if _, ok := Discover(dir); ok {
		t.Error("Discover found a file in an empty dir")
	}
	if err := os.WriteFile(filepath.Join(dir, DefaultFile), []byte("ignore: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p, ok := Discover(dir); !ok || filepath.Base(p) != DefaultFile {
		t.Errorf("Discover = %q, %v; want the .assay.yaml path and true", p, ok)
	}
}
