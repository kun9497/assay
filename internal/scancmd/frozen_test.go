package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// D110's scan-time half. A seeded build records a frozen key in
// Meta.Providers[p].Frozen, not on the advisory record, so the disclosure has
// to be read from Meta by the matcher and carried to every renderer. These
// tests drive Run end to end against a real bolt database, the caller that
// the matcher's map lookup and each renderer's line exist for: delete any one
// of them and the matching assertion below goes red.
//
// Two keys in one scan, so every assertion can say "on this finding and NOT
// on that one": npm is frozen, Go is live. The IDs are chosen so neither
// contains the other, and the frozen date is one no other field carries.

var frozenSince = time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)

const (
	frozenID = "GHSA-frzn-0001"
	liveID   = "GHSA-live-0002"
)

func frozenDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	put := func(id, eco, name string) {
		a := advisory.Advisory{
			ID: id, Kind: advisory.KindVulnerability, Database: "GHSA",
			Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
			Affected: []advisory.Affected{{
				Ecosystem: eco, Name: name,
				Ranges: []advisory.Range{{Type: advisory.RangeSemver,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
			}},
		}
		if err := w.Put(a); err != nil {
			t.Fatalf("Put(%s): %v", id, err)
		}
	}
	put(frozenID, "npm", "frozenpkg")
	put(liveID, "Go", "example.com/livepkg")
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{
			"osv": {
				Ecosystems: []string{"Go", "npm"},
				Frozen:     map[string]time.Time{"npm": frozenSince},
			},
		},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func frozenSBOM(t *testing.T) string {
	t.Helper()
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"frozenpkg","version":"1.0.0","purl":"pkg:npm/frozenpkg@1.0.0"},` +
		`{"type":"library","name":"livepkg","version":"1.0.0","purl":"pkg:golang/example.com/livepkg@1.0.0"}]}`
	path := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func runFrozen(t *testing.T, opts Options) (string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), frozenDB(t), frozenSBOM(t), opts, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0;\nstdout: %s\nstderr: %s", code, out.String(), errOut.String())
	}
	return out.String(), errOut.String()
}

func TestRun_D110_JSONCarriesFrozenSinceOnlyOnTheFrozenKey(t *testing.T) {
	out, _ := runFrozen(t, Options{Output: "json"})
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Findings      []struct {
			Advisory struct {
				ID string `json:"id"`
			} `json:"advisory"`
			FrozenSince *string `json:"frozenSince"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	// frozenSince itself was additive and omitempty, the D108 crossMappedFrom
	// precedent, and bumped nothing; 12 is D111's coverage[], which is not.
	if doc.SchemaVersion != 12 {
		t.Errorf("schemaVersion = %d, want 12", doc.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, f := range doc.Findings {
		seen[f.Advisory.ID] = true
		switch f.Advisory.ID {
		case frozenID:
			if f.FrozenSince == nil || *f.FrozenSince != "2026-06-30" {
				t.Errorf("%s frozenSince = %v, want \"2026-06-30\"", frozenID, f.FrozenSince)
			}
		case liveID:
			if f.FrozenSince != nil {
				t.Errorf("%s frozenSince = %q, want absent: Go is a live key", liveID, *f.FrozenSince)
			}
		}
	}
	if !seen[frozenID] || !seen[liveID] {
		t.Fatalf("findings = %v, want both %s and %s:\n%s", seen, frozenID, liveID, out)
	}
}

func TestRun_D110_TableMarksTheFrozenRowAndFootnotesTheDate(t *testing.T) {
	out, _ := runFrozen(t, Options{})
	var frozenRow, liveRow string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, frozenID):
			frozenRow = line
		case strings.Contains(line, liveID):
			liveRow = line
		}
	}
	if frozenRow == "" || liveRow == "" {
		t.Fatalf("missing a row:\n%s", out)
	}
	// The marker sits in the ECOSYSTEM cell, so assert the rendered pair
	// rather than the glyph alone.
	if !strings.Contains(frozenRow, "npm @") {
		t.Errorf("frozen row lacks the \"npm @\" marker: %q", frozenRow)
	}
	if strings.Contains(liveRow, "@") {
		t.Errorf("live row carries the frozen marker: %q", liveRow)
	}
	want := "\n@ advisory data for npm includes entries carried forward since 2026-06-30: " +
		"the upstream stopped publishing some or all of it\n"
	if !strings.Contains(out, want) {
		t.Errorf("table lacks the footnote line %q:\n%s", want, out)
	}
	if strings.Contains(out, "advisory data for Go") {
		t.Errorf("table footnotes the live key Go:\n%s", out)
	}
}

func TestRun_D110_SARIFMessageSaysFrozenSince(t *testing.T) {
	out, _ := runFrozen(t, Options{Output: "sarif"})
	var doc struct {
		Runs []struct {
			Results []struct {
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not SARIF JSON: %v\n%s", err, out)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	var frozenMsg, liveMsg string
	for _, r := range doc.Runs[0].Results {
		// Keyed on the message's own leading advisory ID: ruleId prefers a
		// CVE when the record has one, so it is not the advisory ID in
		// general.
		switch {
		case strings.HasPrefix(r.Message.Text, frozenID+" affects "):
			frozenMsg = r.Message.Text
		case strings.HasPrefix(r.Message.Text, liveID+" affects "):
			liveMsg = r.Message.Text
		}
	}
	if !strings.Contains(frozenMsg, "advisory data for npm includes entries carried forward since 2026-06-30") {
		t.Errorf("%s message lacks the frozen sentence: %q", frozenID, frozenMsg)
	}
	if liveMsg == "" || strings.Contains(liveMsg, "carried forward") {
		t.Errorf("%s message = %q, want present and without a frozen sentence", liveID, liveMsg)
	}
}

func TestRun_D110_ExplainPrintsTheFrozenLine(t *testing.T) {
	out, _ := runFrozen(t, Options{Explain: frozenID})
	want := "frozen:   advisory data for npm includes entries carried forward since 2026-06-30"
	if !strings.Contains(out, want) {
		t.Errorf("--explain %s lacks %q:\n%s", frozenID, want, out)
	}
	live, _ := runFrozen(t, Options{Explain: liveID})
	if strings.Contains(live, "frozen") {
		t.Errorf("--explain %s mentions frozen for a live key:\n%s", liveID, live)
	}
}
