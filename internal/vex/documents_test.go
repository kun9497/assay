package vex

import (
	"testing"
	"time"

	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// Each document's counts are its own when several are applied as one set.
func TestApplyAll_CountsBelongToTheDocumentThatEarnedThem(t *testing.T) {
	const purl = "pkg:rpm/amzn/openssl@3.0.8-1"
	doc := func(day int, cves ...string) *Document {
		d := &Document{Timestamp: time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC), HasTimestamp: true}
		for i, c := range cves {
			d.Statements = append(d.Statements, Statement{
				Order: i, Vulnerability: Vulnerability{Name: c}, Products: []Product{{ID: purl}},
				Status: "not_affected", Justification: "component_not_present",
			})
		}
		return d
	}
	f := matcher.Finding{
		Package:     pkgmeta.Package{Name: "openssl", Version: "3.0.8-1", Type: "rpm", PURL: purl},
		Identifiers: []string{"ALAS-1", "CVE-2026-1", "CVE-2026-2"},
		Bundled:     []string{"CVE-2026-1", "CVE-2026-2"},
	}
	f.Advisory.ID = "ALAS-1"
	docs := []*Document{doc(1, "CVE-2026-9", "CVE-2026-8"), doc(2, "CVE-2026-1"), doc(3, "CVE-2026-2", "CVE-2026-7")}
	kept, suppressed, stats := ApplyAll(docs, []matcher.Finding{f}, Target{}, func(m string) { t.Log(m) })
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Fatalf("%d kept, %d suppressed; want the fully waived bundle suppressed", len(kept), len(suppressed))
	}
	for i, want := range []Stats{
		{Statements: 2, Unmatched: 2},
		{Statements: 1, Waived: 1},
		{Statements: 2, Unmatched: 1, Waived: 1, Applied: 1},
	} {
		if stats[i] != want {
			t.Errorf("document %d: %+v, want %+v", i, stats[i], want)
		}
	}
}
