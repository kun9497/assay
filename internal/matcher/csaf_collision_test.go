package matcher

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// TestRedHatAndSUSERecordsForTheSameCVEDoNotCollide is D90's regression test
// for the bug this slice fixes, written caller-first (CLAUDE.md).
//
// Before the fix, both CSAF providers (internal/provider/redhat, D47, and
// internal/provider/suse, D77) stored their record for one CVE under the
// bare CVE as Advisory.ID. The store's by-id bucket (internal/store/bolt.go)
// is last-writer-wins on ID, so on a full multi-provider build the second
// Put silently overwrote the first's Affected entries. The per-ecosystem
// index rows for BOTH vendors still existed and Lookup for either ecosystem
// still returned a hit -- but by-id held only one vendor's whole record, so
// whichever ecosystem lost the race got back a record with no affected entry
// for it at all. Measured against a real two-provider build: ubi9 lost 377
// of 415 Red Hat tuples (91%).
//
// This drives it through the REAL store, not fakeStore: fakeStore.Lookup
// (matcher_test.go) answers straight out of a byKey map with no separate
// by-id bucket to collide in, so it cannot reproduce this bug no matter how
// it is fixtured -- only Bolt.Put/Lookup's ID-keyed sharing can.
func TestRedHatAndSUSERecordsForTheSameCVEDoNotCollide(t *testing.T) {
	redhatAdv := advisory.Advisory{
		ID:       "REDHAT-CVE-2026-73566",
		Database: "REDHAT",
		Source:   "redhat",
		Kind:     advisory.KindVulnerability,
		Aliases:  []string{"CVE-2026-73566"},
		Affected: []advisory.Affected{{
			Ecosystem: "Red Hat:9",
			Name:      "tar",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.34-7.el9"}},
			}},
		}},
	}
	// A DIFFERENT fixed version from the Red Hat record on purpose: if a
	// collision returns the wrong vendor's record, the fixed version proves
	// it (equal versions across both fixtures could pass by accident).
	suseAdv := advisory.Advisory{
		ID:       "SUSE-CVE-2026-73566",
		Database: "SUSE",
		Source:   "suse",
		Kind:     advisory.KindVulnerability,
		Aliases:  []string{"CVE-2026-73566"},
		Affected: []advisory.Affected{{
			Ecosystem: "SLES:15.SP6",
			Name:      "tar",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.34-150000.3.20.1"}},
			}},
		}},
	}

	path := filepath.Join(t.TempDir(), "v.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(redhatAdv); err != nil {
		t.Fatalf("Put(%s): %v", redhatAdv.ID, err)
	}
	if err := w.Put(suseAdv); err != nil {
		t.Fatalf("Put(%s): %v", suseAdv.ID, err)
	}
	// Ecosystems (D20) is what Covers() reads, and it comes from provider
	// self-report, not from what Put indexed -- so both ecosystems have to
	// be named here or Match's own coverage guard skips every package before
	// ever reaching the store bug this test exists to catch.
	err = w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{
			"redhat": {Ecosystems: []string{"Red Hat:9"}},
			"suse":   {Ecosystems: []string{"SLES:15.SP6"}},
		},
	})
	if err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// The store-level assertion: each ecosystem's Lookup returns ITS OWN
	// record, whole, carrying its own Affected entry -- not a record
	// clobbered by the other vendor's Put landing on the same by-id key.
	gotRH, err := db.Lookup("Red Hat:9", "tar")
	if err != nil {
		t.Fatalf("Lookup(Red Hat:9, tar): %v", err)
	}
	if len(gotRH) != 1 || gotRH[0].ID != "REDHAT-CVE-2026-73566" {
		t.Fatalf("Lookup(Red Hat:9, tar) = %+v, want exactly the Red Hat record", gotRH)
	}
	if len(gotRH[0].Affected) != 1 || gotRH[0].Affected[0].Ecosystem != "Red Hat:9" ||
		len(gotRH[0].Affected[0].Ranges) != 1 || gotRH[0].Affected[0].Ranges[0].Events[1].Fixed != "1.34-7.el9" {
		t.Fatalf("Lookup(Red Hat:9, tar) record = %+v, want the Red Hat record's OWN affected "+
			"entry fixed at 1.34-7.el9 -- a by-id collision returns the SUSE record instead", gotRH[0])
	}

	gotSUSE, err := db.Lookup("SLES:15.SP6", "tar")
	if err != nil {
		t.Fatalf("Lookup(SLES:15.SP6, tar): %v", err)
	}
	if len(gotSUSE) != 1 || gotSUSE[0].ID != "SUSE-CVE-2026-73566" {
		t.Fatalf("Lookup(SLES:15.SP6, tar) = %+v, want exactly the SUSE record", gotSUSE)
	}
	if len(gotSUSE[0].Affected) != 1 || gotSUSE[0].Affected[0].Ecosystem != "SLES:15.SP6" ||
		len(gotSUSE[0].Affected[0].Ranges) != 1 || gotSUSE[0].Affected[0].Ranges[0].Events[1].Fixed != "1.34-150000.3.20.1" {
		t.Fatalf("Lookup(SLES:15.SP6, tar) record = %+v, want the SUSE record's OWN affected "+
			"entry fixed at 1.34-150000.3.20.1 -- a by-id collision returns the Red Hat record instead",
			gotSUSE[0])
	}

	// Through the matcher: a target on EACH ecosystem gets its OWN finding,
	// judged against its own vendor's fixed version. A by-id collision would
	// silently substitute the other vendor's record (or its absence) here
	// too, since Match reads through the same store.
	rhRes, err := New(db).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{{Name: "tar", Version: "1.30-5.el9", Ecosystem: "Red Hat:9"}},
	})
	if err != nil {
		t.Fatalf("Match(Red Hat:9): %v", err)
	}
	if len(rhRes.Findings) != 1 || rhRes.Findings[0].Advisory.ID != "REDHAT-CVE-2026-73566" ||
		rhRes.Findings[0].Evidence.Fixed != "1.34-7.el9" {
		t.Fatalf("Match(Red Hat:9) findings = %+v, want one finding against REDHAT-CVE-2026-73566 "+
			"fixed at 1.34-7.el9", rhRes.Findings)
	}

	suseRes, err := New(db).Match(pkgmeta.Target{
		Packages: []pkgmeta.Package{{Name: "tar", Version: "1.30-150000.3.10.1", Ecosystem: "SLES:15.SP6"}},
	})
	if err != nil {
		t.Fatalf("Match(SLES:15.SP6): %v", err)
	}
	if len(suseRes.Findings) != 1 || suseRes.Findings[0].Advisory.ID != "SUSE-CVE-2026-73566" ||
		suseRes.Findings[0].Evidence.Fixed != "1.34-150000.3.20.1" {
		t.Fatalf("Match(SLES:15.SP6) findings = %+v, want one finding against SUSE-CVE-2026-73566 "+
			"fixed at 1.34-150000.3.20.1", suseRes.Findings)
	}
}
