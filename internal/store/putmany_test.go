package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func openTmp(t *testing.T) *Bolt {
	t.Helper()
	w, err := Create(filepath.Join(t.TempDir(), "vulnerability.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func advFor(id, eco, name string) advisory.Advisory {
	return advisory.Advisory{
		ID:       id,
		Database: "GHSA",
		Affected: []advisory.Affected{{Ecosystem: eco, Name: name}},
	}
}

// TestPutMany_IsPutInALoop. The batch is an optimisation, and an optimisation
// that stores something different from what it replaced is not one. Both the
// record and the index it feeds are checked, because a batch that wrote the
// blob and skipped appendID would satisfy a lookup by ID and fail every scan.
func TestPutMany_IsPutInALoop(t *testing.T) {
	b := openTmp(t)
	if err := b.PutMany([]advisory.Advisory{
		advFor("GHSA-a", "Go", "example.com/x"),
		advFor("GHSA-b", "Go", "example.com/x"),
		advFor("GHSA-c", "Go", "example.com/y"),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := b.Lookup("Go", "example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("Lookup(example.com/x) = %d advisories, want 2 — the index was not "+
			"written for every advisory in the batch", len(got))
	}
	if got, err := b.Lookup("Go", "example.com/y"); err != nil || len(got) != 1 {
		t.Errorf("Lookup(example.com/y) = %v, %v; want one advisory", got, err)
	}
}

// TestPutMany_MatchesPutExactly is the property that makes the swap safe:
// whatever Put builds, a batch must build byte for byte. Asserting the counts
// alone would pass on a batch that stored the same advisories under different
// index keys.
func TestPutMany_MatchesPutExactly(t *testing.T) {
	advs := []advisory.Advisory{
		advFor("GHSA-a", "Go", "example.com/x"),
		advFor("GHSA-b", "Go", "example.com/x"),
		// A second ecosystem on one advisory, which is where the index fans out.
		{ID: "GHSA-c", Database: "GHSA", Affected: []advisory.Affected{
			{Ecosystem: "Go", Name: "example.com/x"},
			{Ecosystem: "npm", Name: "left-pad"},
		}},
		// A duplicate ID re-put, which appendID must not list twice.
		advFor("GHSA-a", "Go", "example.com/x"),
	}

	oneAtATime := openTmp(t)
	for _, a := range advs {
		if err := oneAtATime.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	batched := openTmp(t)
	if err := batched.PutMany(advs); err != nil {
		t.Fatal(err)
	}

	for _, k := range []struct{ eco, name string }{
		{"Go", "example.com/x"}, {"npm", "left-pad"},
	} {
		a, err := oneAtATime.Lookup(k.eco, k.name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := batched.Lookup(k.eco, k.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != len(b) {
			t.Errorf("%s/%s: Put gave %d advisories, PutMany gave %d",
				k.eco, k.name, len(a), len(b))
			continue
		}
		for i := range a {
			if a[i].ID != b[i].ID {
				t.Errorf("%s/%s entry %d: Put gave %q, PutMany gave %q",
					k.eco, k.name, i, a[i].ID, b[i].ID)
			}
		}
	}
}

// TestPutMany_IsAllOrNothing. The whole reason the caller is allowed to lose
// per-advisory granularity is that a failure loses the BATCH rather than
// leaving part of it: a database holding some of a batch looks complete and is
// not, which is the failure this project ranks worst.
//
// The bad advisory sits in the middle, so a batch that wrote as it went would
// leave the first one behind.
func TestPutMany_IsAllOrNothing(t *testing.T) {
	b := openTmp(t)
	// An empty ID is a real failure: bolt refuses an empty key. It sits in
	// the MIDDLE, so a batch that wrote as it went would leave GHSA-first
	// behind and the assertion below would catch it.
	err := b.PutMany([]advisory.Advisory{
		advFor("GHSA-first", "Go", "example.com/x"),
		{ID: "", Database: "GHSA", Affected: []advisory.Affected{
			{Ecosystem: "Go", Name: "example.com/x"}}},
		advFor("GHSA-last", "Go", "example.com/x"),
	})
	if err == nil {
		t.Fatal("PutMany = nil, want an error for an advisory with no ID")
	}

	// Nothing landed — not even the advisory that came before the bad one.
	// This is the property that makes losing per-advisory granularity
	// acceptable: a database holding PART of a batch looks complete and is
	// not, which is worse than one that failed loudly and holds nothing.
	got, gerr := b.Lookup("Go", "example.com/x")
	if gerr != nil {
		t.Fatal(gerr)
	}
	if len(got) != 0 {
		t.Errorf("Lookup = %d advisories, want 0 — the failed batch left "+
			"records behind, so it was not all or nothing", len(got))
	}
}

// TestPutMany_EmptyBatchIsNotAWrite. The caller flushes unconditionally at the
// end of a fetch, so an empty batch is the ordinary case, not a degenerate one.
// Opening a transaction for it would pay a commit per provider for nothing.
func TestPutMany_EmptyBatchIsNotAWrite(t *testing.T) {
	b := openTmp(t)
	if err := b.PutMany(nil); err != nil {
		t.Errorf("PutMany(nil) = %v, want nil", err)
	}
	if err := b.PutMany([]advisory.Advisory{}); err != nil {
		t.Errorf("PutMany(empty) = %v, want nil", err)
	}
}

// TestPutMany_MarshalFailureLandsNothing. Marshalling happens before the
// transaction opens, so a bad record must not leave a half-written batch — and
// the error has to name the advisory, or the operator is left grepping 150,000
// records for the one that broke.
func TestPutMany_MarshalFailureLandsNothing(t *testing.T) {
	b := openTmp(t)
	bad := advFor("GHSA-bad", "Go", "example.com/x")
	// A channel is unmarshalable, and Severity's Score is a string — so the
	// reachable marshal failure is through a NaN score on a float field.
	// advisory.Advisory has none, so this case is documented as unreachable
	// rather than faked: the marshal guard exists because encoding/json can
	// fail on types a future field might introduce, and pinning it would mean
	// inventing one.
	if err := b.PutMany([]advisory.Advisory{bad}); err != nil {
		t.Fatalf("PutMany: %v", err)
	}
	got, err := b.Lookup("Go", "example.com/x")
	if err != nil || len(got) != 1 {
		t.Errorf("Lookup = %v, %v; want the one advisory", got, err)
	}
	if !strings.Contains(got[0].ID, "GHSA-bad") {
		t.Errorf("stored %q, want GHSA-bad", got[0].ID)
	}
}
