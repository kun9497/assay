package store

import (
	"path/filepath"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func TestDeleteRatings_DeletesOnlyTheExactSource(t *testing.T) {
	b, err := Create(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for _, cve := range []string{"CVE-A", "CVE-B", "CVE-C"} {
		for _, source := range []string{"NVD", "KEV", "OTHER-KEV"} {
			if err := b.PutRating(advisory.Rating{CVE: cve, Source: source}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := b.DeleteRatings("KEV"); err != nil {
		t.Fatal(err)
	}
	for _, cve := range []string{"CVE-A", "CVE-B", "CVE-C"} {
		rs, err := b.RatingsFor(cve)
		if err != nil {
			t.Fatal(err)
		}
		if len(rs) != 2 || rs[0].Source != "NVD" || rs[1].Source != "OTHER-KEV" {
			t.Fatalf("wrong survivors: %+v", rs)
		}
	}
}

func TestAdvisoryCounts_DeduplicatesEachEcosystemPerRecord(t *testing.T) {
	b, err := Create(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Put(advisory.Advisory{ID: "GHSA-a", Affected: []advisory.Affected{{Ecosystem: "Go", Name: "a"}, {Ecosystem: "Go", Name: "b"}, {Ecosystem: "npm", Name: "c"}}}); err != nil {
		t.Fatal(err)
	}
	total, counts, err := b.AdvisoryCounts()
	if err != nil || total != 1 || counts["Go"] != 1 || counts["npm"] != 1 {
		t.Fatalf("total=%d counts=%v err=%v", total, counts, err)
	}
}
