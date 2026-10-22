package redhat

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// The 2026-10-22 external review's #4, on Red Hat's side of D129. The delta
// ran before the archive was downloaded, so an archive regenerated in
// between carried documents newer than the delta's copies, which the walk
// then dropped as superseded. The archive is now downloaded first, and an
// archive copy newer than the delta's by current_release_date is emitted
// after it rather than skipped. See suse/snapshot_test.go for the fuller
// account; the two providers mirror each other.

// docJSONDated is docJSON with the tracking dates CSAF carries.
func docJSONDated(t *testing.T, cve string, current time.Time, pkg, fixedEVR string) string {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal([]byte(rhel9Doc(t, cve, pkg, fixedEVR)), &raw); err != nil {
		t.Fatal(err)
	}
	tracking := raw["document"].(map[string]any)["tracking"].(map[string]any)
	tracking["current_release_date"] = current.Format(time.RFC3339)
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lastFixed(t *testing.T, got []advisory.Advisory, id string) string {
	t.Helper()
	fixed, seen := "", false
	for _, a := range got {
		if a.ID != id {
			continue
		}
		seen = true
		for _, af := range a.Affected {
			for _, r := range af.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						fixed = e.Fixed
					}
				}
			}
		}
	}
	if !seen {
		t.Fatalf("%s was never emitted", id)
	}
	return fixed
}

func TestFetch_ArchiveIsDownloadedBeforeTheDelta(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", "2026-08-06T00:00:00+00:00"}),
		docs:    map[string]string{"2026/cve-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "curl", "")},
	}
	if _, _, err := fetchAll(t, serve(t, f)); err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	archiveAt, changesAt := slices.Index(reqs, "GET csaf_vex_2026-08-05.tar.zst"), slices.Index(reqs, "GET "+changesFile)
	if archiveAt < 0 || changesAt < 0 || archiveAt > changesAt {
		t.Errorf("the delta was consulted before the archive was downloaded: %v", reqs)
	}
}

func TestDelta_ArchiveCopyNewerThanTheDeltasCopyIsKept(t *testing.T) {
	t1 := time.Date(2026, 8, 6, 1, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveOf(t, map[string]string{
			"2026/cve-2026-0001.json": docJSONDated(t, "CVE-2026-0001", t2, "openssh", "0:2-2.el9.x86_64"),
		}),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", t1.Format(time.RFC3339)}),
		docs: map[string]string{
			"2026/cve-2026-0001.json": docJSONDated(t, "CVE-2026-0001", t1, "openssh", "0:1-1.el9.x86_64"),
		},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if n := f.hitsFor("2026/cve-2026-0001.json"); n != 1 {
		t.Fatalf("precondition: the delta copy was fetched %d times, want 1", n)
	}
	if fixed := lastFixed(t, got, "REDHAT-CVE-2026-0001"); fixed != "0:2-2.el9" {
		t.Errorf("fixed = %q, want the archive's newer 0:2-2.el9 to be the last word", fixed)
	}
	if !strings.Contains(progress, "1 archive documents newer than the copy the delta fetched") {
		t.Errorf("progress does not count the archive copy that outranked the delta's:\n%s", progress)
	}
	if !strings.Contains(progress, "0 archive documents superseded") {
		t.Errorf("a newer archive copy must not be counted as superseded:\n%s", progress)
	}
}

// The control: a delta copy at least as new as the archive's still
// supersedes it (D129).
func TestDelta_CopyAsNewAsTheArchivesStillSupersedes(t *testing.T) {
	t1 := time.Date(2026, 8, 6, 1, 0, 0, 0, time.UTC)
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveOf(t, map[string]string{
			"2026/cve-2026-0001.json": docJSONDated(t, "CVE-2026-0001", t1, "openssh", "0:1-1.el9.x86_64"),
		}),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", t1.Format(time.RFC3339)}),
		docs: map[string]string{
			"2026/cve-2026-0001.json": docJSONDated(t, "CVE-2026-0001", t1, "openssh", "0:3-3.el9.x86_64"),
		},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if fixed := lastFixed(t, got, "REDHAT-CVE-2026-0001"); fixed != "0:3-3.el9" {
		t.Errorf("fixed = %q, want the delta's equally-dated 0:3-3.el9", fixed)
	}
	if !strings.Contains(progress, "1 archive documents superseded") || !strings.Contains(progress, "0 archive documents newer") {
		t.Errorf("progress should count one superseded copy and no newer archive copy:\n%s", progress)
	}
}
