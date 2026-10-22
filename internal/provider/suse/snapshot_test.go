package suse

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// The 2026-10-22 external review's #4. D129 ran the delta BEFORE the
// 445 MB archive download, keyed on a pre-flight HEAD's Last-Modified. SUSE
// rebuilds the archive in place under one URL, so an archive regenerated
// between that HEAD and the GET carried documents NEWER than the delta's
// copies -- and the walk, trusting that a fetched delta copy supersedes,
// dropped the newer archive copy. Installed openssh 9.6p1-1.0 was affected
// per the archive (fixed 9.6p1-1.1) and clean per the stale delta copy
// (fixed 9.6p1-1.0).
//
// Now the archive is downloaded first, its own GET response's Last-Modified
// is the delta cutoff, and a document the delta fetched is still compared
// against the archive's copy by current_release_date: the archive copy is
// emitted after the delta's when it is the newer one.

var (
	regenT0 = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC) // what a stale HEAD would say
	regenT1 = regenT0.Add(time.Hour)                        // the delta copy's revision
	regenT2 = regenT1.Add(time.Hour)                        // the regenerated archive and its copy
)

// docJSONDated is docJSONForTest with the tracking dates CSAF carries, so a
// test can give two copies of one document a revision order.
func docJSONDated(cve string, current time.Time, platforms []string, packages map[string]string, recommended []string) string {
	var raw map[string]any
	if err := json.Unmarshal([]byte(docJSONForTest(cve, platforms, packages, recommended, nil)), &raw); err != nil {
		panic(err)
	}
	tracking := raw["document"].(map[string]any)["tracking"].(map[string]any)
	tracking["initial_release_date"] = regenT0.Format(time.RFC3339)
	tracking["current_release_date"] = current.Format(time.RFC3339)
	b, _ := json.Marshal(raw)
	return string(b)
}

// staleOpensshDoc is revision 1 of CVE-2024-6387: fixed at 9.6p1-1.0, dated
// regenT1. testdata/archive_regenerated.tar.bz2 holds revision 2 of the same
// document: fixed at 9.6p1-1.1, dated regenT2 (generated once by a python
// script, like the other fixtures; compress/bzip2 has no writer).
func staleOpensshDoc() string {
	return docJSONDated("CVE-2024-6387", regenT1,
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{"openssh-9.6p1-1.0": "pkg:rpm/suse/openssh@9.6p1-1.0?upstream=openssh-9.6p1-1.0.src.rpm"},
		[]string{"SUSE Linux Enterprise Server 15 SP6:openssh-9.6p1-1.0"})
}

// fixedOn returns the fixed version the LAST emitted copy of id carries on
// eco -- last write wins in the store, so that is the record a scan reads.
func fixedOn(t *testing.T, got []advisory.Advisory, id, eco string) string {
	t.Helper()
	fixed := ""
	seen := false
	for _, a := range got {
		if a.ID != id {
			continue
		}
		seen = true
		for _, af := range a.Affected {
			if af.Ecosystem != eco {
				continue
			}
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

func indexOf(list []string, s string) int {
	return slices.Index(list, s)
}

// The archive is downloaded before the delta is consulted, and the delta
// cutoff is the Last-Modified of the bytes actually downloaded -- never a
// pre-flight HEAD's, which an in-place rebuild can make stale.
func TestFetch_ArchiveIsDownloadedBeforeTheDelta(t *testing.T) {
	f := &feed{
		archive:         fixture(t, "archive_regenerated.tar.bz2"),
		archiveModified: regenT2,
		headModified:    regenT0,
		changes:         changesCSV([2]string{"2024/cve-2024-6387.json", regenT1.Format(time.RFC3339)}),
		docs:            map[string]string{"2024/cve-2024-6387.json": staleOpensshDoc()},
	}
	s := serve(t, f)
	var progress bytes.Buffer
	p := New(Options{BaseURL: s.URL, Progress: &progress})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	archiveAt, changesAt := indexOf(reqs, "GET "+archiveName), indexOf(reqs, "GET csaf-vex/"+changesFile)
	if archiveAt < 0 || changesAt < 0 || archiveAt > changesAt {
		t.Errorf("the delta was consulted before the archive was downloaded: %v", reqs)
	}
	// The cutoff is the downloaded archive's own time, so the revision-1 row
	// (older than it) is not fetched at all.
	if n := f.hitsFor("csaf-vex/2024/cve-2024-6387.json"); n != 0 {
		t.Errorf("a document older than the downloaded archive was fetched %d times", n)
	}
	if got := fixedOn(t, got, "SUSE-CVE-2024-6387", "SLES:15.SP6"); got != "9.6p1-1.1" {
		t.Errorf("openssh fixed = %q, want the regenerated archive's 9.6p1-1.1", got)
	}
	if !prov.DataAsOf.Equal(regenT2) {
		t.Errorf("DataAsOf = %s, want the downloaded archive's %s, not the HEAD's", prov.DataAsOf, regenT2)
	}
	if !strings.Contains(progress.String(), "0 archive documents superseded") {
		t.Errorf("progress should count no superseded copy:\n%s", progress.String())
	}
}

// Even a document the delta DID fetch does not supersede an archive copy
// that is newer than it (a cached individual document behind a fresh
// archive): the archive copy is emitted after the delta's, so last write
// wins with the newer revision, and the case is counted.
func TestFetch_ArchiveCopyNewerThanTheDeltasCopyIsKept(t *testing.T) {
	f := &feed{
		archive:         fixture(t, "archive_regenerated.tar.bz2"),
		archiveModified: regenT1, // the row below is on the cutoff, so it is fetched
		changes:         changesCSV([2]string{"2024/cve-2024-6387.json", regenT1.Format(time.RFC3339)}),
		docs:            map[string]string{"2024/cve-2024-6387.json": staleOpensshDoc()},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if n := f.hitsFor("csaf-vex/2024/cve-2024-6387.json"); n != 1 {
		t.Fatalf("precondition: the delta copy was fetched %d times, want 1", n)
	}
	if got := fixedOn(t, got, "SUSE-CVE-2024-6387", "SLES:15.SP6"); got != "9.6p1-1.1" {
		t.Errorf("openssh fixed = %q, want the archive's newer 9.6p1-1.1 to be the last word", got)
	}
	if !strings.Contains(progress, "1 archive documents newer than the copy the delta fetched") {
		t.Errorf("progress does not count the archive copy that outranked the delta's:\n%s", progress)
	}
	if !strings.Contains(progress, "0 archive documents superseded") {
		t.Errorf("a newer archive copy must not be counted as superseded:\n%s", progress)
	}
}

// The control D129 must keep: a delta copy at least as new as the archive's
// still supersedes it, including when it converts to nothing.
func TestFetch_DeltaCopyAsNewAsTheArchivesStillSupersedes(t *testing.T) {
	f := &feed{
		archive:         fixture(t, "archive_regenerated.tar.bz2"),
		archiveModified: regenT1,
		changes:         changesCSV([2]string{"2024/cve-2024-6387.json", regenT2.Format(time.RFC3339)}),
		docs: map[string]string{"2024/cve-2024-6387.json": docJSONDated("CVE-2024-6387", regenT2,
			[]string{"SUSE Linux Enterprise Server 15 SP6"},
			map[string]string{"openssh-9.6p1-1.2": "pkg:rpm/suse/openssh@9.6p1-1.2?upstream=openssh-9.6p1-1.2.src.rpm"},
			[]string{"SUSE Linux Enterprise Server 15 SP6:openssh-9.6p1-1.2"})},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if got := fixedOn(t, got, "SUSE-CVE-2024-6387", "SLES:15.SP6"); got != "9.6p1-1.2" {
		t.Errorf("openssh fixed = %q, want the delta's equally-dated 9.6p1-1.2", got)
	}
	if !strings.Contains(progress, "1 archive documents superseded") || !strings.Contains(progress, "0 archive documents newer") {
		t.Errorf("progress should count one superseded copy and no newer archive copy:\n%s", progress)
	}
}
