package redhat

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// rhel9Doc is a document naming one mainline RHEL 9 package, either fixed at a
// version or affected with none.
func rhel9Doc(t *testing.T, cve, pkg, fixedEVR string) string {
	t.Helper()
	cp := map[string]string{"R": "cpe:/o:redhat:enterprise_linux:9"}
	if fixedEVR == "" {
		return docJSON(t, cve, cp, nil, []string{"R:" + pkg})
	}
	return docJSON(t, cve, cp, []string{"R:" + pkg + "-" + fixedEVR}, nil)
}

// archiveWith is the one-document archive most of these tests need under them.
func archiveWith(t *testing.T) []byte {
	t.Helper()
	return archiveOf(t, map[string]string{
		"2024/cve-2024-0001.json": rhel9Doc(t, "CVE-2024-0001", "openssh", "0:1-1.el9.x86_64"),
	})
}

// The gap this pass exists to close. A document written AFTER the archive was
// built is not in it, and on both differential runs against grype every finding
// grype had and assay did not came from exactly that.
func TestDelta_FetchesDocumentsNewerThanTheArchive(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(
			// Newer than the archive: fetched.
			[2]string{"2026/cve-2026-8458.json", "2026-08-06T03:46:10+00:00"},
			[2]string{"2026/cve-2026-18839.json", "2026-08-05T00:00:01+00:00"},
			// Older: the scan stops here, and everything below is untouched.
			[2]string{"2024/cve-2024-0001.json", "2026-08-04T23:59:59+00:00"},
			[2]string{"2020/cve-2020-1111.json", "2020-01-01T00:00:00+00:00"},
		),
		docs: map[string]string{
			"2026/cve-2026-8458.json":  rhel9Doc(t, "CVE-2026-8458", "curl", ""),
			"2026/cve-2026-18839.json": rhel9Doc(t, "CVE-2026-18839", "popt", ""),
		},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, a := range got {
		ids[a.ID] = true
	}
	// D90: emitted IDs are REDHAT-prefixed.
	for _, want := range []string{"REDHAT-CVE-2024-0001", "REDHAT-CVE-2026-8458", "REDHAT-CVE-2026-18839"} {
		if !ids[want] {
			t.Errorf("%s missing; got %v", want, ids)
		}
	}
	// The scan STOPS at the cutoff rather than reading the whole file, and the
	// rows below it are never requested. Asserted on the server's own hit
	// count, because a delta that fetched everything would still produce the
	// right advisories and be quietly 62,989 requests.
	if n := f.hitsFor("2020/cve-2020-1111.json"); n != 0 {
		t.Errorf("a document older than the archive was fetched %d times", n)
	}
	if n := f.hitsFor("2024/cve-2024-0001.json"); n != 0 {
		t.Errorf("a document already in the archive was fetched %d times", n)
	}
	if !strings.Contains(progress, "2 changed since the archive") {
		t.Errorf("progress does not account for the delta: %s", progress)
	}
}

// The newer document WINS, and since D129 it wins by being the ONLY copy
// emitted: the delta runs before the archive walk and the archive skips every
// document the delta fetched. Last-write-wins by ID had nothing to win with
// when the newer copy converted to nothing (the test after this one).
func TestDelta_TheNewerDocumentReplacesTheArchivesCopy(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveOf(t, map[string]string{
			"2026/cve-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "openssh", "0:1-1.el9.x86_64"),
		}),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", "2026-08-06T00:00:00+00:00"}),
		docs: map[string]string{
			"2026/cve-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "openssh", "0:2-2.el9.x86_64"),
		},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d advisories, want only the delta's copy: %+v", len(got), got)
	}
	ev := got[0].Affected[0].Ranges[0].Events
	if got[0].ID != "REDHAT-CVE-2026-0001" || ev[1].Fixed != "0:2-2.el9" {
		t.Errorf("the surviving copy is the archive's (fixed=%q), want the delta's 0:2-2.el9", ev[1].Fixed)
	}
	if !strings.Contains(progress, "1 archive documents superseded by a newer copy the delta fetched (D129)") {
		t.Errorf("progress does not account for the superseded archive copy:\n%s", progress)
	}
}

// D129's reason to exist (external review #5): Red Hat corrected a document to
// nothing affected -- no fixed, no known_affected -- and before D129 the delta
// emitted nothing for it, so the archive's stale affected range stood until the
// archive was regenerated, about two days.
func TestDelta_CorrectionToNothingAffectedLeavesNoRecord(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveOf(t, map[string]string{
			"2026/cve-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "openssh", ""),
			// A second document, untouched by the delta, so the D20 coverage
			// guard has a record to count -- the correction must not be the
			// only thing the archive held.
			"2024/cve-2024-0001.json": rhel9Doc(t, "CVE-2024-0001", "curl", "0:1-1.el9.x86_64"),
		}),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", "2026-08-06T00:00:00+00:00"}),
		docs: map[string]string{
			"2026/cve-2026-0001.json": docJSON(t, "CVE-2026-0001", map[string]string{"R": "cpe:/o:redhat:enterprise_linux:9"}, nil, nil),
		},
	}
	got, _, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range got {
		if a.ID == "REDHAT-CVE-2026-0001" {
			t.Fatalf("the archive's record survived the correction to nothing affected: %+v", a.Affected)
		}
	}
}

// The supersede key is the document's own CVE, not its file name: an archive
// entry spelled differently from the changes.csv row (another year directory,
// upper case) is still skipped. Keyed on a file name, that drift would have
// made the walk emit the archive's stale copy AFTER the delta's -- the one
// failure the old order could not have (D129's review).
func TestDelta_SupersedeIsByDocumentIDNotFileName(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveOf(t, map[string]string{
			"2025/CVE-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "openssh", "0:1-1.el9.x86_64"),
		}),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", "2026-08-06T00:00:00+00:00"}),
		docs: map[string]string{
			"2026/cve-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "openssh", "0:2-2.el9.x86_64"),
		},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Affected[0].Ranges[0].Events[1].Fixed != "0:2-2.el9" {
		t.Fatalf("emitted %+v, want only the delta's copy: the respelled archive entry was not recognised as the same document", got)
	}
	if !strings.Contains(progress, "1 archive documents superseded") {
		t.Errorf("progress does not count the superseded copy:\n%s", progress)
	}
}

// The other direction: a document the delta listed but could not fetch keeps
// its archive copy. Superseding on the listing alone would drop a live advisory
// for a night on every transient 404.
func TestDelta_GoneDocumentKeepsTheArchivesCopy(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveOf(t, map[string]string{
			"2026/cve-2026-0001.json": rhel9Doc(t, "CVE-2026-0001", "openssh", "0:1-1.el9.x86_64"),
		}),
		changes: changesCSV([2]string{"2026/cve-2026-0001.json", "2026-08-06T00:00:00+00:00"}),
		// Listed, not served.
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "REDHAT-CVE-2026-0001" {
		t.Fatalf("the archive's record was dropped for a document the delta could not fetch: %+v", got)
	}
	if !strings.Contains(progress, "1 already withdrawn") || !strings.Contains(progress, "0 archive documents superseded") {
		t.Errorf("progress should count the gone document and no superseded copy:\n%s", progress)
	}
}

// A document listed in changes.csv and no longer served is a race between two
// files Red Hat writes separately, not a fault. It is counted and the build
// continues.
func TestDelta_WithdrawnDocumentIsCountedNotFatal(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(
			[2]string{"2026/cve-2026-0002.json", "2026-08-06T00:00:00+00:00"},
			[2]string{"2026/cve-2026-0003.json", "2026-08-06T00:00:00+00:00"},
		),
		docs: map[string]string{
			"2026/cve-2026-0003.json": rhel9Doc(t, "CVE-2026-0003", "curl", ""),
		},
	}
	got, progress, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatalf("a withdrawn document failed the build: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("emitted %d advisories, want the archive's and the one still published", len(got))
	}
	if !strings.Contains(progress, "1 already withdrawn") {
		t.Errorf("progress does not count the withdrawn document: %s", progress)
	}
}

// Everything that is NOT a 404 fails the build. This pass exists to close a
// known gap, and one that quietly closed part of it would leave the database
// looking complete while sitting somewhere in between.
func TestDelta_AnythingButA404IsFatal(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV([2]string{"2026/cve-2026-0004.json", "2026-08-06T00:00:00+00:00"}),
		docs:    map[string]string{"2026/cve-2026-0004.json": "{not json"},
	}
	if _, _, err := fetchAll(t, serve(t, f)); err == nil {
		t.Fatal("an unparseable delta document was accepted")
	} else if !strings.Contains(err.Error(), "cve-2026-0004") {
		t.Errorf("error = %v, want it to name the document", err)
	}
}

// A 5xx is NOT a withdrawal. Without this the only fatal case tested was an
// unparseable body, which the JSON decoder catches on its own — so a status
// check that treated every non-200 as "no longer published" survived, and a
// feed having a bad afternoon would have produced a quietly short database.
func TestDelta_AServerErrorIsFatal(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV([2]string{"2026/cve-2026-0008.json", "2026-08-06T00:00:00+00:00"}),
		status:  map[string]int{"2026/cve-2026-0008.json": 500},
	}
	_, progress, err := fetchAll(t, serve(t, f))
	if err == nil {
		t.Fatal("a 500 was treated as a withdrawal")
	}
	if !strings.Contains(err.Error(), "cve-2026-0008") {
		t.Errorf("error = %v, want it to name the document", err)
	}
	if strings.Contains(progress, "1 already withdrawn") {
		t.Errorf("a 500 was counted as a withdrawal: %s", progress)
	}
}

// changes.csv is sorted newest first, and the early exit depends on it. A file
// that arrived in another order would otherwise stop after one row and produce
// a silently short delta — the same shape of miss this whole pass closes.
func TestDelta_RefusesAnUnsortedChangesFile(t *testing.T) {
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(
			[2]string{"2026/cve-2026-0005.json", "2026-08-06T00:00:00+00:00"},
			[2]string{"2026/cve-2026-0006.json", "2026-08-07T00:00:00+00:00"},
		),
	}
	if _, _, err := fetchAll(t, serve(t, f)); err == nil {
		t.Fatal("an unsorted changes.csv was accepted")
	} else if !strings.Contains(err.Error(), "not sorted") {
		t.Errorf("error = %v, want it to name the ordering", err)
	}
}

// A row whose path becomes a URL is validated for the pointer file's reason.
func TestDelta_RefusesABadPath(t *testing.T) {
	for _, bad := range []string{
		"../../../etc/passwd",
		"https://example.invalid/cve-2026-0007.json",
		"2026/cve-2026-0007.json.txt",
		"cve-2026-0007.json",
	} {
		t.Run(bad, func(t *testing.T) {
			f := &feed{
				pointer: "csaf_vex_2026-08-05.tar.zst",
				archive: archiveWith(t),
				changes: changesCSV([2]string{bad, "2026-08-06T00:00:00+00:00"}),
			}
			if _, _, err := fetchAll(t, serve(t, f)); err == nil {
				t.Errorf("path %q was accepted", bad)
			} else if !strings.Contains(err.Error(), "not a document path") {
				t.Errorf("error = %v, want it to name the validation", err)
			}
		})
	}
}

// overlargeChanges lists one more document than maxDelta, all changed the day
// after the 2026-08-05 archive the tests below serve.
func overlargeChanges() [][2]string {
	rows := make([][2]string, 0, maxDelta+1)
	for i := 0; i <= maxDelta; i++ {
		rows = append(rows, [2]string{
			"2026/cve-2026-" + strconv.Itoa(100000-i) + ".json", "2026-08-06T00:00:00+00:00",
		})
	}
	return rows
}

// An overlarge delta behind an archive older than maxArchiveAge is an archive
// that has stopped being rebuilt: an error rather than an hour of
// one-at-a-time requests, and not one request is made before it. The clock
// is one second past the boundary, so this is also where the boundary is.
func TestDelta_RefusesAnOverlargeDeltaBehindAStaleArchive(t *testing.T) {
	rows := overlargeChanges()
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(rows...),
	}
	stale := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC).Add(maxArchiveAge + time.Second)
	_, _, err := fetchAllAt(t, serve(t, f), stale)
	if err == nil {
		t.Fatal("an overlarge delta behind a stale archive was accepted")
	}
	// 21 days and a second is printed as 22 days old: the message rounds up
	// so it never reads "21 days old, past ... 21 days" (review).
	for _, want := range []string{"20001 documents have changed", "22 days old", "stopped being rebuilt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to say %q", err, want)
		}
	}
	if n := f.hitsFor(rows[0][0]); n != 0 {
		t.Errorf("the first listed document was fetched %d times before the refusal", n)
	}
}

// QA 2026-11-06: the same delta behind an archive exactly maxArchiveAge old
// is a regenerated corpus (Red Hat rewrote 20,514 documents on 2026-11-05
// behind a five-day-old archive), and is fetched. The run is cancelled on the
// first advisory the delta emits, so the test's cost is one document rather
// than 20,001; what it holds is that the fetch BEGAN and the progress line
// said why, where the count alone had refused.
func TestDelta_FetchesAnOverlargeDeltaBehindAFreshArchive(t *testing.T) {
	// Two clocks: the boundary itself, and the 2026-11-05 shape (a five-day
	// -old archive), whose printed age is not the constant's 21 -- so a
	// progress line that printed the limit instead of the age would fail.
	for _, c := range []struct {
		name string
		age  time.Duration
		days string
	}{
		{"exactly 21 days old", maxArchiveAge, "21 days old"},
		{"five days old", 5 * 24 * time.Hour, "5 days old"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rows := overlargeChanges()
			f := &feed{
				pointer: "csaf_vex_2026-08-05.tar.zst",
				archive: archiveWith(t),
				changes: changesCSV(rows...),
				// Only the first listed document is served; the rest would
				// 404 as withdrawn, and the cancellation below means they
				// are never asked.
				docs: map[string]string{rows[0][0]: rhel9Doc(t, "CVE-2026-100000", "curl", "")},
			}
			s := serve(t, f)
			var progress bytes.Buffer
			p := New(Options{BaseURL: s.URL, Progress: &progress})
			p.now = func() time.Time { return time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC).Add(c.age) }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			emitted := 0
			_, err := p.Fetch(ctx, func(advisory.Advisory) error {
				emitted++
				cancel()
				return nil
			})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want the cancellation -- an overlarge delta behind a fresh archive must be fetched, not refused", err)
			}
			// The delta runs before the archive walk (D129), so the one
			// advisory is the delta's, and the server saw the request that
			// produced it.
			if emitted != 1 || f.hitsFor(rows[0][0]) != 1 {
				t.Errorf("emitted %d advisories and fetched the first listed document %d times, want 1 and 1",
					emitted, f.hitsFor(rows[0][0]))
			}
			want := "redhat: 20001 documents have changed since the 2026-08-05 archive was built, past the 20000 a delta " +
				"usually holds, but that archive is " + c.days + " and still being rebuilt, so they are fetched one at a time"
			if !strings.Contains(progress.String(), want) {
				t.Errorf("progress lacks the line saying why an overlarge delta was fetched:\n%s", progress.String())
			}
		})
	}
}

// The delta honours cancellation. A stale archive can mean thousands of
// requests, so this is the difference between Ctrl-C working and not.
func TestDelta_HonoursCancellation(t *testing.T) {
	rows := make([][2]string, 0, 50)
	docs := map[string]string{}
	for i := 0; i < 50; i++ {
		p := "2026/cve-2026-" + strconv.Itoa(21000+i) + ".json"
		rows = append(rows, [2]string{p, "2026-08-06T00:00:00+00:00"})
		docs[p] = rhel9Doc(t, "CVE-2026-"+strconv.Itoa(21000+i), "curl", "")
	}
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(rows...),
		docs:    docs,
	}
	s := serve(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	// Cancel on the SECOND advisory. The first is the archive's, so by then
	// the archive walk has finished and only the delta's own ctx.Err() check
	// can stop what follows. Cancelling on the first would be caught by the
	// archive loop and would leave the delta's check untested — which is
	// exactly what this test did before.
	_, err := New(Options{BaseURL: s.URL}).Fetch(ctx, func(advisory.Advisory) error {
		emitted++
		if emitted == 2 {
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("a cancelled delta ran to completion")
	}
	if emitted > 3 {
		t.Errorf("kept emitting after cancellation: %d of %d", emitted, len(docs))
	}
}

// Documents are fetched concurrently and emitted IN ORDER, and this is what
// makes that testable: the first document is held back long enough that the
// two behind it certainly finish first. An implementation that emitted results
// as they arrived would put them the other way round — and since the store's
// last-write-wins is what makes a re-emitted advisory replace its own record,
// a document changes.csv lists twice would survive as whichever request was
// quickest. Since D129 the delta is emitted BEFORE the archive walk, so the
// archive's own record comes last.
func TestDelta_EmitsInOrderDespiteConcurrency(t *testing.T) {
	order := []string{"2026/cve-2026-3001.json", "2026/cve-2026-3002.json", "2026/cve-2026-3003.json"}
	rows := make([][2]string, 0, len(order))
	docs := map[string]string{}
	for i, p := range order {
		rows = append(rows, [2]string{p, "2026-08-06T00:00:0" + strconv.Itoa(i) + "+00:00"})
		docs[p] = rhel9Doc(t, "CVE-2026-300"+strconv.Itoa(i+1), "curl", "")
	}
	// Descending, as the real file is.
	rows[0], rows[2] = rows[2], rows[0]
	first := rows[0][0]
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(rows...),
		docs:    docs,
		delay:   map[string]time.Duration{first: 300 * time.Millisecond},
	}
	got, _, err := fetchAll(t, serve(t, f))
	if err != nil {
		t.Fatal(err)
	}
	// The delta's advisories in changes.csv order, then the archive's (D129).
	var ids []string
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	// D90: emitted IDs are REDHAT-prefixed.
	want := []string{"REDHAT-CVE-2026-3003", "REDHAT-CVE-2026-3002", "REDHAT-CVE-2026-3001", "REDHAT-CVE-2024-0001"}
	if len(ids) != len(want) {
		t.Fatalf("emitted %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("emitted %v, want %v — the delayed document must still come first", ids, want)
		}
	}
}

// Concurrency must not cost cancellation. A stale archive can mean thousands
// of requests, and stopping has to stop the ones in flight too.
func TestDelta_CancellationStopsTheConcurrentFetches(t *testing.T) {
	rows := make([][2]string, 0, 200)
	docs := map[string]string{}
	for i := 0; i < 200; i++ {
		p := "2026/cve-2026-" + strconv.Itoa(41000+i) + ".json"
		rows = append(rows, [2]string{p, "2026-08-06T00:00:00+00:00"})
		docs[p] = rhel9Doc(t, "CVE-2026-"+strconv.Itoa(41000+i), "curl", "")
	}
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(rows...),
		docs:    docs,
	}
	s := serve(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	// Cancel on the SECOND advisory: the first is the archive's, so by then the
	// archive walk has finished and only the delta can be stopped.
	_, err := New(Options{BaseURL: s.URL}).Fetch(ctx, func(advisory.Advisory) error {
		emitted++
		if emitted == 2 {
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("a cancelled delta ran to completion")
	}
	// A few may already be in flight and land, but not two hundred.
	if emitted > deltaWorkers+2 {
		t.Errorf("kept emitting after cancellation: %d of %d", emitted, len(docs))
	}
}

// Cancelling must not leave the producer wedged. It blocks handing out
// semaphore tokens once deltaWorkers are outstanding, and if it stopped
// watching for cancellation it would sit there forever holding the path list
// and every slot channel — a leak rather than a wrong answer, which is exactly
// why nothing else here catches it.
func TestDelta_CancellationLeavesNoGoroutineBehind(t *testing.T) {
	rows := make([][2]string, 0, 400)
	docs := map[string]string{}
	for i := 0; i < 400; i++ {
		p := "2026/cve-2026-" + strconv.Itoa(51000+i) + ".json"
		rows = append(rows, [2]string{p, "2026-08-06T00:00:00+00:00"})
		docs[p] = rhel9Doc(t, "CVE-2026-"+strconv.Itoa(51000+i), "curl", "")
	}
	f := &feed{
		pointer: "csaf_vex_2026-08-05.tar.zst",
		archive: archiveWith(t),
		changes: changesCSV(rows...),
		docs:    docs,
		// Slow enough that the workers are certainly all busy, and the
		// producer certainly blocked, when the cancel lands.
		delay: map[string]time.Duration{},
	}
	for p := range docs {
		f.delay[p] = 40 * time.Millisecond
	}
	s := serve(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	_, err := New(Options{BaseURL: s.URL}).Fetch(ctx, func(advisory.Advisory) error {
		emitted++
		if emitted == 2 {
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("a cancelled delta ran to completion")
	}

	// The stack is searched for THIS function's producer goroutine by name
	// rather than the total being counted: net/http keeps idle-connection
	// goroutines of its own, so a count is noisy in the direction that fails a
	// correct implementation — it did, at 9 against 3, before this was written
	// this way.
	//
	// Polled, because the in-flight fetches are still unwinding when Fetch
	// returns.
	const producer = "eachDocument.func1"
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		dump := string(buf[:runtime.Stack(buf, true)])
		if !strings.Contains(dump, producer) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is still running after cancellation; it is waiting for a semaphore "+
				"token nobody will return", producer)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
