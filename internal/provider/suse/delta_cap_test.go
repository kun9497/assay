package suse

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// QA 2026-11-06: the delta cap is decided by the archive's age, mirroring
// redhat's TestDelta_RefusesAnOverlargeDeltaBehindAStaleArchive and
// TestDelta_FetchesAnOverlargeDeltaBehindAFreshArchive. The cutoff here is
// the archive's Last-Modified (archiveBuilt2026) rather than a date in its
// name, so the clock is pinned relative to that.

// fetchAllAt is fetchAll with the provider's clock pinned to now, which is
// what the archive-age guard reads.
func fetchAllAt(t *testing.T, s *httptest.Server, now time.Time) ([]advisory.Advisory, string, error) {
	t.Helper()
	var progress bytes.Buffer
	p := New(Options{BaseURL: s.URL, Progress: &progress})
	p.now = func() time.Time { return now }
	var got []advisory.Advisory
	_, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	return got, progress.String(), err
}

// overlargeChanges lists one more document than maxDelta, all changed an hour
// after the fixture archive's Last-Modified.
func overlargeChanges() [][2]string {
	rows := make([][2]string, 0, maxDelta+1)
	when := archiveBuilt2026.Add(time.Hour).Format(time.RFC3339)
	for i := 0; i <= maxDelta; i++ {
		rows = append(rows, [2]string{"2026/cve-2026-" + strconv.Itoa(100000-i) + ".json", when})
	}
	return rows
}

func TestFetch_RefusesAnOverlargeDeltaBehindAStaleArchive(t *testing.T) {
	rows := overlargeChanges()
	f := &feed{
		archive:         fixture(t, "archive.tar.bz2"),
		archiveModified: archiveBuilt2026,
		changes:         changesCSV(rows...),
	}
	_, _, err := fetchAllAt(t, serve(t, f), archiveBuilt2026.Add(maxArchiveAge+time.Second))
	if err == nil {
		t.Fatal("an overlarge delta behind a stale archive was accepted")
	}
	// 21 days and a second is printed as 22 days old (rounded up, as redhat's).
	for _, want := range []string{"20001 documents have changed", "22 days old", "stopped being rebuilt"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to say %q", err, want)
		}
	}
	if n := f.hitsFor("csaf-vex/" + rows[0][0]); n != 0 {
		t.Errorf("the first listed document was fetched %d times before the refusal", n)
	}
}

func TestFetch_FetchesAnOverlargeDeltaBehindAFreshArchive(t *testing.T) {
	// The boundary itself and a five-day-old archive, as redhat's test: the
	// second clock's printed age is not the constant's 21.
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
				archive:         fixture(t, "archive.tar.bz2"),
				archiveModified: archiveBuilt2026,
				changes:         changesCSV(rows...),
				docs: map[string]string{rows[0][0]: docJSONForTest("CVE-2026-100000",
					[]string{"openSUSE Leap 15.6"},
					map[string]string{"newpkg-1.0-1.1": "pkg:rpm/suse/newpkg@1.0-1.1?upstream=newpkg-1.0-1.1.src.rpm"},
					[]string{"openSUSE Leap 15.6:newpkg-1.0-1.1"}, nil)},
			}
			s := serve(t, f)
			var progress bytes.Buffer
			p := New(Options{BaseURL: s.URL, Progress: &progress})
			p.now = func() time.Time { return archiveBuilt2026.Add(c.age) }
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
			if emitted != 1 || f.hitsFor("csaf-vex/"+rows[0][0]) != 1 {
				t.Errorf("emitted %d advisories and fetched the first listed document %d times, want 1 and 1",
					emitted, f.hitsFor("csaf-vex/"+rows[0][0]))
			}
			want := "suse: 20001 documents have changed since the 2026-08-19 archive was built, past the 20000 a delta " +
				"usually holds, but that archive is " + c.days + " and still being rebuilt, so they are fetched one at a time"
			if !strings.Contains(progress.String(), want) {
				t.Errorf("progress lacks the line saying why an overlarge delta was fetched:\n%s", progress.String())
			}
		})
	}
}
