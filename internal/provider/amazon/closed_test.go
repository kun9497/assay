package amazon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// D113's Amazon half, driven through Fetch end to end: the fold is the caller,
// and a test of a "is this topic closed" helper would pass while Fetch still
// folded every repo's date.
//
// fetchedAt is the fixed fetch time Options.Now hands Fetch, so every age
// below is exact rather than relative to whenever the suite runs.
var fetchedAt = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

// at renders a fetchedAt-relative date in the feed's own layout.
func at(daysBefore int) string {
	return fetchedAt.AddDate(0, 0, -daysBefore).Format(alasDateLayout)
}

// closedFixture serves one AL2 core repo whose newest update is coreDays old
// and one extras topic, "selinux-ng", whose single update is topicDays old,
// and runs Fetch at fetchedAt.
func closedFixture(t *testing.T, coreDays, topicDays int) (prov providerResult) {
	t.Helper()
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"selinux-ng"})
	// "selng" and the core package "corepkg" share no substring with each
	// other or with either ID (CLAUDE.md's substring rule).
	mountRepo(t, mux, "/extras/selinux-ng/latest/x86_64", []updateFixture{{
		id: "ALAS2SELINUX-NG-2023-001", severity: "medium",
		issued: at(topicDays), updated: at(topicDays),
		pkgs: []pkgFixture{{name: "selng", epoch: "0", version: "3.5", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2026-900", severity: "low",
		issued: at(coreDays), updated: at(coreDays),
		pkgs: []pkgFixture{{name: "corepkg", epoch: "0", version: "1.0", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var progress strings.Builder
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
		Progress:      &progress,
		Now:           func() time.Time { return fetchedAt },
	})
	var ids []string
	got, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		ids = append(ids, a.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	prov.DataAsOf, prov.Closed, prov.Records = got.DataAsOf, got.Closed, got.Records
	prov.ids, prov.progress = ids, progress.String()
	return prov
}

type providerResult struct {
	DataAsOf time.Time
	Closed   map[string]time.Time
	Records  int
	ids      []string
	progress string
}

func daysBeforeFetch(daysBefore int) time.Time { return fetchedAt.AddDate(0, 0, -daysBefore) }

// The 2026-08-27 investigation's shape: core current, one extras topic whose
// only advisory is three years old. Before D113 the topic set the provider's
// DataAsOf — and through it the published artifact's floor.
func TestFetch_D113_AClosedExtrasTopicDoesNotSetTheFloor(t *testing.T) {
	got := closedFixture(t, 0, 3*365)

	if !got.DataAsOf.Equal(fetchedAt) {
		t.Errorf("DataAsOf = %v, want core's %v — a topic silent for three years is closed "+
			"and must not set the floor", got.DataAsOf, fetchedAt)
	}
	want := map[string]time.Time{"selinux-ng": daysBeforeFetch(3 * 365)}
	if !reflect.DeepEqual(got.Closed, want) {
		t.Errorf("Closed = %v, want %v — the exclusion must be recorded for db status, not silent",
			got.Closed, want)
	}
	// Only the DATE is excluded: the topic's advisory is still ingested,
	// because a package installed from it is still installed.
	if !containsID(got.ids, "ALAS2SELINUX-NG-2023-001") || got.Records != 2 {
		t.Errorf("emitted %v (Records %d), want the closed topic's advisory beside core's", got.ids, got.Records)
	}
	if !strings.Contains(got.progress, "1 closed (no advisory in over 730 days; not counted toward the data date)") {
		t.Errorf("the summary line does not name the closed count:\n%s", got.progress)
	}
}

// Core is never closed. If AL2 core stops publishing, the floor must fall —
// that is the failure D59 exists to catch, and the closed rule must not be
// able to hide it.
func TestFetch_D113_CoreIsNeverClosed(t *testing.T) {
	got := closedFixture(t, 3*365, 0)

	if want := daysBeforeFetch(3 * 365); !got.DataAsOf.Equal(want) {
		t.Errorf("DataAsOf = %v, want core's own %v — core is exempt from closure by construction",
			got.DataAsOf, want)
	}
	if len(got.Closed) != 0 {
		t.Errorf("Closed = %v, want none — the stale repo is core and the topic is current", got.Closed)
	}
	if !strings.Contains(got.progress, "0 closed") {
		t.Errorf("the summary line does not say nothing was closed:\n%s", got.progress)
	}
}

// The line is "more than two years": exactly 730 days still counts, 731 does
// not. A topic that has published in the last two years is a channel that may
// publish tomorrow, and its date stays in the fold.
func TestFetch_D113_ClosedBoundaryIsMoreThan730Days(t *testing.T) {
	got := closedFixture(t, 0, 730)
	if want := daysBeforeFetch(730); !got.DataAsOf.Equal(want) {
		t.Errorf("at exactly 730 days: DataAsOf = %v, want the topic's %v — not yet closed", got.DataAsOf, want)
	}
	if len(got.Closed) != 0 {
		t.Errorf("at exactly 730 days: Closed = %v, want none", got.Closed)
	}

	got = closedFixture(t, 0, 731)
	if !got.DataAsOf.Equal(fetchedAt) {
		t.Errorf("at 731 days: DataAsOf = %v, want core's %v — the topic is closed", got.DataAsOf, fetchedAt)
	}
	if _, ok := got.Closed["selinux-ng"]; !ok {
		t.Errorf("at 731 days: Closed = %v, want selinux-ng", got.Closed)
	}
}

func containsID(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
