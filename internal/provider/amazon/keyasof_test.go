package amazon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// D113 revised (2026-11-09): each release is dated by its own repositories
// (Provenance.KeyAsOf). The provider's DataAsOf stays the stalest active
// repository -- on the 2026-11-09 artifact that is one quiet AL2 extras
// topic's 2025-03-06 -- and
// attributing it to Amazon Linux:2023 refused every AL2023 image scan under a
// freshness gate for a date that was not its data's.
func TestFetch_KeyAsOfDatesEachReleaseByItsOwnRepositories(t *testing.T) {
	mux := http.NewServeMux()
	mountRepo(t, mux, "/stale", []updateFixture{{
		id: "ALAS2-2026-0002", title: "stale repo update",
		issued: "2026-01-05 10:00:00", updated: "2026-01-06 11:00:00",
		severity: "important",
		pkgs:     []pkgFixture{{name: "curl", epoch: "0", version: "7.0", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/fresh", []updateFixture{{
		id: "ALAS2023-2026-0003", title: "fresh repo update",
		issued: "2026-06-01 10:00:00", updated: "2026-06-02 11:00:00",
		severity: "important",
		pkgs:     []pkgFixture{{name: "openssl", epoch: "0", version: "3.0", release: "1.amzn2023"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos: []Repo{
			{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/stale/mirror.list"},
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/fresh/mirror.list"},
		},
		ExtrasBaseURL: quietExtrasServer(t),
	})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	stale := time.Date(2026, 1, 6, 11, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 6, 2, 11, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(stale) {
		t.Errorf("DataAsOf = %v, want the stalest repository's %v, unchanged by the revision", prov.DataAsOf, stale)
	}
	if got := prov.KeyAsOf["Amazon Linux:2"]; !got.Equal(stale) {
		t.Errorf("KeyAsOf[Amazon Linux:2] = %v, want %v", got, stale)
	}
	if got := prov.KeyAsOf["Amazon Linux:2023"]; !got.Equal(fresh) {
		t.Errorf("KeyAsOf[Amazon Linux:2023] = %v, want its own repository's %v, not AL2's", got, fresh)
	}
}

// A closed extras topic (D113) dates neither the provider nor its release:
// the fixture's AL2 core is current and its one topic three years quiet, so
// Amazon Linux:2's own date is core's.
func TestFetch_KeyAsOfLeavesAClosedTopicOut(t *testing.T) {
	got := closedFixture(t, 0, 3*365)
	if at, ok := got.KeyAsOf["Amazon Linux:2"]; !ok || !at.Equal(fetchedAt) {
		t.Errorf("KeyAsOf[Amazon Linux:2] = %v (present %v), want core's %v -- the closed topic must not date the release",
			at, ok, fetchedAt)
	}
}

// A release one of whose repositories carried no date is left out of KeyAsOf:
// AL2's core is dated here and one AL2 extras topic ships an update with no
// <issued>/<updated>, so Amazon Linux:2 reads as the provider's (unknown)
// date rather than as core's -- the same "unknown, not min(known)" rule
// DataAsOf follows.
func TestFetch_KeyAsOfLeavesAReleaseWithAnUndatedRepositoryOut(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"selinux-ng"})
	mountRepo(t, mux, "/extras/selinux-ng/latest/x86_64", []updateFixture{{
		id: "ALAS2SELINUX-NG-2026-002", severity: "medium",
		// no issued, no updated: an undated repository
		pkgs: []pkgFixture{{name: "selng", epoch: "0", version: "3.6", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2026-901", severity: "low",
		issued: at(1), updated: at(1),
		pkgs: []pkgFixture{{name: "corepkg", epoch: "0", version: "1.1", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
		Now:           func() time.Time { return fetchedAt },
	})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !prov.DataAsOf.IsZero() {
		t.Errorf("DataAsOf = %v, want zero: one repository could not be dated", prov.DataAsOf)
	}
	if at, ok := prov.KeyAsOf["Amazon Linux:2"]; ok {
		t.Errorf("KeyAsOf[Amazon Linux:2] = %v, want it absent: one of the release's repositories carried no date", at)
	}
}

// The order the repositories arrive in must not matter: here the release's
// CORE repository is the undated one and a dated extras topic follows it, so
// the release stays out of KeyAsOf even though a dated repository came last.
func TestFetch_KeyAsOfStaysOutOnceAnyRepositoryOfTheReleaseWasUndated(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"selinux-ng"})
	mountRepo(t, mux, "/extras/selinux-ng/latest/x86_64", []updateFixture{{
		id: "ALAS2SELINUX-NG-2026-003", severity: "medium",
		issued: at(2), updated: at(2),
		pkgs: []pkgFixture{{name: "selng", epoch: "0", version: "3.7", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2026-902", severity: "low",
		// no issued, no updated: the core repository is the undated one
		pkgs: []pkgFixture{{name: "corepkg", epoch: "0", version: "1.2", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
		Now:           func() time.Time { return fetchedAt },
	})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if at, ok := prov.KeyAsOf["Amazon Linux:2"]; ok {
		t.Errorf("KeyAsOf[Amazon Linux:2] = %v, want it absent: the undated core came first and the dated topic must not re-date the release", at)
	}
}

// Within one release the stalest active repository wins, as DataAsOf's own
// fold does across the provider: a current core beside an extras topic 400
// days quiet (open -- closure is at two years) dates Amazon Linux:2 by the
// topic, because the release's data is only as fresh as its least current
// channel.
func TestFetch_KeyAsOfIsTheStalestActiveRepositoryOfTheRelease(t *testing.T) {
	got := closedFixture(t, 0, 400)
	want := daysBeforeFetch(400)
	if at, ok := got.KeyAsOf["Amazon Linux:2"]; !ok || !at.Equal(want) {
		t.Errorf("KeyAsOf[Amazon Linux:2] = %v (present %v), want the open topic's %v, not core's %v",
			at, ok, want, fetchedAt)
	}
	if !got.DataAsOf.Equal(want) {
		t.Errorf("DataAsOf = %v, want %v: the same topic sets the provider's floor", got.DataAsOf, want)
	}
}
