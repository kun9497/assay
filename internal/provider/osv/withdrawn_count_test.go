package osv

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// The osv: progress line a build prints names how many records each
// ecosystem lost to D16's withdrawn drop, so a collapsed key (Echo:Go
// 285 -> 2 on 2026-11-15) reads as an upstream withdrawal from the log of
// the build that saw it. Driven through Fetch: the count is the caller's.
func TestFetch_ProgressNamesWithdrawnPerEcosystem(t *testing.T) {
	rec := func(id, eco, withdrawn string) string {
		w := ""
		if withdrawn != "" {
			w = `"withdrawn":"` + withdrawn + `",`
		}
		return `{"id":"` + id + `",` + w + `"affected":[{"package":{"name":"x","ecosystem":"` + eco + `"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`
	}
	body := zipWith(t, map[string]string{
		"ECHO-a.json": rec("ECHO-a", "Echo:Go", "2026-11-12T08:00:07Z"),
		"ECHO-b.json": rec("ECHO-b", "Echo:Go", "2026-11-12T08:00:07Z"),
		"ECHO-c.json": rec("ECHO-c", "Echo:npm", "2026-11-12T08:00:07Z"),
		"ECHO-d.json": rec("ECHO-d", "Echo:Go", ""),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Mon, 16 Nov 2026 00:00:00 GMT")
		w.Write(body)
	}))
	defer srv.Close()
	p := New([]string{"Echo"}, srv.URL)
	var progress bytes.Buffer
	p.progress = &progress
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ECHO-d" {
		t.Fatalf("emitted %v, want only ECHO-d", got)
	}
	if want := "withdrawn (D16) by affected ecosystem: Echo:Go 2, Echo:npm 1"; !strings.Contains(progress.String(), want) {
		t.Errorf("progress lacks %q:\n%s", want, progress.String())
	}
}

func TestStats_WithdrawnSummaryNone(t *testing.T) {
	if got := (stats{}).withdrawnSummary(); got != "none" {
		t.Errorf("withdrawnSummary of nothing = %q, want none", got)
	}
	aff := func(ecos ...string) []rawAffected {
		var out []rawAffected
		for _, e := range ecos {
			var a rawAffected
			a.Package.Ecosystem, a.Package.Name = e, "pkg"
			out = append(out, a)
		}
		return out
	}
	var st stats
	// One record, three entries: two of npm count once; PyPI belongs to
	// another archive; an Ubuntu lineage key is never indexed.
	st.countWithdrawn(aff("npm", "npm", "PyPI", "Ubuntu:Pro:18.04:LTS"), "npm")
	st.countWithdrawn(aff("npm", "npm", "PyPI", "Ubuntu:Pro:18.04:LTS"), "PyPI")
	st.countWithdrawn(aff("Packagist:https://packages.drupal.org/8"), "Packagist")
	// The Ubuntu archive: mainline counts, a lineage key never indexed does
	// not, though familyMatches ties both to the family.
	st.countWithdrawn(aff("Ubuntu:22.04:LTS", "Ubuntu:Pro:18.04:LTS"), "Ubuntu")
	if got, want := st.withdrawnSummary(), "Packagist 1, PyPI 1, Ubuntu:22.04:LTS 1, npm 1"; got != want {
		t.Errorf("withdrawnSummary = %q, want %q", got, want)
	}
	var empty stats
	empty.countWithdrawn([]rawAffected{{}}, "")
	if len(empty.Withdrawn) != 0 {
		t.Errorf("a nameless entry counted: %v", empty.Withdrawn)
	}
}

// Through convert: a withdrawn MAL-* or ALBA record is no lost advisory --
// D15 and D72 drop them live too -- so it is not counted.
func TestConvert_WithdrawnCountSkipsRecordsNeverStored(t *testing.T) {
	var st stats
	for _, rec := range []string{
		`{"id":"MAL-2025-1","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"evil","ecosystem":"npm"},"versions":["1.0.0"]}]}`,
		`{"id":"ALBA-2024:1","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"x","ecosystem":"AlmaLinux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`,
		`{"id":"GHSA-real","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"name":"ok","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`,
	} {
		want := "npm"
		if strings.Contains(rec, "AlmaLinux") {
			want = "AlmaLinux"
		}
		if _, ok, err := convert([]byte(rec), want, &st, nil); ok || err != nil {
			t.Fatalf("convert(%s) = ok %v, err %v; want dropped", rec, ok, err)
		}
	}
	if got := st.withdrawnSummary(); got != "npm 1" {
		t.Errorf("withdrawnSummary = %q, want npm 1 (the GHSA only)", got)
	}
}
