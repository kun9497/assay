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
}

// Through convert: a withdrawn record counts under each key the live path
// would have stored it under, and nowhere else -- one record in the npm and
// PyPI archives once per key, Packagist folded, an Ubuntu lineage key, a
// nameless entry, MAL-*, ALBA, an Echo sentinel-only entry and a GIT-only
// range not at all.
func TestConvert_WithdrawnCountsOnlyKeysTheRecordWouldHaveFilled(t *testing.T) {
	const w = `"withdrawn":"2026-01-01T00:00:00Z",`
	rng := `"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]`
	ent := func(eco, name string) string {
		return `{"package":{"name":"` + name + `","ecosystem":"` + eco + `"},` + rng + `}`
	}
	var st stats
	for _, c := range []struct{ rec, want string }{
		{`{"id":"GHSA-two",` + w + `"affected":[` + ent("npm", "a") + `,` + ent("npm", "b") + `,` + ent("PyPI", "c") + `]}`, "npm"},
		{`{"id":"GHSA-two",` + w + `"affected":[` + ent("npm", "a") + `,` + ent("npm", "b") + `,` + ent("PyPI", "c") + `]}`, "PyPI"},
		{`{"id":"GHSA-drupal",` + w + `"affected":[` + ent("Packagist:https://packages.drupal.org/8", "drupal/x") + `]}`, "Packagist"},
		{`{"id":"UBUNTU-CVE-2026-1",` + w + `"affected":[` + ent("Ubuntu:22.04:LTS", "a") + `,` + ent("Ubuntu:Pro:18.04:LTS", "a") + `]}`, "Ubuntu"},
		{`{"id":"GHSA-noname",` + w + `"affected":[` + ent("Go", "") + `]}`, "Go"},
		{`{"id":"MAL-2025-1",` + w + `"affected":[{"package":{"name":"evil","ecosystem":"npm"},"versions":["1.0.0"]}]}`, "npm"},
		{`{"id":"ALBA-2024:1",` + w + `"affected":[` + ent("AlmaLinux:9", "x") + `]}`, "AlmaLinux"},
		{`{"id":"ECHO-s",` + w + `"affected":[{"package":{"name":"linux","ecosystem":"Echo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1"}]}]}]}`, "Echo"},
		{`{"id":"GHSA-git",` + w + `"affected":[{"package":{"name":"g","ecosystem":"Go"},"ranges":[{"type":"GIT","repo":"https://x","events":[{"introduced":"0"},{"fixed":"abc"}]}]}]}`, "Go"},
	} {
		if _, ok, err := convert([]byte(c.rec), c.want, &st, nil); ok || err != nil {
			t.Fatalf("convert(%s) = ok %v, err %v; want dropped", c.rec, ok, err)
		}
	}
	if got, want := st.withdrawnSummary(), "Packagist 1, PyPI 1, Ubuntu:22.04:LTS 1, npm 1"; got != want {
		t.Errorf("withdrawnSummary = %q, want %q", got, want)
	}
}
