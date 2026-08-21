package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// TestFetch_UbuntuTrackerDisabledDisclosure mirrors
// amazon.TestFetch_PrintsExtrasDisclosure: with UBUNTU_TRACKER_ENABLE off
// (the New() default), Fetch must print the disclosure line and must not
// attempt git at all -- there is no git repository anywhere near this test,
// so a build that tried would fail loudly rather than silently succeed.
func TestFetch_UbuntuTrackerDisabledDisclosure(t *testing.T) {
	body := zipWith(t, map[string]string{
		"UBUNTU-CVE-2026-9200.json": `{"id":"UBUNTU-CVE-2026-9200","upstream":["CVE-2026-9200"],
			"affected":[{"package":{"name":"openssl","ecosystem":"Ubuntu:22.04:LTS"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Ubuntu/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	var progress strings.Builder
	p := New([]string{"Ubuntu"}, srv.URL).WithProgress(&progress)
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !strings.Contains(progress.String(), "UBUNTU_TRACKER_ENABLE=0") {
		t.Errorf("progress = %q, want the disabled disclosure naming UBUNTU_TRACKER_ENABLE=0", progress.String())
	}
	if len(got) != 1 {
		t.Fatalf("Fetch emitted %d advisories, want 1", len(got))
	}
	if fs := got[0].Affected[0].Ranges[0].FixState; fs != "" {
		t.Errorf("FixState = %q, want empty -- the tracker must not be consulted when disabled", fs)
	}
}

// TestFetch_UbuntuTrackerStampsEndToEnd is the full-stack version of
// TestConvert_UbuntuIgnoredStampsWontFix: a real git clone (via
// WithUbuntuTracker(true) and the ubuntuTrackerURL/ubuntuSpoolDir test
// overrides) feeding a real OSV archive fetch, through Provider.Fetch
// exactly as `assay db build` drives it. Skipped when git is unavailable
// (requireGit, ubuntu_spool_test.go).
func TestFetch_UbuntuTrackerStampsEndToEnd(t *testing.T) {
	requireGit(t)
	src := initFixtureTrackerRepo(t)

	body := zipWith(t, map[string]string{
		"UBUNTU-CVE-2026-9100.json": `{"id":"UBUNTU-CVE-2026-9100","upstream":["CVE-2026-9100"],
			"affected":[{"package":{"name":"x","ecosystem":"Ubuntu:22.04:LTS"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Ubuntu/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	var progress strings.Builder
	p := New([]string{"Ubuntu"}, srv.URL).WithProgress(&progress).WithUbuntuTracker(true)
	p.ubuntuTrackerURL = src
	p.ubuntuSpoolDir = filepath.Join(t.TempDir(), "spool")

	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Fetch emitted %d advisories, want 1", len(got))
	}
	if fs := got[0].Affected[0].Ranges[0].FixState; fs != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q -- the real clone's jammy_x: ignored tuple must reach the finding",
			fs, advisory.FixStateWontFix)
	}
	out := progress.String()
	if !strings.Contains(out, "ubuntu tracker (D85): synced") {
		t.Errorf("progress = %q, want the sync line", out)
	}
	if !strings.Contains(out, "1 tuple(s) loaded") {
		t.Errorf("progress = %q, want it to report 1 tuple loaded", out)
	}
	if !strings.Contains(out, "1 range(s) stamped wont-fix") {
		t.Errorf("progress = %q, want it to report 1 range stamped wont-fix", out)
	}
}
