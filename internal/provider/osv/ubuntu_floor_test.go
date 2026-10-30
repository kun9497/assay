package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/store"
)

// trackerRepo is initFixtureTrackerRepo with the files given, for layouts the
// standard one-file fixture cannot express.
func trackerRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "src")
	for name, body := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "--initial-branch=master"},
		{"-c", "user.name=assay-test", "-c", "user.email=assay-test@example.invalid", "add", "-A"},
		{"-c", "user.name=assay-test", "-c", "user.email=assay-test@example.invalid", "commit", "-m", "seed"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return src
}

// fetchUbuntuWith runs Provider.Fetch over a one-record Ubuntu archive (a
// fix-less range for package x on jammy) against the given tracker clone.
func fetchUbuntuWith(t *testing.T, tracker string) (store.Provenance, string, error) {
	prov, progress, _, err := fetchUbuntuCounting(t, tracker)
	return prov, progress, err
}

// fetchUbuntuCounting is fetchUbuntuWith, also counting the archive requests.
func fetchUbuntuCounting(t *testing.T, tracker string) (store.Provenance, string, int, error) {
	t.Helper()
	body := zipWith(t, map[string]string{
		"UBUNTU-CVE-2026-9100.json": `{"id":"UBUNTU-CVE-2026-9100","upstream":["CVE-2026-9100"],
			"affected":[{"package":{"name":"x","ecosystem":"Ubuntu:22.04:LTS"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}`,
	})
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Ubuntu/all.zip" {
			http.NotFound(w, r)
			return
		}
		hits++
		w.Write(body)
	}))
	defer srv.Close()
	var progress strings.Builder
	p := New([]string{"Ubuntu"}, srv.URL).WithProgress(&progress).WithUbuntuTracker(true)
	p.ubuntuTrackerURL = tracker
	p.ubuntuSpoolDir = filepath.Join(t.TempDir(), "spool")
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	return prov, progress.String(), hits, err
}

// D157 (audit A15, revising D85): a tracker clone that parses to nothing --
// Canonical moving active/ and retired/, or respelling the Candidate: header
// -- was accepted with a progress line, and every Ubuntu wont-fix and
// not-fixed state (2,094,636 ranges in the 2026-10-29 nightly) silently became
// unknown in the published artifact. Zero is never a real tracker: the build
// fails, naming the count and the switch that builds without fix states on
// purpose.
func TestFetch_D157_ATrackerThatParsesToNothingFailsTheBuild(t *testing.T) {
	requireGit(t)
	for name, files := range map[string]map[string]string{
		"layout moved":     {"data/active/CVE-2026-9100": "Candidate: CVE-2026-9100\n\nPatches_x:\njammy_x: ignored\n"},
		"header respelled": {"active/CVE-2026-9100": "CVE-ID: CVE-2026-9100\n\nPatches_x:\njammy_x: ignored\n"},
	} {
		_, _, hits, err := fetchUbuntuCounting(t, trackerRepo(t, files))
		if err == nil {
			t.Errorf("%s: Fetch succeeded, want the build to fail on a tracker with no tuples", name)
			continue
		}
		// Before the archive, not after it: Ubuntu's is 601 MB compressed,
		// and a tracker with nothing in it is known before any is fetched.
		if hits != 0 {
			t.Errorf("%s: the Ubuntu archive was fetched %d time(s) before the empty tracker failed the build", name, hits)
		}
		if !strings.Contains(err.Error(), "0 tuple") || !strings.Contains(err.Error(), "UBUNTU_TRACKER_ENABLE=0") {
			t.Errorf("%s: error = %v, want it to name the zero count and UBUNTU_TRACKER_ENABLE=0", name, err)
		}
	}
}

// Tuples that stamp nothing are the same loss one step later: a tracker read
// fine whose keys no longer meet the archive's (a codename table gone stale,
// a CVE id respelled) leaves every fix-less Ubuntu range unstamped.
func TestFetch_D157_ATrackerThatStampsNothingFailsTheBuild(t *testing.T) {
	requireGit(t)
	_, _, err := fetchUbuntuWith(t, trackerRepo(t, map[string]string{
		"active/CVE-2026-0001": "Candidate: CVE-2026-0001\n\nPatches_y:\njammy_y: ignored\n",
	}))
	if err == nil || !strings.Contains(err.Error(), "stamped no") {
		t.Errorf("Fetch error = %v, want the build to fail on fix-less Ubuntu ranges with none stamped", err)
	}
}

// The count the publish guard holds (D157's second half) rides on the
// provider's provenance.
func TestFetch_D157_ProvenanceCarriesTheStampedCount(t *testing.T) {
	requireGit(t)
	prov, _, err := fetchUbuntuWith(t, initFixtureTrackerRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	if prov.UbuntuFixStates != 1 {
		t.Errorf("Provenance.UbuntuFixStates = %d, want 1 (the one jammy_x: ignored range)", prov.UbuntuFixStates)
	}
}
