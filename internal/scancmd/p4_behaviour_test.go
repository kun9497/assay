package scancmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-20, the P4 items that reach a scan.

func TestWarnIfStale_AgesTheAdvisoriesNotTheBuild(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		m    store.Meta
		want bool
	}{
		"fresh build":                   {store.Meta{BuiltAt: now}, false},
		"fresh build, old advisories":   {store.Meta{BuiltAt: now, AdvisoriesBuiltAt: now.AddDate(0, 0, -30)}, true},
		"fresh build, fresh advisories": {store.Meta{BuiltAt: now, AdvisoriesBuiltAt: now.AddDate(0, 0, -1)}, false},
	} {
		var b strings.Builder
		warnIfStale(tc.m, now, &b)
		if got := strings.Contains(b.String(), "30 days ago"); got != tc.want {
			t.Errorf("%s: %q", name, b.String())
		}
	}
}

// npmLockDir is a directory holding one good package-lock.json when ok, and
// one that does not parse.
func npmLockDir(t *testing.T, ok bool) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte("[[package]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok {
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"),
			[]byte(`{"lockfileVersion":3,"packages":{"node_modules/y":{"version":"1.0.0","resolved":"https://registry.npmjs.org/y/-/y-1.0.0.tgz","integrity":"sha512-x"}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRun_AnUnreadPathIsNotACleanHeadline(t *testing.T) {
	db := vexDB(t, "npm", vexAdv{"GHSA-x", "CVE-2031-1", "x", "2.0.0"})
	out, stderr, code := provRun(t, db, "dir:"+npmLockDir(t, true), Options{})
	if code != 0 || strings.Contains(out, "No known vulnerabilities") || !strings.Contains(out, "1 path(s) could not be read - this is NOT a clean result") {
		t.Errorf("exit %d%s%s%s", code, out, string(rune(10)), stderr)
	}
}

func TestRun_SARIFOfAnUnreadDirectoryIsNotSuccessful(t *testing.T) {
	db := vexDB(t, "npm", vexAdv{"GHSA-x", "CVE-2031-1", "x", "2.0.0"})
	for _, tc := range []struct {
		readable bool
		code     int
		want     string
	}{{false, 2, `"executionSuccessful":false`}, {true, 0, `"executionSuccessful":true`}} {
		out, _, code := provRun(t, db, "dir:"+npmLockDir(t, tc.readable), Options{Output: "sarif"})
		compact := strings.NewReplacer(" ", "", string(rune(10)), "").Replace(out)
		if code != tc.code || !strings.Contains(compact, tc.want) {
			t.Errorf("readable %v: exit %d, want %d and %s", tc.readable, code, tc.code, tc.want)
		}
		if got := strings.Contains(compact, `"level":"error"`); got != !tc.readable {
			t.Errorf("readable %v: an error-level notification = %v", tc.readable, got)
		}
	}
}

func TestRun_ALinkedRootDirectoryIsWalked(t *testing.T) {
	db := vexDB(t, "npm", vexAdv{"GHSA-x", "CVE-2031-1", "y", "2.0.0"})
	real := npmLockDir(t, true)
	link := filepath.Join(t.TempDir(), "link")
	if runtime.GOOS == "windows" {
		if b, err := exec.Command("cmd", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
			t.Fatalf("junction: %v %s", err, b)
		}
	} else if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	out, stderr, code := provRun(t, db, "dir:"+link, Options{FailOnUnknown: true})
	if code != 1 || !strings.Contains(out, "CVE-2031-1") && !strings.Contains(out, "GHSA-x") {
		t.Errorf("exit %d, want the finding through the link%s%s", code, out, stderr)
	}
}
