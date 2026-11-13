package scancmd

import (
	"strings"
	"testing"
)

// Linux QA of v0.18.1 (2026-11-13), through Run: etc/debian_version is read
// for Debian's point release (D121) in the same layer pass as os-release,
// on every image. An Alpine image whose etc/debian_version is a symbolic
// link cycle is not incomplete for it -- the scan never consults the file
// there -- so nothing is listed unread and the strict gate exits 0, as it
// does with the file absent or an ordinary file. A Debian image's cycle at
// that path stays reported, and a cycle at a path every image reads
// (os-release) stays reported on Alpine too.
func TestRun_DebianVersionUnreadableIsReportedOnDebianOnly(t *testing.T) {
	cycle := []p4Entry{
		{name: debianVersionPath, link: "/etc/debian_version.loop"},
		{name: "etc/debian_version.loop", link: "/" + debianVersionPath},
	}
	alpine := func(extra ...p4Entry) string {
		es := append([]p4Entry{{name: osReleasePath, body: osReleaseAlpine319}, {name: apkDBPath, body: p4ApkPatched}}, extra...)
		return p4Archive(t, p4Tar(t, es...))
	}
	debian := func(extra ...p4Entry) string {
		es := append([]p4Entry{{name: osReleasePath, body: osReleaseDebian12Bookworm}, {name: dpkgDBPath, body: dpkgOpensslAndGlibc}}, extra...)
		return p4Archive(t, p4Tar(t, es...))
	}
	alpineDB, debianDB := layerDigestDB(t), vexDB(t, "Debian:12")
	for _, tc := range []struct {
		name, db, target string
		wantCode         int
		wantUnread       string
	}{
		{"alpine, debian_version a link cycle", alpineDB, alpine(cycle...), 0, ""},
		{"alpine, debian_version an ordinary file", alpineDB, alpine(p4Entry{name: debianVersionPath, body: "12.4\n"}), 0, ""},
		{"alpine, debian_version absent", alpineDB, alpine(), 0, ""},
		// No os-release at all (the Distro is nil): the file is not consulted
		// either. The packages are unkeyed, so the strict gate's exit code is
		// not this row's subject (-1); the unread list is.
		{"no os-release, debian_version a link cycle", alpineDB, p4Archive(t, p4Tar(t, append([]p4Entry{{name: apkDBPath, body: p4ApkPatched}}, cycle...)...)), -1, ""},
		{"debian, debian_version a link cycle", debianDB, debian(cycle...), 2, debianVersionPath},
		{"alpine, os-release a link cycle is still reported", alpineDB, p4Archive(t, p4Tar(t,
			p4Entry{name: osReleasePath, link: "/etc/os-release.loop"}, p4Entry{name: "etc/os-release.loop", link: "/" + osReleasePath},
			p4Entry{name: apkDBPath, body: p4ApkPatched})), 2, osReleasePath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, out, errOut, code := p4Scan(t, tc.db, tc.target, Options{FailOnIncompleteTarget: true})
			var unread []string
			for _, u := range doc.Unread {
				unread = append(unread, u.Path)
			}
			if tc.wantCode >= 0 && code != tc.wantCode {
				t.Fatalf("Run = %d, want %d\nunread: %v\nstdout: %s\nstderr: %s", code, tc.wantCode, unread, out, errOut)
			}
			if tc.wantUnread == "" {
				if len(unread) != 0 || doc.Summary.TargetIncomplete != 0 || strings.Contains(errOut, "not read:") {
					t.Fatalf("unread = %v, targetIncomplete = %d, want none: the scan does not consult etc/debian_version here\nstderr: %s", unread, doc.Summary.TargetIncomplete, errOut)
				}
				return
			}
			if len(unread) != 1 || unread[0] != tc.wantUnread || doc.Summary.TargetIncomplete < 1 || !strings.Contains(errOut, "not read: "+tc.wantUnread) {
				t.Fatalf("unread = %v, targetIncomplete = %d, want exactly %s reported\nstderr: %s", unread, doc.Summary.TargetIncomplete, tc.wantUnread, errOut)
			}
		})
	}
}
