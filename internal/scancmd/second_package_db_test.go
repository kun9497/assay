package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
)

// QA 2026-11-20. An image's inventory was whichever package database came
// first in a fixed order -- apk, dpkg, rpm, pacman -- so a second database
// earlier in that order replaced the real one without a word. The database
// of the image's own format is now the inventory, and any other database
// holding something is reported not read.

// unreadReasonOf is the reason path was reported not read for, "" when it
// was not reported.
func unreadReasonOf(img *source.Image, path string) string {
	for _, u := range img.Unresolved() {
		if u.Path == path {
			return u.Reason
		}
	}
	return ""
}

func namesOf(t *testing.T, img *source.Image) (names []string, types map[string]bool) {
	t.Helper()
	target, _, _, err := catalogFromImage(context.Background(), "test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v", err)
	}
	types = map[string]bool{}
	for _, p := range target.Packages {
		names = append(names, p.Name)
		types[p.Type] = true
	}
	return names, types
}

// The caller's test, through Run: a Debian 12 image whose dpkg status lists
// openssl, with a one-record apk database dropped beside it. Before the fix
// this scan read the apk record alone and exited 0 with "No known
// vulnerabilities found in 1 package(s)" under every gate.
func TestRun_AStrayApkDatabaseDoesNotReplaceADebianInventory(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0101", "CVE-2031-0101", "openssl", "99.0-1"})
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath: osReleaseDebian12Bookworm,
		dpkgDBPath:    dpkgOpensslAndGlibc,
		apkDBPath:     apkOneRecord,
	})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, "docker-archive:"+tarPath, Options{Output: "json", FailOnUnknown: true}, &out, &errOut)
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v (stderr: %s)", err, errOut.String())
	}
	if code != 1 || len(doc.Findings) == 0 {
		t.Fatalf("exit=%d findings=%d, want exit 1 and the openssl findings of the dpkg inventory (stderr: %s)",
			code, len(doc.Findings), errOut.String())
	}
	for _, f := range doc.Findings {
		if !strings.HasPrefix(f.Package.PURL, "pkg:deb/") {
			t.Errorf("finding on %s (%s), want only the image's own deb packages", f.Package.Name, f.Package.PURL)
		}
	}
	reported := false
	for _, u := range doc.Unread {
		if u.Path == apkDBPath && strings.Contains(u.Reason, "a second package database") && strings.Contains(u.Reason, "the dpkg status database was read") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("unread = %+v, want the apk database named with what was read instead", doc.Unread)
	}
	if !strings.Contains(errOut.String(), "not read: "+apkDBPath+" (a second package database") {
		t.Errorf("stderr does not say the apk database was not read:\n%s", errOut.String())
	}
}

// The second database is something the caller can fix, so the target-scoped
// incompleteness gate sees it.
func TestRun_ASecondPackageDatabaseTripsTheIncompleteGate(t *testing.T) {
	db := vexDB(t, "Debian:12", vexAdv{"DEBIAN-2031-0101", "CVE-2031-0101", "no-such-package", "99.0-1"})
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	files := map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgDBPath: dpkgOpensslAndGlibc}
	writeImageTar(t, tarPath, files)

	var out, errOut bytes.Buffer
	opts := Options{FailOnIncomplete: true, FailOnIncompleteTarget: true}
	if code := Run(context.Background(), db, "docker-archive:"+tarPath, opts, &out, &errOut); code != 0 {
		t.Fatalf("one database: Run = %d, want 0 (stderr: %s)", code, errOut.String())
	}

	files[apkDBPath] = apkOneRecord
	writeImageTar(t, tarPath, files)
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), db, "docker-archive:"+tarPath, opts, &out, &errOut); code != 2 {
		t.Fatalf("with a stray apk database: Run = %d, want 2 under --fail-on-incomplete=target (stderr: %s)", code, errOut.String())
	}
}

// Fedora's dpkg rpm ships an empty /var/lib/dpkg/status. It used to fail the
// scan with "none of [...] holds an rpm database" while the rpmdb sat there.
// An empty file holds no inventory, so it is not reported either.
func TestCatalogFromImage_AnEmptyDpkgStatusDoesNotHideAnRpmDatabase(t *testing.T) {
	for name, status := range map[string]string{"empty": "", "blank lines": "\n\n"} {
		t.Run(name, func(t *testing.T) {
			img := archImage(t, map[string]string{
				osReleasePath:              osReleaseRHEL9,
				"var/lib/rpm/rpmdb.sqlite": string(fixtureBytes(t, rpmFixture)),
				dpkgDBPath:                 status,
			})
			names, types := namesOf(t, img)
			if len(names) != 6 || !types["rpm"] || len(types) != 1 {
				t.Fatalf("cataloged %v of types %v, want the rpmdb's 6 rpm packages", names, types)
			}
			if r := unreadReasonOf(img, dpkgDBPath); r != "" {
				t.Errorf("the empty dpkg status was reported not read (%s); it holds nothing", r)
			}
		})
	}
}

func TestCatalogFromImage_TheImagesOwnFormatIsItsInventory(t *testing.T) {
	rpm := string(fixtureBytes(t, rpmFixture))
	for _, tc := range []struct {
		name       string
		files      map[string]string
		wantType   string
		wantN      int
		wantUnread string
		wantReadAs string
	}{
		{
			name:     "rhel with a populated dpkg status",
			files:    map[string]string{osReleasePath: osReleaseRHEL9, "var/lib/rpm/rpmdb.sqlite": rpm, dpkgDBPath: dpkgOpensslAndGlibc},
			wantType: "rpm", wantN: 6, wantUnread: dpkgDBPath, wantReadAs: "the rpm database was read",
		},
		{
			name:     "rhel with an apk database",
			files:    map[string]string{osReleasePath: osReleaseRHEL9, "var/lib/rpm/rpmdb.sqlite": rpm, apkDBPath: apkOneRecord},
			wantType: "rpm", wantN: 6, wantUnread: apkDBPath, wantReadAs: "the rpm database was read",
		},
		{
			// An RPM distro this build has no advisory key for is still an
			// RPM distro: its identity implies the format without a key.
			name:     "centos (no key) with an apk database",
			files:    map[string]string{osReleasePath: "ID=centos\nVERSION_ID=\"7\"\n", "var/lib/rpm/rpmdb.sqlite": rpm, apkDBPath: apkOneRecord},
			wantType: "rpm", wantN: 6, wantUnread: apkDBPath, wantReadAs: "the rpm database was read",
		},
		{
			// pacman's database is a pass of its own, made only when nothing
			// else was found -- or when the image says it is Arch.
			name: "arch with an apk database",
			files: map[string]string{
				osReleasePath:                           osReleaseArch,
				"var/lib/pacman/local/acl-2.4.0-1/desc": archDesc("acl", "2.4.0-1", "acl"),
				apkDBPath:                               apkOneRecord,
			},
			wantType: "alpm", wantN: 1, wantUnread: apkDBPath, wantReadAs: "the pacman database was read",
		},
		{
			name:     "debian (status.d) with an apk database",
			files:    map[string]string{osReleasePath: osReleaseDebian12Bookworm, dpkgStatusDir + "/libc6": dpkgOpensslAndGlibc, apkDBPath: apkOneRecord},
			wantType: "deb", wantN: 3, wantUnread: apkDBPath, wantReadAs: "the dpkg status.d database was read",
		},
		{
			// No identity to go by: the old order still decides, and the
			// database it passes over is still named.
			name:     "no os-release, apk and dpkg",
			files:    map[string]string{apkDBPath: apkOneRecord, dpkgDBPath: dpkgOpensslAndGlibc},
			wantType: "apk", wantN: 1, wantUnread: dpkgDBPath, wantReadAs: "the apk database was read",
		},
		{
			// With no identity the old order decides, but an empty dpkg
			// status does not outrank a database that holds something.
			name:     "no os-release, an empty dpkg status and an rpmdb",
			files:    map[string]string{"var/lib/rpm/rpmdb.sqlite": rpm, dpkgDBPath: ""},
			wantType: "rpm", wantN: 6,
		},
		{
			// The identity's own database is absent: what is there is read,
			// and nothing is reported, because nothing was passed over.
			name:     "debian identity, only an apk database",
			files:    map[string]string{osReleasePath: osReleaseDebian12Bookworm, apkDBPath: apkOneRecord},
			wantType: "apk", wantN: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := archImage(t, tc.files)
			names, types := namesOf(t, img)
			if len(names) != tc.wantN || !types[tc.wantType] || len(types) != 1 {
				t.Fatalf("cataloged %v of types %v, want %d %s package(s)", names, types, tc.wantN, tc.wantType)
			}
			if tc.wantUnread != "" {
				r := unreadReasonOf(img, tc.wantUnread)
				if !strings.Contains(r, "a second package database") || !strings.Contains(r, tc.wantReadAs) {
					t.Errorf("%s reported as %q, want a second package database and %q", tc.wantUnread, r, tc.wantReadAs)
				}
			}
			if len(img.Unresolved()) != map[bool]int{true: 1, false: 0}[tc.wantUnread != ""] {
				t.Errorf("unresolved = %+v, want exactly the database passed over", img.Unresolved())
			}
		})
	}
}
