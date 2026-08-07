package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/source"
)

// The rpmdb fixtures are read from the cataloger's own testdata rather than
// copied here. They are built by real sqlite3 (see that package's
// sqlite_test.go), and a second copy would be 127 KB of identical bytes that
// could drift out of step with the expectations both files share.
const (
	rpmFixture    = "../cataloger/rpmdb/testdata/rpmdb.sqlite"
	rpmWALFixture = "../cataloger/rpmdb/testdata/rpmdb-wal.sqlite"
	rpmWALSidecar = "../cataloger/rpmdb/testdata/rpmdb-wal.sqlite-wal"
)

// osReleaseRHEL9 is a real ubi9 /etc/os-release, trimmed to the fields that
// matter. ID is "rhel" — the field this build routes on, because ubi, Alma and
// Rocky all report an el9 release string and only the ID tells them apart.
const osReleaseRHEL9 = `NAME="Red Hat Enterprise Linux"
VERSION="9.8 (Plow)"
ID="rhel"
VERSION_ID="9.8"
PRETTY_NAME="Red Hat Enterprise Linux 9.8 (Plow)"
`

func fixtureBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// rpmImage wraps one set of tar entries as a single-layer image.
func rpmImage(t *testing.T, files map[string]string) *source.Image {
	t.Helper()
	return &source.Image{Layers: []source.Layer{imageLayer(t, "sha256:rpm", files)}}
}

// Both rpmdb locations are probed. The relocated one is not an exotic case:
// RHEL 10, CentOS Stream 10 and Fedora 36+ all keep the real directory at
// /usr/lib/sysimage/rpm and leave /var/lib/rpm as a symlink to it.
func TestCatalogFromImage_RPMAtEitherLocation(t *testing.T) {
	db := fixtureBytes(t, rpmFixture)
	for _, dir := range []string{"var/lib/rpm", "usr/lib/sysimage/rpm"} {
		t.Run(dir, func(t *testing.T) {
			img := rpmImage(t, map[string]string{
				osReleasePath:         osReleaseRHEL9,
				dir + "/rpmdb.sqlite": db,
			})
			target, stats, err := catalogFromImage("test-image", img)
			if err != nil {
				t.Fatal(err)
			}
			if stats.Cataloged != 6 {
				t.Fatalf("cataloged %d packages, want 6", stats.Cataloged)
			}
			byName := map[string]string{}
			for _, p := range target.Packages {
				byName[p.Name] = p.Version
			}
			// Two rows the report would actually print, one of which carries an
			// epoch. Checked by exact value: "openssl" is a substring of
			// "openssl-libs", so a Contains assertion here would pass off the
			// wrong column (CLAUDE.md).
			if got := byName["openssl-libs"]; got != "1:3.5.5-6.el9_8" {
				t.Errorf("openssl-libs = %q, want 1:3.5.5-6.el9_8", got)
			}
			if got := byName["glibc"]; got != "2.34-274.el9_8" {
				t.Errorf("glibc = %q, want 2.34-274.el9_8", got)
			}
			if _, ok := byName["gpg-pubkey"]; ok {
				t.Error("a gpg-pubkey keyring entry reached the inventory")
			}
			if target.Distro == nil || target.Distro.ID != "rhel" {
				t.Errorf("Distro = %+v, want ID rhel", target.Distro)
			}
			for _, p := range target.Packages {
				if p.Locations[0].LayerDigest != "sha256:rpm" {
					t.Errorf("%s LayerDigest = %q", p.Name, p.Locations[0].LayerDigest)
				}
			}
		})
	}
}

// D43: the inventory is read and NO verdict follows. Every package is
// catalogued with an empty ecosystem, because Distro.Ecosystem() has no key for
// an RPM distro and this build ships no provider for one — so the matcher
// reports all of them as skipped and Summary.Trustworthy() takes the scan to
// exit 2.
//
// The alternative would be a clean verdict built on the OSV Red Hat feed, which
// is errata-only: it cannot express "affected, will not fix", a class covering
// 39,372 CVEs that exist only in Red Hat's VEX feed.
func TestCatalogFromImage_RPMPackagesAreUnkeyed(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:              osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	})
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range target.Packages {
		if p.Ecosystem != "" {
			t.Errorf("%s has ecosystem %q; D43 ships no Red Hat provider, so a key here "+
				"would send the lookup into an empty bucket and report clean", p.Name, p.Ecosystem)
		}
		// The source name is still populated, because it costs nothing now and
		// D8's indirection is what the provider will need.
		if p.Source == nil || p.Source.Name == "" {
			t.Errorf("%s has no Source; SOURCERPM is what D8 looks the advisory up under", p.Name)
		}
	}
}

// And the scan really does reach exit 2 rather than reporting a clean image.
// This is the assertion D43 rests on, and it holds through a guard slice 4
// wrote — Summary.Trustworthy() is false when Components > 0 and Evaluated ==
// 0 — rather than through any RHEL special case.
func TestRun_RHELImageIsNotClean(t *testing.T) {
	dbPath := testDB(t)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath:              osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run(RHEL image) = %d, want 2 (stdout: %s, stderr: %s)", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "NOT a clean result") {
		t.Errorf("stdout = %q, want the report to say this is not clean", out.String())
	}
	// The packages were found and NAMED, not silently dropped — an inventory
	// nobody can see is the same as no scan. Asserted on the rendered
	// name-and-version pair rather than on either half: "openssl" is a
	// substring of "openssl-libs" and a bare "6" would match any digit
	// anywhere, so both would pass off a column this test is not about
	// (CLAUDE.md).
	for _, want := range []string{
		"openssl-libs 1:3.5.5-6.el9_8: no version comparer",
		"6 component(s) seen, 0 evaluated",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout does not contain %q:\n%s", want, out.String())
		}
	}
}

// The claim the two-directory probe rests on, made testable: Image.Files
// follows a symlink that IS the wanted path and does NOT follow one on a
// directory component of it. If that ever changed, probing both directories
// would become harmless redundancy rather than a requirement, and this test is
// what would say so.
func TestCatalogFromImage_DirectorySymlinkIsNotFollowed(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// The real database, under the relocated directory.
	body := fixtureBytes(t, rpmFixture)
	for _, e := range []struct {
		name, body, link string
		typ              byte
	}{
		{name: osReleasePath, body: osReleaseRHEL9, typ: tar.TypeReg},
		{name: "usr/lib/sysimage/rpm/rpmdb.sqlite", body: body, typ: tar.TypeReg},
		// exactly what RHEL 10 ships
		{name: "var/lib/rpm", link: "../../usr/lib/sysimage/rpm", typ: tar.TypeSymlink},
	} {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link}
		if e.typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	img := &source.Image{Layers: []source.Layer{{
		DiffID: "sha256:relocated",
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil },
	}}}

	// The traditional path resolves to nothing…
	files, err := img.Files([]string{"var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	if files["var/lib/rpm/rpmdb.sqlite"].Data != nil {
		t.Error("Image.Files followed a symlink on a directory component; the two-directory " +
			"probe in rpmDBDirs is documented as necessary because it does not")
	}
	// …and the scan still finds the database, because both are probed.
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatalf("an image whose /var/lib/rpm is a symlink was not catalogued: %v", err)
	}
	if stats.Cataloged != 6 || len(target.Packages) != 6 {
		t.Errorf("cataloged %d packages from the relocated directory, want 6", stats.Cataloged)
	}
}

// A live write-ahead log reaches ReadSQLite as its real size and the scan is
// refused (D45). Without the sibling probe this image would report two
// packages where three are installed.
func TestCatalogFromImage_LiveWALIsRefused(t *testing.T) {
	files := map[string]string{
		osReleasePath:                  osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite":     fixtureBytes(t, rpmWALFixture),
		"var/lib/rpm/rpmdb.sqlite-wal": fixtureBytes(t, rpmWALSidecar),
	}
	if _, _, err := catalogFromImage("test-image", rpmImage(t, files)); err == nil {
		t.Fatal("an image carrying a live write-ahead log was catalogued from the main file alone")
	} else if !strings.Contains(err.Error(), "write-ahead log") {
		t.Errorf("error = %v, want one naming the write-ahead log", err)
	}

	// The same image WITHOUT the log is read normally, so the refusal above is
	// caused by the sibling and not by the database.
	delete(files, "var/lib/rpm/rpmdb.sqlite-wal")
	if _, stats, err := catalogFromImage("test-image", rpmImage(t, files)); err != nil {
		t.Errorf("the same database with no log was refused: %v", err)
	} else if stats.Cataloged != 2 {
		t.Errorf("cataloged %d packages, want 2", stats.Cataloged)
	}
}

// Backends this build does not read are NAMED. "We found a database we cannot
// read" and "we found no database" are different facts, and only the first
// tells the reader what to do about it.
func TestCatalogFromImage_UnreadableBackendsAreNamed(t *testing.T) {
	// A BerkeleyDB Packages file: the magic at offset 12, little-endian.
	bdb := make([]byte, 4096)
	bdb[12], bdb[13], bdb[14], bdb[15] = 0x61, 0x15, 0x06, 0x00

	for _, tc := range []struct{ name, path, want string }{
		{"BerkeleyDB", "var/lib/rpm/Packages", "BerkeleyDB"},
		{"ndb", "usr/lib/sysimage/rpm/Packages.db", "ndb"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img := rpmImage(t, map[string]string{osReleasePath: osReleaseRHEL9, tc.path: string(bdb)})
			_, _, err := catalogFromImage("test-image", img)
			if err == nil {
				t.Fatal("an unreadable backend was catalogued")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.path) {
				t.Errorf("error = %v, want it to name both %q and the path", err, tc.want)
			}
		})
	}
}

// An RPM distribution with no database at all is a hard error naming what was
// looked for — never an empty inventory. This is the highest-likelihood false
// negative in the whole path: a probe that missed the relocated directory would
// find nothing on RHEL 10, and "nothing" from a scanner reads as a clean image.
func TestCatalogFromImage_RPMDistroWithNoDatabase(t *testing.T) {
	img := rpmImage(t, map[string]string{osReleasePath: osReleaseRHEL9})
	_, _, err := catalogFromImage("test-image", img)
	if err == nil {
		t.Fatal("an RPM image with no database was catalogued without error")
	}
	// The message has to carry the distro it identified AND the paths it
	// checked, because those are the two things that let a reader tell a
	// missing database from a database somewhere this build did not look.
	for _, want := range []string{"rhel", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A damaged header is counted, not dropped. The count has to reach
// Summary.TargetIncomplete, which is what an operator gates on with
// --fail-on-incomplete=target (D36).
func TestCatalogFromImage_UnreadableHeaderIsCounted(t *testing.T) {
	db := []byte(fixtureBytes(t, rpmFixture))
	// Blank one record's NAME so it reads as empty, which toPackage rejects.
	//
	// Located by the NAME/VERSION pair rather than by the name alone: the
	// string "alternatives" also occurs inside that package's own file list,
	// and corrupting one of those would damage a tag nothing reads and leave
	// the record perfectly parseable — a test that passed by not testing.
	// The NUL is a byte here, never an escape in a string (CLAUDE.md).
	// EVERY occurrence is blanked, not the first. The fixture holds two: the
	// live record on a leaf page, and a stale copy left in free space on page 2
	// from before that page split. Corrupting only the first hits the dead one
	// and the record parses perfectly — which is exactly what this test did on
	// its first run, and it passed the scan while asserting nothing.
	nul := []byte{0}
	needle := append(append([]byte("alternatives"), nul...), []byte("1.24")...)
	found := 0
	for i := 0; ; {
		j := bytes.Index(db[i:], needle)
		if j < 0 {
			break
		}
		copy(db[i+j:i+j+len("alternatives")], bytes.Repeat(nul, len("alternatives")))
		i += j + len(needle)
		found++
	}
	if found == 0 {
		t.Fatal("the fixture no longer contains the NAME/VERSION pair this test damages")
	}

	img := rpmImage(t, map[string]string{
		osReleasePath:              osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite": string(db),
	})
	_, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatalf("one damaged record failed the whole scan: %v", err)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1 — a record whose header cannot be read is a "+
			"package we could not evaluate, and dropping it silently is the miss this counts", stats.SkippedNoVersion)
	}
	if stats.Cataloged != 5 {
		t.Errorf("cataloged %d, want the other 5", stats.Cataloged)
	}
	// Components must include it, or the skipped record vanishes from every
	// denominator the report computes.
	if stats.Components != 6 {
		t.Errorf("Components = %d, want 6 (5 read + 1 skipped)", stats.Components)
	}
}
