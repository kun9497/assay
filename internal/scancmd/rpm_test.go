package scancmd

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// The rpmdb fixtures are read from the cataloger's own testdata rather than
// copied here. They are built by real sqlite3 (see that package's
// sqlite_test.go), and a second copy would be 127 KB of identical bytes that
// could drift out of step with the expectations both files share.
const (
	rpmFixture    = "../cataloger/rpmdb/testdata/rpmdb.sqlite"
	rpmWALFixture = "../cataloger/rpmdb/testdata/rpmdb-wal.sqlite"
	bdbFixture    = "../cataloger/rpmdb/testdata/Packages"
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

// osReleaseRHEL8 is a real ubi8 /etc/os-release, and the fixture database was
// built from that same image -- so a scan of the two together keys on Red Hat:8
// and reads packages that really do belong to it.
const osReleaseRHEL8 = `NAME="Red Hat Enterprise Linux"
VERSION="8.10 (Ootpa)"
ID="rhel"
VERSION_ID="8.10"
PRETTY_NAME="Red Hat Enterprise Linux 8.10 (Ootpa)"
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

// D47: RPM packages are keyed on the mainline major, so they are actually
// evaluated. This is the line slice 12 deliberately did not cross -- with no
// provider, a key here would have sent every lookup into an empty bucket and
// reported clean.
func TestCatalogFromImage_RPMPackagesAreKeyed(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:              osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	})
	target, _, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range target.Packages {
		// The MINOR is dropped: os-release says 9.8, the advisories are keyed
		// on the major, and a "Red Hat:9.8" key would match nothing at all.
		if p.Ecosystem != "Red Hat:9" {
			t.Errorf("%s has ecosystem %q, want Red Hat:9", p.Name, p.Ecosystem)
		}
		if p.Source == nil || p.Source.Name == "" {
			t.Errorf("%s has no Source; SOURCERPM is what D8 looks the advisory up under", p.Name)
		}
	}
}

// A RHEL image against a database with no Red Hat data is NOT clean. D20's
// coverage set is what carries this: the ecosystem resolves, the lookup finds
// nothing, and the difference between "ingested and nothing matched" and
// "never ingested" is the whole reason that set is stored.
func TestRun_RHELImageAgainstADatabaseWithoutRedHat(t *testing.T) {
	dbPath := testDB(t) // declares Alpine, Go, npm, PyPI -- no Red Hat
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath:              osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	})

	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, Options{}, &out, &errOut)
	if code != 2 {
		t.Errorf("Run = %d, want 2 (stdout: %s, stderr: %s)", code, out.String(), errOut.String())
	}
	for _, want := range []string{
		`ecosystem "Red Hat:9" is not in this database`,
		"6 component(s) seen, 0 evaluated",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout does not contain %q: %s", want, out.String())
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

// Both backends are read, and which one an image carries is a property of its
// release rather than of anything the caller asked for. RHEL 8 keeps a
// BerkeleyDB hash file where RHEL 9 keeps a SQLite one, and the packages that
// come out are the same shape either way.
func TestCatalogFromImage_BerkeleyDBIsRead(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:          osReleaseRHEL8,
		"var/lib/rpm/Packages": fixtureBytes(t, bdbFixture),
	})
	target, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cataloged != 6 {
		t.Fatalf("cataloged %d packages, want 6: %+v", stats.Cataloged, target.Packages)
	}
	byName := map[string]string{}
	for _, p := range target.Packages {
		byName[p.Name] = p.Version
		// RHEL 8, not 9: the key follows os-release, and a scan that read the
		// database correctly but keyed it on the wrong release would match
		// nothing while looking perfectly healthy.
		if p.Ecosystem != "Red Hat:8" {
			t.Errorf("%s ecosystem = %q, want Red Hat:8", p.Name, p.Ecosystem)
		}
		if p.Locations[0].LayerDigest != "sha256:rpm" {
			t.Errorf("%s LayerDigest = %q", p.Name, p.Locations[0].LayerDigest)
		}
	}
	if got := byName["libnsl2"]; got != "1.2.0-2.20180605git4a062cf.el8" {
		t.Errorf("libnsl2 = %q, want 1.2.0-2.20180605git4a062cf.el8", got)
	}
	// D8 through SOURCERPM, on the backend that did not have it a slice ago.
	for _, p := range target.Packages {
		if p.Name == "langpacks-en" && (p.Source == nil || p.Source.Name != "langpacks") {
			t.Errorf("langpacks-en Source = %+v, want name langpacks", p.Source)
		}
	}
}

// The relocated directory holds a BerkeleyDB database on some images too, so
// both backends are probed at both paths rather than one path each.
func TestCatalogFromImage_BerkeleyDBAtTheRelocatedPath(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:                   osReleaseRHEL8,
		"usr/lib/sysimage/rpm/Packages": fixtureBytes(t, bdbFixture),
	})
	_, stats, err := catalogFromImage("test-image", img)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Cataloged != 6 {
		t.Errorf("cataloged %d packages, want 6", stats.Cataloged)
	}
}

// ndb is still refused BY NAME. openSUSE and SLES are the only distributions
// that use it and there is no SUSE advisory source for it to serve, so
// "we found a database we do not read" is the honest answer and "we found no
// database" is not.
func TestCatalogFromImage_NDBIsNamed(t *testing.T) {
	ndb := make([]byte, 4096)
	copy(ndb, "RpmP")
	img := rpmImage(t, map[string]string{
		osReleasePath:                      osReleaseRHEL9,
		"usr/lib/sysimage/rpm/Packages.db": string(ndb),
	})
	_, _, err := catalogFromImage("test-image", img)
	if err == nil {
		t.Fatal("an ndb database was catalogued")
	}
	for _, want := range []string{"ndb", "usr/lib/sysimage/rpm/Packages.db"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q", err, want)
		}
	}
}

// A BerkeleyDB file that is damaged fails the scan rather than yielding a
// short list, the same way a damaged SQLite one does.
func TestCatalogFromImage_DamagedBerkeleyDBIsRefused(t *testing.T) {
	b := []byte(fixtureBytes(t, bdbFixture))
	truncated := string(b[:len(b)-4096])
	img := rpmImage(t, map[string]string{
		osReleasePath:          osReleaseRHEL8,
		"var/lib/rpm/Packages": truncated,
	})
	if _, _, err := catalogFromImage("test-image", img); err == nil {
		t.Fatal("a truncated BerkeleyDB database was catalogued")
	} else if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error = %v, want it to say the database is truncated", err)
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

// redHatDB is a database carrying Red Hat records for the fixture image, in
// the two shapes the CSAF VEX provider emits (D48): a range that closes on a
// fixed version, and one that never closes because Red Hat says there is
// nothing to upgrade to.
func redHatDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	put := func(id, name string, events []advisory.Event) {
		t.Helper()
		if err := w.Put(advisory.Advisory{
			ID:       id,
			Database: "REDHAT",
			Source:   "redhat",
			Kind:     advisory.KindVulnerability,
			Upstream: []string{id},
			Affected: []advisory.Affected{{
				Ecosystem: "Red Hat:9",
				Name:      name,
				Ranges:    []advisory.Range{{Type: advisory.RangeEcosystem, Events: events}},
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Installed openssl-libs is 1:3.5.5-6.el9_8, below the fix.
	put("CVE-2024-0001", "openssl-libs",
		[]advisory.Event{{Introduced: "0"}, {Fixed: "1:3.5.5-8.el9_8"}})
	// Installed glibc is 2.34-274.el9_8, above the fix: not a finding, which is
	// what proves the comparer is running rather than everything matching.
	put("CVE-2024-0002", "glibc",
		[]advisory.Event{{Introduced: "0"}, {Fixed: "2.34-100.el9"}})
	// The shape this whole slice exists for. No fixed event at all.
	put("CVE-2005-2541", "zlib", []advisory.Event{{Introduced: "0"}})
	// Written against the SOURCE package (D8): the image has audit-libs, whose
	// SOURCERPM names audit. An advisory naming audit must still reach it.
	put("CVE-2024-0003", "audit", []advisory.Event{{Introduced: "0"}, {Fixed: "3.1.5-99.el9"}})

	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"redhat": {Ecosystems: []string{"Red Hat:9"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func rhelTar(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, p, map[string]string{
		osReleasePath:              osReleaseRHEL9,
		"var/lib/rpm/rpmdb.sqlite": fixtureBytes(t, rpmFixture),
	})
	return p
}

// The whole path, end to end: an rpmdb read out of an image layer, packages
// keyed on Red Hat:9, versions ordered by rpmvercmp, and findings rendered.
func TestRun_RHELImageProducesFindings(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(context.Background(), redHatDB(t), "docker-archive:"+rhelTar(t), Options{}, &out, &errOut)
	if code != 0 {
		t.Errorf("Run = %d, want 0 — findings exist but no --fail-on gate was set "+
			"(stderr: %s)", code, errOut.String())
	}
	s := out.String()

	// Asserted per ROW, by locating the line the advisory is on and checking
	// the other cells of that same line. A bare Contains over the whole report
	// would pass off a neighbouring row: "openssl" is a substring of
	// "openssl-libs", and "zlib" appears in the fixture's own file lists.
	for _, tc := range []struct{ advisory, wantPkg, wantVersion, wantFixed string }{
		{"CVE-2024-0001", "openssl-libs", "1:3.5.5-6.el9_8", "1:3.5.5-8.el9_8"},
		// D8: the advisory names the SOURCE package, and the row has to show
		// both so a reader can check the claim against the advisory they look
		// up.
		{"CVE-2024-0003", "audit-libs (audit)", "3.1.5-8.el9", "3.1.5-99.el9"},
		// D48: no fixed event at all, and the cell says so in a word rather
		// than with the "-" that means "not in this record".
		{"CVE-2005-2541", "zlib", "1.2.11-40.el9", "none"},
	} {
		line := lineWith(s, tc.advisory)
		if line == "" {
			t.Errorf("no row for %s: %s", tc.advisory, s)
			continue
		}
		for _, want := range []string{tc.wantPkg, tc.wantVersion, tc.wantFixed} {
			if !strings.Contains(line, want) {
				t.Errorf("row %s = %q, missing %q", tc.advisory, line, want)
			}
		}
	}

	// glibc is above its fix and must NOT appear. This is the row that shows
	// the comparer decided something rather than everything matching.
	if strings.Contains(s, "CVE-2024-0002") {
		t.Errorf("glibc 2.34-274.el9_8 was reported against a fix of 2.34-100.el9:\n%s", s)
	}
	if !strings.Contains(s, "3 finding(s)") {
		t.Errorf("want exactly 3 findings:\n%s", s)
	}
	// D48's rendering: the unfixable row says so, and says it differently from
	// a row whose fix simply is not in this record.
	if !strings.Contains(s, "1 with no fix available") {
		t.Errorf("summary does not count the unfixable finding:\n%s", s)
	}
	if !strings.Contains(s, "no source records a version that fixes this") {
		t.Errorf("the FIXED IN footnote is missing:\n%s", s)
	}
}

// D48's gate. The findings here are all unrated, so --fail-on cannot reach
// them and this flag is the only thing that can — which is why it exists as a
// flag rather than as a band.
func TestRun_RHELFailOnUnfixable(t *testing.T) {
	dbPath, tarPath := redHatDB(t), rhelTar(t)
	critical, none := severity.Critical, severity.None
	for _, tc := range []struct {
		name string
		opts Options
		want int
	}{
		{"no gate", Options{}, 0},
		{"--fail-on-unfixable", Options{FailOnUnfixable: true}, 1},
		// A severity threshold cannot express this ask: every finding here is
		// unrated, and D17 keeps Unknown outside the ordering.
		{"--fail-on critical", Options{FailOn: &critical}, 0},
		{"--fail-on none", Options{FailOn: &none}, 0},
		// The gates are independent: nothing in this scan was incomplete, so
		// the incompleteness gate stays quiet and only the unfixable one
		// fires. A gate that fired on somebody else's condition would be
		// indistinguishable from one that worked.
		{"unfixable and incomplete together, nothing incomplete", Options{FailOnUnfixable: true, FailOnIncomplete: true}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, tc.opts, &out, &errOut); code != tc.want {
				t.Errorf("Run = %d, want %d (stdout: %s)", code, tc.want, out.String())
			}
		})
	}
}

// lineWith returns the single output line containing needle, or "".
func lineWith(out, needle string) string {
	for _, l := range strings.Split(out, string(rune(10))) {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// D47's debt. A RHEL finding is matched against MAINLINE errata, and a host on
// EUS, AUS, TUS or E4S may have a different fixed version for the same CVE.
// The reader has to be told, because the alternative is discovering it when a
// quoted fixed version turns out not to be installable.
func TestRun_RedHatFindingsDiscloseTheMainlineCaveat(t *testing.T) {
	var out, errOut bytes.Buffer
	Run(context.Background(), redHatDB(t), "docker-archive:"+rhelTar(t), Options{}, &out, &errOut)
	if !strings.Contains(errOut.String(), "mainline RHEL errata") {
		t.Errorf("stderr does not disclose the mainline-errata caveat:\n%s", errOut.String())
	}
	// On stderr, never stdout: `--output json | jq` has to stay clean, and the
	// whole of D18's stream discipline rests on nothing but the report reaching
	// stdout.
	if strings.Contains(out.String(), "mainline RHEL errata") {
		t.Errorf("the caveat reached stdout, which breaks `--output json | jq`:\n%s", out.String())
	}
	var jsonOut, jsonErr bytes.Buffer
	Run(context.Background(), redHatDB(t), "docker-archive:"+rhelTar(t),
		Options{Output: "json"}, &jsonOut, &jsonErr)
	if !json.Valid(jsonOut.Bytes()) {
		t.Errorf("--output json did not produce a valid document:\n%s", jsonOut.String())
	}
	if !strings.Contains(jsonErr.String(), "mainline RHEL errata") {
		t.Errorf("the caveat is missing from the json run's stderr:\n%s", jsonErr.String())
	}
}

// And it is printed only when a Red Hat finding was actually emitted. A caveat
// attached to nothing is one readers learn to skip past, and the next one they
// skip may be the one that mattered.
func TestRun_NoRedHatFindingsNoCaveat(t *testing.T) {
	// An Alpine image against the ordinary fixture database: findings or not,
	// nothing here was matched under a Red Hat key.
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath: osReleaseAlpine319,
		apkDBPath:     apkOneRecord,
	})
	var out, errOut bytes.Buffer
	Run(context.Background(), testDB(t), "docker-archive:"+tarPath, Options{}, &out, &errOut)
	if strings.Contains(errOut.String(), "mainline RHEL errata") {
		t.Errorf("an Alpine scan disclosed a Red Hat caveat:\n%s", errOut.String())
	}
}
