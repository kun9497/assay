package rpmdb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures are built by scratchpad/genrpmdb.py using the real sqlite3
// library — the same implementation rpm writes with — so this file checks the
// reader against the format's own code rather than against a second copy of
// my understanding of it. The generator prints what real SQLite reads back,
// and the expectations below are those numbers.
const (
	fixture     = "testdata/rpmdb.sqlite"
	walFixture  = "testdata/rpmdb-wal.sqlite"
	walSidecar  = "testdata/rpmdb-wal.sqlite-wal"
	fixturePath = "/var/lib/rpm/rpmdb.sqlite"
)

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every package in the fixture, with the NEVRA and source name real SQLite
// says the blobs encode.
func TestReadSQLite_Fixture(t *testing.T) {
	res, err := ReadSQLite(read(t, fixture), WALAbsent, "", fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("skipped %d records, want none: %v", len(res.Skipped), res.Skipped)
	}
	want := []struct{ name, version, source string }{
		{"alternatives", "1.24-2.el9", "chkconfig"},
		{"audit-libs", "3.1.5-8.el9", "audit"},
		{"glibc", "2.34-274.el9_8", "glibc"},
		// The one row with a non-zero epoch, which must appear in the version
		// string the comparer receives.
		{"openssl-libs", "1:3.5.5-6.el9_8", "openssl"},
		// An EXPLICIT zero epoch, which must not (D46).
		{"systemd-libs", "252-67.el9_8.4", "systemd"},
		// Sized so its payload takes SQLite's M branch rather than its K one;
		// see TestSQLite_OverflowRecoversWholeBlobs.
		{"zlib", "1.2.11-40.el9", "zlib"},
	}
	if len(res.Packages) != len(want) {
		t.Fatalf("read %d packages, want %d: %+v", len(res.Packages), len(want), res.Packages)
	}
	for i, w := range want {
		p := res.Packages[i]
		if p.Name != w.name || p.Version != w.version {
			t.Errorf("package %d = %s %s, want %s %s", i, p.Name, p.Version, w.name, w.version)
		}
		if p.Source == nil || p.Source.Name != w.source {
			t.Errorf("package %d (%s) Source = %+v, want name %q", i, p.Name, p.Source, w.source)
		}
	}
	// The sixth row is a gpg-pubkey keyring entry. Asserted by absence from a
	// list whose length is already fixed above, so a change that stopped
	// filtering it fails on both counts.
	for _, p := range res.Packages {
		if p.Name == "gpg-pubkey" {
			t.Error("a gpg-pubkey keyring entry was reported as an installed package")
		}
	}
}

// Overflow chains, asserted on the recovered byte counts rather than on the
// packages, because the tags a NEVRA needs all sit in the first few hundred
// bytes of a header: a reader that dropped every overflow page would still
// produce five plausible packages and only the lengths would say otherwise.
//
// 187 of 188 blobs in a real ubi9 database exceed one page, so this is the
// normal path and not an edge case.
func TestSQLite_OverflowRecoversWholeBlobs(t *testing.T) {
	f, err := openSQLite(read(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	_, packages, err := f.schemaRoots()
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	err = f.walkTable(packages, func(_ int64, cols [][]byte) error {
		sizes = append(sizes, len(cols[len(cols)-1]))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Printed by the generator from real SQLite's own length(blob).
	want := []int{6354, 6170, 33851, 6559, 6200, 229, 8154}
	if len(sizes) != len(want) {
		t.Fatalf("walked %d rows, want %d", len(sizes), len(want))
	}
	for i := range want {
		if sizes[i] != want[i] {
			t.Errorf("row %d blob is %d bytes, real SQLite says %d", i+1, sizes[i], want[i])
		}
	}
	// Both overflow branches must be exercised, and the fixture is checked for
	// it rather than assumed. SQLite keeps K bytes on the page normally and M
	// bytes when K would exceed X, and the second branch is reached by about
	// one payload size in eight — none of the natural blobs above land there,
	// so the last row was sized deliberately. Without this check, regenerating
	// the fixture could quietly drop the M case and a mutation of it would
	// survive, which is what happened the first time this table was written.
	var sawK, sawM bool
	for _, p := range want {
		if p <= f.usable-35 {
			continue
		}
		m := ((f.usable-12)*32)/255 - 23
		if m+(p-m)%(f.usable-4) > f.usable-35 {
			sawM = true
		} else {
			sawK = true
		}
	}
	if !sawK || !sawM {
		t.Errorf("fixture exercises K=%v M=%v; both overflow branches need a row", sawK, sawM)
	}
	// And at least one blob long enough to need a chain of several pages, not
	// just one spill page.
	if want[2] < f.usable*4 {
		t.Errorf("the largest fixture blob is %d bytes against a %d-byte usable page; "+
			"the fixture no longer exercises a multi-page overflow chain", want[2], f.usable)
	}
}

// D45, in the only form that proves anything: the main file alone gives the
// WRONG answer, and the guard refuses it.
//
// A test that only checked "a large walSize is rejected" would pass against a
// guard keyed on anything at all, including the header version bytes that can
// never differ. This one reads a database whose log really does hold a package
// the main file does not.
func TestReadSQLite_LiveWALIsRefused(t *testing.T) {
	db := read(t, walFixture)
	wal := read(t, walSidecar)

	// First: the main file alone is genuinely stale. Real SQLite sees three
	// rows in this database; the main file holds two.
	stale, err := ReadSQLite(db, WALAbsent, "", fixturePath)
	if err != nil {
		t.Fatalf("reading the main file alone should succeed (it is a valid database): %v", err)
	}
	if len(stale.Packages) != 2 {
		t.Fatalf("the main file alone holds %d packages, want 2 — the fixture no longer "+
			"demonstrates the defect this guard exists for", len(stale.Packages))
	}
	for _, p := range stale.Packages {
		if p.Name == "zlib" {
			t.Fatal("zlib is in the main file; it is supposed to exist only in the log")
		}
	}

	// And the header cannot distinguish the two cases, which is why the guard
	// is not there. Both bytes are 2 on every real rpmdb.
	if db[18] != 2 || db[19] != 2 {
		t.Fatalf("file-format version bytes are %d,%d; the fixture is not in WAL mode and "+
			"cannot show why a header-based guard is vacuous", db[18], db[19])
	}

	// Second: with the log's real size, the read is refused rather than
	// returning the stale two.
	if _, err := ReadSQLite(db, int64(len(wal)), "", fixturePath); !errors.Is(err, ErrSQLite) {
		t.Errorf("a %d-byte write-ahead log was accepted (err = %v); the scan would have "+
			"reported 2 packages where 3 are installed", len(wal), err)
	}

	// A log that holds only its 32-byte header has been checkpointed and is
	// not a reason to refuse — refusing it would fail every scan of an
	// ordinary image.
	if _, err := ReadSQLite(read(t, fixture), walHeaderLen, "", fixturePath); err != nil {
		t.Errorf("a checkpointed (header-only) log was refused: %v", err)
	}
}

// Not having looked is not the same as there being nothing to find. A caller
// that cannot say either way gets an error rather than the benefit of the
// doubt, because the benefit of the doubt here is a silently short package
// list.
func TestReadSQLite_UncheckedWALIsAnError(t *testing.T) {
	if _, err := ReadSQLite(read(t, fixture), -2, "", fixturePath); !errors.Is(err, ErrWALNotChecked) {
		t.Errorf("err = %v, want ErrWALNotChecked", err)
	}
}

// D45's second half: a damaged page anywhere in the file is a refusal, not a
// shorter package list.
//
// Page 12 is the root of the Recommendname table, which the Packages walk
// never reaches — the same shape as the real demonstration, where overwriting
// one index root left a prototype reporting 186 packages and no error while
// real SQLite called the image malformed. Generating the corruption here
// rather than committing a second 118 KB file; the identical construction was
// checked against real SQLite, which reports "database disk image is
// malformed".
func TestReadSQLite_DamagedPageIsRefused(t *testing.T) {
	const victimPage = 12
	db := read(t, fixture)
	f, err := openSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), db...)
	off := (victimPage - 1) * f.pageSize
	for i := off; i < off+f.pageSize; i++ {
		corrupt[i] = 0xFF
	}

	// The Packages walk alone is untroubled by it. This is the assertion that
	// makes the next one mean something: without it, a reader that never
	// validated anything would pass the test below by accident only if the
	// damage happened to land in its path.
	cf, err := openSQLite(corrupt)
	if err != nil {
		t.Fatal(err)
	}
	_, packages, err := cf.schemaRoots()
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	if err := cf.walkTable(packages, func(int64, [][]byte) error { rows++; return nil }); err != nil {
		t.Fatalf("the Packages walk failed on its own, so this fixture does not test whole-file "+
			"validation: %v", err)
	}
	if rows != 7 {
		t.Fatalf("the Packages walk read %d rows on the damaged file, want all 7 — page %d is "+
			"supposed to be outside its path", rows, victimPage)
	}

	// So the refusal has to come from validating the rest of the file.
	if _, err := ReadSQLite(corrupt, WALAbsent, "", fixturePath); !errors.Is(err, ErrSQLite) {
		t.Errorf("a database with a destroyed index root was read as though it were intact "+
			"(err = %v); real SQLite calls this image malformed", err)
	}
}

// Files that are not this format at all. Each must name what it found rather
// than returning zero packages, because "no packages" from a scanner is a
// clean verdict.
func TestReadSQLite_RejectsWrongFiles(t *testing.T) {
	good := read(t, fixture)
	f, err := openSQLite(good)
	if err != nil {
		t.Fatal(err)
	}

	// A BerkeleyDB Packages file starts with its own magic, and RHEL 8 images
	// really will be handed to this reader if the format sniff is wrong.
	bdb := make([]byte, 4096)
	bdb[12], bdb[13], bdb[14], bdb[15] = 0x61, 0x15, 0x06, 0x00

	notWholePages := append(append([]byte(nil), good...), 1, 2, 3)

	badPageSize := append([]byte(nil), good...)
	badPageSize[16], badPageSize[17] = 0x00, 0x03 // 768: not a power of two

	// Reserved space so large the usable page falls below the format's floor.
	badReserved := append([]byte(nil), good...)
	badReserved[20] = 0xFF

	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"shorter than the file header", good[:64]},
		{"a BerkeleyDB Packages file", bdb},
		{"zeroed", make([]byte, 8192)},
		{"not a whole number of pages", notWholePages},
		{"page size that is not a power of two", badPageSize},
		{"reserved tail larger than the page allows", badReserved},
		{"truncated mid-database", good[:f.pageSize*3]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ReadSQLite(tc.in, WALAbsent, "", fixturePath)
			if !errors.Is(err, ErrSQLite) {
				t.Fatalf("err = %v, want one wrapping ErrSQLite (got %d packages)", err, len(res.Packages))
			}
		})
	}
}

// The Packages rootpage is read from the schema, not assumed. It is 2 on every
// image measured and would stay 2 until an rpm release adds a table before it.
func TestSQLite_PackagesRootComesFromTheSchema(t *testing.T) {
	f, err := openSQLite(read(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	roots, packages, err := f.schemaRoots()
	if err != nil {
		t.Fatal(err)
	}
	if packages == 0 {
		t.Fatal("the Packages table was not found in sqlite_master")
	}
	// The fixture carries eleven other b-trees. If the schema read collapsed
	// to "page 2", this count would drop and the whole-file validation above
	// would silently stop covering anything.
	if len(roots) < 10 {
		t.Errorf("found %d b-tree roots, want the schema's dozen — whole-file validation "+
			"only covers what this returns", len(roots))
	}
}

// A database with no Packages table is not an empty package list.
func TestReadSQLite_NoPackagesTable(t *testing.T) {
	// The WAL fixture's sibling directory has no such file, so this builds the
	// case by pointing the reader at a valid SQLite database that holds a
	// different schema: the -wal file itself is not one, so use a real
	// database with its schema page blanked instead.
	db := read(t, walFixture)
	f, err := openSQLite(db)
	if err != nil {
		t.Fatal(err)
	}
	blank := append([]byte(nil), db...)
	// Zero the cell count on page 1, leaving a structurally valid but empty
	// schema.
	blank[sqliteHeaderLen+3], blank[sqliteHeaderLen+4] = 0, 0
	res, err := ReadSQLite(blank, WALAbsent, "", fixturePath)
	if !errors.Is(err, ErrSQLite) {
		t.Errorf("a database with no Packages table read as %d packages (err = %v)", len(res.Packages), err)
	}
	_ = f
}

// The fixtures are committed, so a rename or a stray clean is caught here
// rather than as a confusing failure inside every other test.
func TestFixturesExist(t *testing.T) {
	for _, p := range []string{fixture, walFixture, walSidecar} {
		if _, err := os.Stat(filepath.FromSlash(p)); err != nil {
			t.Errorf("fixture %s: %v", p, err)
		}
	}
}
