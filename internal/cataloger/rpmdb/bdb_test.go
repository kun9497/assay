package rpmdb

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

// The fixtures are built by scratchpad/mkfixture.py, which copies RPM header
// blobs byte for byte out of a genuine ubi8 /var/lib/rpm/Packages and lays
// them out in a fresh BerkeleyDB hash file. The blobs are what rpm wrote; the
// framing is what the script wrote.
//
// The reader itself was separately checked against the REAL 11 MB ubi8 file
// and against syft reading the same image: 183 packages each, all 183 shared,
// syft's only extras being the two gpg-pubkey keyring entries this build
// filters, and zero source-name disagreements. That run is recorded in the
// roadmap rather than here, because an 11 MB fixture is not worth committing.
const (
	bdbFixture   = "testdata/Packages"
	bdbFixtureBE = "testdata/Packages-bigendian"
	bdbPath      = "/var/lib/rpm/Packages"
)

// Every package in the fixture, with the NEVRA and source name the real ubi8
// headers encode.
func TestReadBDB_Fixture(t *testing.T) {
	res, err := ReadBDB(read(t, bdbFixture), "Red Hat:8", bdbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("skipped %d records, want none: %v", len(res.Skipped), res.Skipped)
	}
	want := map[string]struct{ version, source string }{
		"basesystem":   {"11-5.el8", "basesystem"},
		"langpacks-en": {"1.0-12.el8", "langpacks"},
		"libnsl2":      {"1.2.0-2.20180605git4a062cf.el8", "libnsl2"},
		"librhsm":      {"0.0.3-5.el8", "librhsm"},
		"passwd":       {"0.80-4.el8", "passwd"},
		"subscription-manager-rhsm-certificates": {
			"20220623-1.el8", "subscription-manager-rhsm-certificates"},
	}
	if len(res.Packages) != len(want) {
		t.Fatalf("read %d packages, want %d: %+v", len(res.Packages), len(want), res.Packages)
	}
	for _, p := range res.Packages {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected package %s", p.Name)
			continue
		}
		if p.Version != w.version {
			t.Errorf("%s version = %q, want %q", p.Name, p.Version, w.version)
		}
		// D8's indirection. The header parser is shared with the SQLite
		// backend, and this asserts it is actually reached on this path rather
		// than the packages arriving with no source at all.
		if p.Source == nil || p.Source.Name != w.source {
			t.Errorf("%s Source = %+v, want name %q", p.Name, p.Source, w.source)
		}
		if p.Ecosystem != "Red Hat:8" {
			t.Errorf("%s ecosystem = %q", p.Name, p.Ecosystem)
		}
		if len(p.Locations) != 1 || p.Locations[0].Path != bdbPath {
			t.Errorf("%s Locations = %+v", p.Name, p.Locations)
		}
	}
	// The source database carries two gpg-pubkey keyring entries and the
	// fixture holds both, so this asserts the filter runs on this path too and
	// not only on the SQLite one.
	for _, p := range res.Packages {
		if p.Name == "gpg-pubkey" {
			t.Error("a gpg-pubkey keyring entry was reported as an installed package")
		}
	}
}

// Overflow chains, asserted on the recovered byte counts rather than on the
// packages: a NEVRA's tags sit in the first few hundred bytes of a header, so
// a reader that dropped every page after the first would still produce six
// plausible packages and only the lengths would say otherwise.
func TestBDB_OverflowRecoversWholeBlobs(t *testing.T) {
	f, err := openBDB(read(t, bdbFixture))
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for pgno := uint32(1); pgno <= f.lastPgno; pgno++ {
		p, err := f.page(pgno)
		if err != nil {
			t.Fatal(err)
		}
		if p[bdbHashMetaAtOff] != bdbHash && p[bdbHashMetaAtOff] != bdbHashUnsorted {
			continue
		}
		items, err := f.items(p, pgno)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(items); i += 2 {
			if isBDBZeroKey(f, items[i-1]) {
				continue
			}
			b, err := f.value(items[i])
			if err != nil {
				t.Fatal(err)
			}
			sizes = append(sizes, len(b))
		}
	}
	// Printed by the fixture builder, which read them out of the real database.
	want := []int{3968, 4696, 5136, 5564, 6380, 6400, 6936, 26312}
	if len(sizes) != len(want) {
		t.Fatalf("recovered %d blobs, want %d: %v", len(sizes), len(want), sizes)
	}
	got := map[int]bool{}
	for _, s := range sizes {
		got[s] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("no blob of %d bytes was recovered; sizes = %v", w, sizes)
		}
	}
	// And at least one chain long enough that a single-page reader would be
	// caught. Asserted rather than assumed: regenerating the fixture with only
	// small packages would leave this test passing while exercising nothing.
	usable := f.pageSize - bdbPageHeaderLen
	longest := 0
	for _, s := range sizes {
		if s > longest {
			longest = s
		}
	}
	if longest < 5*usable {
		t.Errorf("the longest blob is %d bytes over %d-byte pages; the fixture no longer "+
			"exercises a multi-page overflow chain", longest, usable)
	}
}

// BerkeleyDB writes its integers in HOST order, and s390x is a supported RHEL
// platform. The magic doubles as the byte-order probe, so a big-endian
// database must read exactly like a little-endian one.
func TestReadBDB_BigEndian(t *testing.T) {
	be := read(t, bdbFixtureBE)
	// The fixture really is big-endian. Without this the test would pass
	// against a reader that ignored byte order entirely, on a file that
	// happened to be little-endian.
	if binary.LittleEndian.Uint32(be[12:16]) == bdbHashMagic {
		t.Fatal("the big-endian fixture reads as little-endian; it is not testing byte order")
	}
	res, err := ReadBDB(be, "Red Hat:8", bdbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) == 0 {
		t.Fatal("a big-endian database yielded no packages")
	}
	for _, p := range res.Packages {
		if p.Version == "" || p.Source == nil {
			t.Errorf("%s came back incomplete: %+v", p.Name, p)
		}
	}
	// The two orders must agree about CONTENT, not merely both avoid erroring.
	// Compared against the little-endian fixture rather than against a hard
	// list, so regenerating either fixture cannot leave this asserting nothing:
	// both are built from the same source database, so every package the
	// big-endian one holds must appear identically in the little-endian one.
	le, err := ReadBDB(read(t, bdbFixture), "Red Hat:8", bdbPath)
	if err != nil {
		t.Fatal(err)
	}
	leByName := map[string]string{}
	for _, p := range le.Packages {
		leByName[p.Name] = p.Version
	}
	if len(res.Packages) < 2 {
		t.Fatalf("the big-endian fixture holds %d packages; too few to compare", len(res.Packages))
	}
	for _, p := range res.Packages {
		v, ok := leByName[p.Name]
		if !ok {
			t.Errorf("%s is in the big-endian read but not the little-endian one", p.Name)
			continue
		}
		if v != p.Version {
			t.Errorf("%s reads as %q big-endian and %q little-endian", p.Name, p.Version, v)
		}
	}
}

// Files that are not this format, and files that are but are damaged. Each
// must name what it found, because "no packages" from a scanner is a clean
// verdict.
func TestReadBDB_Rejects(t *testing.T) {
	good := read(t, bdbFixture)

	// One of rpm's nineteen btree index files, which sit in the same directory.
	btree := make([]byte, 4096)
	binary.LittleEndian.PutUint32(btree[12:16], bdbBtreeMagic)

	// A SQLite database, which is what RHEL 9 keeps at the sibling path.
	sqlite := append([]byte(sqliteMagic), 0)
	sqlite = append(sqlite, make([]byte, 4096)...)

	// last_pgno says the file extends further than it does.
	truncated := good[:len(good)-4096]

	badPageSize := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(badPageSize[20:24], 3000)

	wrongMetaType := append([]byte(nil), good...)
	wrongMetaType[bdbHashMetaAtOff] = 9

	for _, tc := range []struct {
		name, want string
		in         []byte
	}{
		{"empty", "too short", nil},
		{"a btree index file", "BTREE", btree},
		{"a SQLite database", "not a BerkeleyDB", sqlite},
		{"truncated", "truncated", truncated},
		{"page size that is not a power of two", "power of two", badPageSize},
		{"metadata page of the wrong type", "type", wrongMetaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ReadBDB(tc.in, "Red Hat:8", bdbPath)
			if !errors.Is(err, ErrBDB) {
				t.Fatalf("err = %v, want one wrapping ErrBDB (got %d packages)", err, len(res.Packages))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// A database whose pages hold no hash records at all is a read that went
// wrong, not an empty machine.
func TestReadBDB_NoRecordsIsAnError(t *testing.T) {
	b := append([]byte(nil), read(t, bdbFixture)...)
	f, err := openBDB(b)
	if err != nil {
		t.Fatal(err)
	}
	for pgno := uint32(1); pgno <= f.lastPgno; pgno++ {
		off := int(pgno)*f.pageSize + bdbHashMetaAtOff
		if b[off] == bdbHash || b[off] == bdbHashUnsorted {
			b[off] = bdbOverflow
		}
	}
	if _, err := ReadBDB(b, "Red Hat:8", bdbPath); !errors.Is(err, ErrBDB) {
		t.Errorf("a database with no hash pages read as %v, want an error", err)
	}
}

// A damaged overflow chain is a counted skip, not a shorter package list and
// not a failed scan: the other records in the file are still worth reporting.
func TestReadBDB_BrokenChainIsSkippedNotDropped(t *testing.T) {
	b := append([]byte(nil), read(t, bdbFixture)...)
	f, err := openBDB(b)
	if err != nil {
		t.Fatal(err)
	}
	// Break the chain belonging to a NAMED package rather than to whichever
	// overflow page comes first. The first one turned out to belong to a
	// gpg-pubkey record, which is filtered anyway — so the test passed its skip
	// assertion while the package count never moved, and it would have gone on
	// passing if the skip had been a silent drop.
	const victim = "librhsm"
	if !breakChainOf(t, f, b, victim) {
		t.Fatalf("%s is not in the fixture; this test no longer damages a real package", victim)
	}
	res, err := ReadBDB(b, "Red Hat:8", bdbPath)
	if err != nil {
		t.Fatalf("one broken chain failed the whole read: %v", err)
	}
	if len(res.Skipped) != 1 {
		t.Errorf("Skipped = %v, want exactly one record accounted for", res.Skipped)
	}
	if len(res.Packages) != 5 {
		t.Errorf("read %d packages, want the other 5", len(res.Packages))
	}
	for _, p := range res.Packages {
		if p.Name == victim {
			t.Errorf("%s came back despite its chain being broken", victim)
		}
	}
}

// breakChainOf corrupts the first overflow page of the record whose header
// names pkg, editing b in place. Reports whether it found one.
func breakChainOf(t *testing.T, f *bdbFile, b []byte, pkg string) bool {
	t.Helper()
	for pgno := uint32(1); pgno <= f.lastPgno; pgno++ {
		p, err := f.page(pgno)
		if err != nil {
			t.Fatal(err)
		}
		if p[bdbHashMetaAtOff] != bdbHash && p[bdbHashMetaAtOff] != bdbHashUnsorted {
			continue
		}
		items, err := f.items(p, pgno)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(items); i += 2 {
			if isBDBZeroKey(f, items[i-1]) {
				continue
			}
			blob, err := f.value(items[i])
			if err != nil {
				continue
			}
			h, err := parseHeader(blob)
			if err != nil {
				continue
			}
			if name, _ := h.str(tagName); name != pkg {
				continue
			}
			it := items[i]
			if it[0] != bdbOffPage {
				t.Fatalf("%s is stored inline; this test needs an off-page record", pkg)
			}
			first := f.order.Uint32(it[4:8])
			b[int(first)*f.pageSize+bdbHashMetaAtOff] = 99
			return true
		}
	}
	return false
}

// The key-0 counter, used in the one direction it constrains. Recovering more
// records than rpm has ever allocated header numbers means the walk is reading
// something that is not a record.
func TestReadBDB_MoreRecordsThanHeaderNumbersIsAnError(t *testing.T) {
	b := append([]byte(nil), read(t, bdbFixture)...)
	f, err := openBDB(b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := f.page(1)
	if err != nil {
		t.Fatal(err)
	}
	items, err := f.items(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(items); i += 2 {
		if !isBDBZeroKey(f, items[i]) {
			continue
		}
		// items are slices of b, so writing through one edits the file.
		f.order.PutUint32(items[i+1][1:5], 1)
		break
	}
	_, err = ReadBDB(b, "Red Hat:8", bdbPath)
	if !errors.Is(err, ErrBDB) {
		t.Fatalf("err = %v, want one wrapping ErrBDB", err)
	}
	if !strings.Contains(err.Error(), "header numbers") {
		t.Errorf("error %q does not name the check that failed", err)
	}
}

// The fixtures are committed; a rename or a stray clean is caught here rather
// than as a confusing failure inside every other test.
func TestBDBFixturesExist(t *testing.T) {
	for _, p := range []string{bdbFixture, bdbFixtureBE} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("fixture %s: %v", p, err)
		}
	}
}

// The three branches the fixture cannot reach, because a well-formed database
// written by rpm never takes them. Each survived a mutation round before this
// test existed, which is what a branch with no reachable input looks like.

// A slot offset that points outside the content area. The offsets also carry
// each item's LENGTH implicitly — an item runs from its own offset up to the
// previous one — so an offset above its predecessor would produce a negative
// length and a slice panic rather than an error.
func TestBDB_RejectsBadSlotOffsets(t *testing.T) {
	base := read(t, bdbFixture)
	f, err := openBDB(base)
	if err != nil {
		t.Fatal(err)
	}
	n := int(f.order.Uint16(base[f.pageSize+20 : f.pageSize+22]))
	slot := func(i int) int { return f.pageSize + bdbPageHeaderLen + i*2 }

	for _, tc := range []struct {
		name string
		i    int
		off  uint16
		want string
	}{
		// Into the page header and the slot array itself.
		{"inside the header", 1, 4, "outside the content area"},
		{"inside the slot array", 1, uint16(bdbPageHeaderLen + n*2 - 2), "outside the content area"},
		// Above the item allocated before it, which is what would make the
		// length negative.
		{"above its predecessor", 1, uint16(f.pageSize), "not below the item before it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), base...)
			f.order.PutUint16(b[slot(tc.i):slot(tc.i)+2], tc.off)
			_, err := ReadBDB(b, "Red Hat:8", bdbPath)
			if !errors.Is(err, ErrBDB) {
				t.Fatalf("err = %v, want one wrapping ErrBDB", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// An INLINE data item. rpm never writes one for a package — the smallest real
// header in a ubi8 database is 3,968 bytes and a page holds 4,070 — but the
// format allows it, and anchore/go-rpmdb handles only the off-page form. A
// reader that rejected inline values would silently drop any package small
// enough to fit, which is the shape of miss this project exists to prevent.
func TestBDB_ReadsInlineValues(t *testing.T) {
	f, err := openBDB(read(t, bdbFixture))
	if err != nil {
		t.Fatal(err)
	}
	item := append([]byte{bdbKeyData}, []byte("a small header would live here")...)
	got, err := f.value(item)
	if err != nil {
		t.Fatalf("an inline value was rejected: %v", err)
	}
	if string(got) != "a small header would live here" {
		t.Errorf("value = %q", got)
	}
	// And an item type this build does not read is named rather than returning
	// empty bytes that would parse as a truncated header.
	if _, err := f.value([]byte{4, 0, 0, 0}); err == nil {
		t.Error("an H_OFFDUP item was accepted")
	}
}

// An overflow page that claims to hold more bytes than the item still needs.
// The clamp is invisible on any file rpm wrote — every chain's last page
// declares exactly the remainder — so without this the branch has no input.
// Its absence would return a blob longer than the item declared, and
// parseHeader ignores trailing bytes, so the over-read would never surface.
func TestBDB_OverflowStopsAtTheItemLength(t *testing.T) {
	b := append([]byte(nil), read(t, bdbFixture)...)
	f, err := openBDB(b)
	if err != nil {
		t.Fatal(err)
	}
	// Find a chain and overstate its LAST page's used-bytes count.
	var pgno, tlen uint32
	p, err := f.page(1)
	if err != nil {
		t.Fatal(err)
	}
	items, err := f.items(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(items); i += 2 {
		if items[i][0] == bdbOffPage {
			pgno = f.order.Uint32(items[i][4:8])
			tlen = f.order.Uint32(items[i][8:12])
			break
		}
	}
	if pgno == 0 {
		t.Fatal("no off-page item in the fixture")
	}
	last := pgno
	for {
		pg, err := f.page(last)
		if err != nil {
			t.Fatal(err)
		}
		next := f.order.Uint32(pg[16:20])
		if next == 0 {
			break
		}
		last = next
	}
	off := int(last)*f.pageSize + 22
	f.order.PutUint16(b[off:off+2], uint16(f.pageSize-bdbPageHeaderLen))

	got, err := f.overflow(pgno, tlen)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != int(tlen) {
		t.Errorf("overflow returned %d bytes for an item declaring %d; the copy is not "+
			"bounded by what the item still needs", len(got), tlen)
	}
}
