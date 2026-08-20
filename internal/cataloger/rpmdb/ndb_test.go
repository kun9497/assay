package rpmdb

import (
	"encoding/binary"
	"hash/adler32"
	"strings"
	"testing"
)

// ndbEntry is one slot in a synthetic ndb file: a real package's pkgidx and
// raw rpm header blob, or blob == nil for a DELETED slot — the shape
// rpmpkgWriteslot(pkgidx=0, blkoff=0, blkcnt=0) leaves behind, Slot magic
// intact, blkoff zeroed.
type ndbEntry struct {
	pkgidx uint32
	blob   []byte
}

// buildNDB assembles a complete, well-formed ndb file: one 4096-byte slot
// page (slotnpages=1 — what the real registry.suse.com/bci/bci-base
// Packages.db pulled during development turned out to use, see the roadmap's
// D76 entry) followed by each entry's blob, framed exactly as
// rpmpkgWriteBlob writes it (rpm-software-management/rpm's own
// lib/backend/ndb/rpmpkg.c). nextpkgidx is passed explicitly rather than
// derived from the entries so a test can build a file that lies about it.
func buildNDB(t *testing.T, nextpkgidx uint32, entries []ndbEntry) []byte {
	t.Helper()
	const slotnpages = 1

	header := make([]byte, ndbHeaderSize)
	copy(header[0:4], ndbMagic[:])
	binary.LittleEndian.PutUint32(header[4:8], ndbVersion)
	binary.LittleEndian.PutUint32(header[8:12], 1) // generation; never read back
	binary.LittleEndian.PutUint32(header[12:16], slotnpages)
	binary.LittleEndian.PutUint32(header[16:20], nextpkgidx)

	slotRegion := make([]byte, slotnpages*ndbPageSize)
	// Every slot in the region carries the magic, occupied or not — exactly
	// what rpmpkgWriteEmptySlotpage stamps into a freshly added page.
	for off := 0; off+ndbSlotSize <= len(slotRegion); off += ndbSlotSize {
		copy(slotRegion[off:off+4], ndbSlotMagic[:])
	}
	// The header occupies the byte range of the first two slots.
	copy(slotRegion[0:ndbHeaderSize], header)

	var blocks []byte
	blkoff := uint32(slotnpages * ndbPageSize / ndbBlkSize)
	slotOff := ndbSlotStart * ndbSlotSize
	for _, e := range entries {
		if e.blob == nil {
			// Deleted: Slot magic only (already stamped above); pkgidx,
			// blkoff and blkcnt stay zero.
			slotOff += ndbSlotSize
			continue
		}
		blob := buildNDBBlob(e.pkgidx, e.blob)
		blkcnt := uint32(len(blob) / ndbBlkSize)
		binary.LittleEndian.PutUint32(slotRegion[slotOff+4:slotOff+8], e.pkgidx)
		binary.LittleEndian.PutUint32(slotRegion[slotOff+8:slotOff+12], blkoff)
		binary.LittleEndian.PutUint32(slotRegion[slotOff+12:slotOff+16], blkcnt)
		blocks = append(blocks, blob...)
		blkoff += blkcnt
		slotOff += ndbSlotSize
	}
	return append(slotRegion, blocks...)
}

// buildNDBBlob frames one raw rpm header blob (as header_test.go's
// buildHeader produces) the way rpmpkgWriteBlob writes it to disk: a BlbS
// head, the header bytes, zero padding out to a whole number of 16-byte
// blocks, and a BlbE tail carrying rpm's own adler32 checksum over everything
// but the tail.
func buildNDBBlob(pkgidx uint32, rpmHeader []byte) []byte {
	blkcnt := (ndbBlobHeadSize + len(rpmHeader) + ndbBlobTailSize + ndbBlkSize - 1) / ndbBlkSize
	total := blkcnt * ndbBlkSize

	buf := make([]byte, total)
	copy(buf[0:4], ndbBlobHeadMagic[:])
	binary.LittleEndian.PutUint32(buf[4:8], pkgidx)
	binary.LittleEndian.PutUint32(buf[8:12], 1) // generation counter; never read back
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(rpmHeader)))
	copy(buf[ndbBlobHeadSize:], rpmHeader)
	// The padding between the header data and the tail is still zero here
	// (buf was zero-allocated), exactly what the real writer memsets it to,
	// so it is covered by the checksum below the same way.
	adl := adler32.Checksum(buf[:total-ndbBlobTailSize])
	tail := buf[total-ndbBlobTailSize:]
	binary.LittleEndian.PutUint32(tail[0:4], adl)
	binary.LittleEndian.PutUint32(tail[4:8], uint32(len(rpmHeader)))
	copy(tail[8:12], ndbBlobTailMagic[:])
	return buf
}

const ndbPath = "/usr/lib/sysimage/rpm/Packages.db"

// Two packages and one DELETED slot between them — the shape D76 exists to
// prove: a real openSUSE/SLES host accumulates deletions over its life, and a
// reader that mishandled blkoff==0 would either crash on it or report a
// phantom package.
func TestReadNDB_Fixture(t *testing.T) {
	pkgA := buildHeader(
		strTag(tagName, "libnsl2"),
		strTag(tagVersion, "1.2.0"),
		strTag(tagRelease, "5.1"),
		strTag(tagSourceRPM, "libnsl2-1.2.0-5.1.src.rpm"),
	)
	pkgB := buildHeader(
		strTag(tagName, "audit-libs"),
		strTag(tagVersion, "3.1.5"),
		strTag(tagRelease, "8.el9"),
		strTag(tagSourceRPM, "audit-3.1.5-8.el9.src.rpm"),
	)
	db := buildNDB(t, 10, []ndbEntry{
		{pkgidx: 1, blob: pkgA},
		{blob: nil}, // deleted: pkgidx 2, once real, now gone
		{pkgidx: 3, blob: pkgB},
	})

	res, err := ReadNDB(db, "openSUSE:15.6", ndbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("skipped %d records, want none: %v", len(res.Skipped), res.Skipped)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("read %d packages, want 2 (the deleted slot must not appear): %+v", len(res.Packages), res.Packages)
	}
	byName := map[string]pkgmetaSummary{}
	for _, p := range res.Packages {
		s := pkgmetaSummary{version: p.Version, ecosystem: p.Ecosystem}
		if p.Source != nil {
			s.source = p.Source.Name
		}
		byName[p.Name] = s
	}
	// D8's indirection, asserted per package: the header pipeline is shared
	// with the BDB and SQLite backends, and this is what proves it is
	// actually REACHED from ndb rather than the packages arriving unsourced.
	if got := byName["libnsl2"]; got.version != "1.2.0-5.1" || got.source != "libnsl2" || got.ecosystem != "openSUSE:15.6" {
		t.Errorf("libnsl2 = %+v, want version 1.2.0-5.1, source libnsl2, ecosystem openSUSE:15.6", got)
	}
	if got := byName["audit-libs"]; got.version != "3.1.5-8.el9" || got.source != "audit" {
		t.Errorf("audit-libs = %+v, want version 3.1.5-8.el9, source audit", got)
	}
	for _, p := range res.Packages {
		if len(p.Locations) != 1 || p.Locations[0].Path != ndbPath {
			t.Errorf("%s Locations = %+v, want path %q", p.Name, p.Locations, ndbPath)
		}
	}
}

type pkgmetaSummary struct {
	version, source, ecosystem string
}

// gpg-pubkey rows are filtered on this path too, not only on BDB/SQLite's.
func TestReadNDB_GpgPubkeyFiltered(t *testing.T) {
	pubkey := buildHeader(strTag(tagName, "gpg-pubkey"), strTag(tagVersion, "abcdef01"), strTag(tagRelease, "5f2c0000"))
	real := buildHeader(strTag(tagName, "bash"), strTag(tagVersion, "5.2"), strTag(tagRelease, "1.1"))
	db := buildNDB(t, 5, []ndbEntry{{pkgidx: 1, blob: pubkey}, {pkgidx: 2, blob: real}})

	res, err := ReadNDB(db, "", ndbPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "bash" {
		t.Errorf("Packages = %+v, want exactly bash — the gpg-pubkey keyring entry must be filtered", res.Packages)
	}
}

// A slot whose Slot magic is damaged fails the WHOLE read (D45's rule,
// applied to the third backend): the slot table is what makes every other
// pkgidx/blkoff pair trustworthy, so once it is suspect nothing downstream
// can be either.
func TestReadNDB_CorruptSlotMagicIsRefused(t *testing.T) {
	pkg := buildHeader(strTag(tagName, "bash"), strTag(tagVersion, "5.2"), strTag(tagRelease, "1.1"))
	db := buildNDB(t, 5, []ndbEntry{{pkgidx: 1, blob: pkg}})
	// Corrupt the FIRST slot in the table (byte offset ndbSlotStart*ndbSlotSize).
	off := ndbSlotStart * ndbSlotSize
	db[off] ^= 0xff

	_, err := ReadNDB(db, "", ndbPath)
	if err == nil {
		t.Fatal("a database with a damaged Slot magic was read without error")
	}
	if !strings.Contains(err.Error(), "slot table is corrupt") {
		t.Errorf("error = %v, want it to name the corrupt slot table", err)
	}
}

// A file truncated inside a blob's claimed block range is refused, not
// silently short-read — the same truncation guard D45 requires of the
// SQLite and BerkeleyDB backends.
func TestReadNDB_TruncatedFileIsRefused(t *testing.T) {
	pkg := buildHeader(strTag(tagName, "bash"), strTag(tagVersion, "5.2"), strTag(tagRelease, "1.1"))
	db := buildNDB(t, 5, []ndbEntry{{pkgidx: 1, blob: pkg}})
	truncated := db[:len(db)-32]

	_, err := ReadNDB(truncated, "", ndbPath)
	if err == nil {
		t.Fatal("a truncated ndb database was read without error")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error = %v, want it to say the database is truncated", err)
	}
}

// A blob whose adler32 checksum does not match its content is a DAMAGED
// RECORD, counted and skipped — not a whole-file failure — the same split
// bdb.go and sqlite.go draw between "the container is unreadable" and "one
// record in it is". The other, undamaged package must still be read.
func TestReadNDB_DamagedBlobIsSkippedNotFatal(t *testing.T) {
	good := buildHeader(strTag(tagName, "bash"), strTag(tagVersion, "5.2"), strTag(tagRelease, "1.1"))
	bad := buildHeader(strTag(tagName, "coreutils"), strTag(tagVersion, "9.4"), strTag(tagRelease, "1"))
	db := buildNDB(t, 5, []ndbEntry{{pkgidx: 1, blob: good}, {pkgidx: 2, blob: bad}})

	// Flip a byte inside package 2's blob DATA (not its framing), so the
	// blob's own length and magic fields still parse — only the checksum and
	// the header content disagree. Located by finding the header magic run
	// for "coreutils" specifically to avoid corrupting package 1 by accident.
	needle := []byte("coreutils")
	idx := indexBytes(db, needle)
	if idx < 0 {
		t.Fatal("fixture does not contain the expected package name; test is not exercising what it claims")
	}
	db[idx] ^= 0xff

	res, err := ReadNDB(db, "", ndbPath)
	if err != nil {
		t.Fatalf("one damaged blob failed the whole read: %v", err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "bash" {
		t.Errorf("Packages = %+v, want only bash (coreutils' blob is damaged)", res.Packages)
	}
	if len(res.Skipped) != 1 {
		t.Fatalf("Skipped = %v, want exactly 1 record", res.Skipped)
	}
	if !strings.Contains(res.Skipped[0], "adler32") && !strings.Contains(res.Skipped[0], "checksum") {
		t.Errorf("Skipped[0] = %q, want it to name the checksum failure", res.Skipped[0])
	}
}

// indexBytes is bytes.Index without the import, kept local because this is
// the only place in the package that needs it.
func indexBytes(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// A pkgidx a slot claims but the header says was never allocated is
// corruption, not a package with an unusual number.
func TestReadNDB_PkgidxBeyondNextPkgIdxIsRefused(t *testing.T) {
	pkg := buildHeader(strTag(tagName, "bash"), strTag(tagVersion, "5.2"), strTag(tagRelease, "1.1"))
	// nextpkgidx of 1 means pkgidx 1 has not been handed out yet.
	db := buildNDB(t, 1, []ndbEntry{{pkgidx: 1, blob: pkg}})

	_, err := ReadNDB(db, "", ndbPath)
	if err == nil {
		t.Fatal("a pkgidx at or beyond nextpkgidx was accepted")
	}
	if !strings.Contains(err.Error(), "allocated") {
		t.Errorf("error = %v, want it to name the allocation mismatch", err)
	}
}

// An ndb file with no occupied slots at all — every slot deleted or never
// used — is refused for the same reason ReadBDB refuses an empty hash walk:
// a read that recovers zero packages from a database that exists is a read
// that went wrong far more often than it is a genuinely empty machine.
func TestReadNDB_NoOccupiedSlotsIsRefused(t *testing.T) {
	db := buildNDB(t, 5, []ndbEntry{{blob: nil}, {blob: nil}})
	_, err := ReadNDB(db, "", ndbPath)
	if err == nil {
		t.Fatal("a database with no occupied slots was read without error")
	}
}

func TestOpenNDB_WrongMagicIsRefused(t *testing.T) {
	db := make([]byte, ndbHeaderSize+ndbPageSize)
	copy(db, "NOPE0000")
	if _, err := openNDB(db); err == nil {
		t.Fatal("a file with the wrong magic was accepted as ndb")
	}
}

func TestOpenNDB_WrongVersionIsRefused(t *testing.T) {
	db := make([]byte, ndbHeaderSize+ndbPageSize)
	copy(db[0:4], ndbMagic[:])
	binary.LittleEndian.PutUint32(db[4:8], 99)
	binary.LittleEndian.PutUint32(db[12:16], 1)
	if _, err := openNDB(db); err == nil {
		t.Fatal("a file claiming an unknown ndb version was accepted")
	}
}
