package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/adler32"
)

// ErrNDB means the ndb database could not be read as a whole. Like ErrBDB and
// ErrSQLite it fails the scan: one unreadable header blob is a counted skip,
// but a slot table we cannot walk tells us nothing about how many packages we
// did not see.
var ErrNDB = errors.New("unreadable ndb rpmdb")

// ndb is rpm's THIRD rpmdb container format (after BerkeleyDB and SQLite,
// D44) — openSUSE's and SLES's own, used nowhere in the Red Hat lineage. D44
// deferred it because nothing in this codebase could route its packages to an
// advisory source; docs/deferred-decisions.md's ndb entry recorded that as
// the reason, and separately measured (2026-08-19 research feeding D71–D75)
// that modern SLES/BCI images cannot be CATALOGUED at all today, independent
// of any advisory question — that half of the justification no longer holds,
// which is what D76 is. Cataloging only: an ndb image still routes to no
// ecosystem (D50 lists only `rhel`), so it scans as "not evaluated" rather
// than clean, exactly like the RPM families D44 already reads with no
// provider behind them.
//
// The record inside is the same as the other two backends: an RPM header
// blob, read by parseHeader in header.go — REUSED, not duplicated, because
// the header layer is format-agnostic (this file's own top comment says so).
//
// Every on-disk fact below was read out of
// rpm-software-management/rpm@master, lib/backend/ndb/rpmpkg.c
// (rpmpkgReadHeader, rpmpkgReadSlots, rpmpkgReadBlob) and then checked
// against a REAL registry.suse.com/bci/bci-base Packages.db pulled during
// development (not committed — see the roadmap's D76 entry for the numbers):
// the magic, the slot layout and one whole blob (header + adler32-verified
// tail) matched byte for byte. Two things the surrounding sketch got only
// approximately right, now pinned down:
//
//   - Every integer is LITTLE-ENDIAN, unconditionally. Unlike BerkeleyDB
//     (bdb.go), which writes host order and uses its magic as a byte-order
//     probe because s390x is a supported RHEL platform, ndb has no such
//     probe anywhere in rpm's source — it was written once, for x86, and the
//     format never grew one. There is no SLES/openSUSE big-endian platform
//     to make this matter in practice, but the reader does not guess: it
//     reads what the format actually specifies.
//   - A block is 16 bytes (BLK_SIZE), confirmed both in rpmpkg.c and by
//     recomputing a real blob's block count from its stored length and
//     getting the slot's own blkcnt back exactly.
type ndbFile struct {
	data       []byte
	slotnpages uint32
	nextpkgidx uint32
	fileblks   uint64
}

// ndb on-disk constants. Magic values are spelled as hex byte arrays rather
// than as string literals (CLAUDE.md: escape sequences typed into a source
// file have flattened silently before on this branch); each is annotated
// with the ASCII it encodes so the constant stays checkable against the
// rpm source by eye.
var (
	ndbMagic         = [4]byte{0x52, 0x70, 0x6d, 0x50} // "RpmP" - PKGDB_MAGIC
	ndbSlotMagic     = [4]byte{0x53, 0x6c, 0x6f, 0x74} // "Slot" - SLOT_MAGIC
	ndbBlobHeadMagic = [4]byte{0x42, 0x6c, 0x62, 0x53} // "BlbS" - BLOBHEAD_MAGIC
	ndbBlobTailMagic = [4]byte{0x42, 0x6c, 0x62, 0x45} // "BlbE" - BLOBTAIL_MAGIC
)

const (
	ndbVersion = 0 // PKGDB_VERSION; the only version this format has ever shipped

	ndbHeaderSize = 32 // PKGDB_HEADER_SIZE: magic(4) version(4) generation(4) slotnpages(4) nextpkgidx(4) + 12 reserved

	ndbSlotSize = 16   // SLOT_SIZE
	ndbBlkSize  = 16   // BLK_SIZE
	ndbPageSize = 4096 // PAGE_SIZE

	// ndbSlotStart is PKGDB_HEADER_SIZE / SLOT_SIZE: the header occupies the
	// byte range of the first two slots, so the slot table proper begins at
	// the third.
	ndbSlotStart = ndbHeaderSize / ndbSlotSize

	ndbBlobHeadSize = 16 // BLOBHEAD_SIZE: magic(4) pkgidx(4) generation(4) bloblen(4)
	ndbBlobTailSize = 12 // BLOBTAIL_SIZE: adler32(4) bloblen(4) magic(4)

	// minNDBBlkcnt is the smallest blkcnt that could hold a head and a tail
	// with zero payload — BLOBHEAD_SIZE+BLOBTAIL_SIZE rounded up to a whole
	// number of blocks, PKGDB_MAX_BLOBSIZE's own arithmetic run backwards.
	minNDBBlkcnt = (ndbBlobHeadSize + ndbBlobTailSize + ndbBlkSize - 1) / ndbBlkSize
)

// Bounds, in the same spirit as header.go's maxIndexEntries/maxDataStore: a
// damaged length field must turn into a parse error, not an allocation big
// enough to matter. The real file measured has slotnpages=1; this is far
// above that, the same "far above anything genuine" margin the BDB and
// SQLite page-walk caps use.
const (
	maxNDBSlotPages = 1 << 16 // 65,536 pages = 256 MiB of slot table
	maxNDBBlobLen   = 1 << 28 // 256 MiB, matching header.go's maxDataStore
)

// ReadNDB reads an ndb rpmdb — /usr/lib/sysimage/rpm/Packages.db, the only
// location openSUSE and SLES write it to — and returns the packages it
// holds.
//
// A scanner only ever enumerates (D44's argument, unchanged for the third
// format): rpm's own rpmpkg.c carries write, lock, salvage and index-rebuild
// logic this never needs, because a read-only walk of the slot table and its
// blobs is the whole of what "list every package" requires.
func ReadNDB(db []byte, ecosystem, path string) (Result, error) {
	f, err := openNDB(db)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s: %v", ErrNDB, path, err)
	}

	// minBlkOff is where the first blob is allowed to start: the slot region
	// itself, in blocks. rpm's own reader rejects a slot whose blkoff lands
	// inside it (rpmpkgReadSlots' "bad entry" check) because that would mean
	// a package blob overlaps the slot table it is indexed by.
	minBlkOff := uint64(f.slotnpages) * (ndbPageSize / ndbBlkSize)
	slotRegionEnd := uint64(f.slotnpages) * ndbPageSize

	var (
		out     Result
		records int
		seen    = map[uint32]bool{}
	)
	for off := uint64(ndbSlotStart) * ndbSlotSize; off+ndbSlotSize <= slotRegionEnd; off += ndbSlotSize {
		s := db[off : off+ndbSlotSize]
		// Every slot in the region carries the magic, occupied or not:
		// rpmpkgWriteEmptySlotpage stamps it into all 256 slots of a page
		// when the page is first added, and deletion (rpmpkgWriteslot with
		// pkgidx=blkoff=blkcnt=0) never touches it. So unlike blkoff==0,
		// which is the legitimate "free" marker, a missing magic here means
		// the slot table itself is damaged and nothing in it can be trusted.
		if [4]byte(s[0:4]) != ndbSlotMagic {
			return Result{}, fmt.Errorf("%w: %s: slot at byte offset %d carries no Slot magic; the slot table is corrupt",
				ErrNDB, path, off)
		}
		pkgidx := binary.LittleEndian.Uint32(s[4:8])
		blkoff := binary.LittleEndian.Uint32(s[8:12])
		blkcnt := binary.LittleEndian.Uint32(s[12:16])
		if blkoff == 0 {
			// A deleted or never-allocated slot (rpmpkgReadSlots' own free-slot
			// test is exactly this one field). Not a package, and not an error.
			continue
		}
		records++
		if pkgidx == 0 || pkgidx >= f.nextpkgidx {
			return Result{}, fmt.Errorf(
				"%w: %s: slot at byte offset %d claims package index %d, but the header says only "+
					"%d have ever been allocated", ErrNDB, path, off, pkgidx, f.nextpkgidx)
		}
		if seen[pkgidx] {
			return Result{}, fmt.Errorf(
				"%w: %s: package index %d is claimed by two slots; rpm's own writer never produces that",
				ErrNDB, path, pkgidx)
		}
		seen[pkgidx] = true
		if uint64(blkoff) < minBlkOff {
			return Result{}, fmt.Errorf(
				"%w: %s: package %d's block offset %d lands inside the slot region (< %d)",
				ErrNDB, path, pkgidx, blkoff, minBlkOff)
		}
		if uint64(blkoff)+uint64(blkcnt) > f.fileblks {
			return Result{}, fmt.Errorf(
				"%w: %s: package %d claims blocks up to %d but the file holds only %d; it is truncated",
				ErrNDB, path, pkgidx, uint64(blkoff)+uint64(blkcnt), f.fileblks)
		}

		blob, err := f.blob(pkgidx, blkoff, blkcnt)
		if err != nil {
			out.Skipped = append(out.Skipped, fmt.Sprintf("package %d: %v", pkgidx, err))
			continue
		}
		h, err := parseHeader(blob)
		if err != nil {
			out.Skipped = append(out.Skipped, fmt.Sprintf("package %d: %v", pkgidx, err))
			continue
		}
		if isPubkey(h) {
			continue
		}
		pkg, err := toPackage(h, ecosystem, path)
		if err != nil {
			out.Skipped = append(out.Skipped, fmt.Sprintf("package %d: %v", pkgidx, err))
			continue
		}
		out.Packages = append(out.Packages, pkg)
	}

	if records == 0 {
		return Result{}, fmt.Errorf(
			"%w: %s holds no occupied slots; a database with no packages is a read that went wrong, "+
				"not an empty machine", ErrNDB, path)
	}
	return out, nil
}

func openNDB(db []byte) (*ndbFile, error) {
	if len(db) < ndbHeaderSize {
		return nil, fmt.Errorf("file is %d bytes, too short for the %d-byte header", len(db), ndbHeaderSize)
	}
	if [4]byte(db[0:4]) != ndbMagic {
		return nil, fmt.Errorf("not an ndb database (magic %x, want %x)", db[0:4], ndbMagic)
	}
	version := binary.LittleEndian.Uint32(db[4:8])
	if version != ndbVersion {
		return nil, fmt.Errorf("ndb version %d, this build reads only version %d", version, ndbVersion)
	}
	slotnpages := binary.LittleEndian.Uint32(db[12:16])
	nextpkgidx := binary.LittleEndian.Uint32(db[16:20])
	if slotnpages == 0 {
		return nil, errors.New("header claims zero slot pages; there is nowhere for a package to be listed")
	}
	if slotnpages > maxNDBSlotPages {
		return nil, fmt.Errorf("header claims %d slot pages", slotnpages)
	}
	// rpm's own rpmpkgReadSlots refuses a file whose length is not a whole
	// number of blocks before it will compute fileblks at all — the same
	// "the arithmetic itself has to be the check" rule header.go's
	// parseHeader doc comment states, applied to this format's own division.
	if len(db)%ndbBlkSize != 0 {
		return nil, fmt.Errorf("file is %d bytes, not a whole number of %d-byte blocks", len(db), ndbBlkSize)
	}
	slotRegionBytes := uint64(slotnpages) * ndbPageSize
	if slotRegionBytes > uint64(len(db)) {
		return nil, fmt.Errorf("header claims %d slot pages (%d bytes), larger than the %d-byte file; it is truncated",
			slotnpages, slotRegionBytes, len(db))
	}
	return &ndbFile{
		data:       db,
		slotnpages: slotnpages,
		nextpkgidx: nextpkgidx,
		fileblks:   uint64(len(db)) / ndbBlkSize,
	}, nil
}

// blob returns one package's raw rpm header — the same shape parseHeader
// reads out of the BerkeleyDB and SQLite backends — verifying the blob's own
// framing (head magic, the pkgidx it names, the declared length against the
// blkcnt the slot reserves for it, the tail magic, and rpm's own adler32
// checksum over everything but the tail itself).
//
// rpm's own rpmpkgReadBlob skips the adler32 check on an ordinary read and
// verifies it only when explicitly asked (rpmpkgVerifyblob, called from
// rpmpkgVerify and from the neighbour-check during writes) — its normal read
// path trusts the length fields alone. This reader always verifies: the cost
// is one pass over bytes already being read, and D45's BerkeleyDB/SQLite
// backends both do full structural validation before trusting anything for
// exactly this reason.
func (f *ndbFile) blob(pkgidx, blkoff, blkcnt uint32) ([]byte, error) {
	if blkcnt < minNDBBlkcnt {
		return nil, fmt.Errorf("block count %d is too small to hold a blob head and tail", blkcnt)
	}
	start := uint64(blkoff) * ndbBlkSize
	end := start + uint64(blkcnt)*ndbBlkSize
	if end > uint64(len(f.data)) {
		return nil, fmt.Errorf("blob at block %d runs past the end of the file", blkoff)
	}
	region := f.data[start:end]

	if [4]byte(region[0:4]) != ndbBlobHeadMagic {
		return nil, errors.New("no BlbS magic at the start of the blob")
	}
	headPkgidx := binary.LittleEndian.Uint32(region[4:8])
	if headPkgidx != pkgidx {
		return nil, fmt.Errorf("blob head names package %d, the slot says %d", headPkgidx, pkgidx)
	}
	bloblen := binary.LittleEndian.Uint32(region[12:16])
	if bloblen > maxNDBBlobLen {
		return nil, fmt.Errorf("blob claims %d bytes", bloblen)
	}
	// rpm's own arithmetic (PKGDB_MAX_BLOBSIZE / rpmpkgWriteBlob), computed in
	// uint64 for the same reason header.go's parseHeader does: the overflow
	// itself has to be impossible, not merely unlikely.
	wantBlkcnt := (uint64(ndbBlobHeadSize) + uint64(bloblen) + uint64(ndbBlobTailSize) + ndbBlkSize - 1) / ndbBlkSize
	if wantBlkcnt != uint64(blkcnt) {
		return nil, fmt.Errorf("blob declares %d bytes, which needs %d blocks, but the slot reserves %d",
			bloblen, wantBlkcnt, blkcnt)
	}

	tail := region[len(region)-ndbBlobTailSize:]
	adler := binary.LittleEndian.Uint32(tail[0:4])
	tailLen := binary.LittleEndian.Uint32(tail[4:8])
	if [4]byte(tail[8:12]) != ndbBlobTailMagic {
		return nil, errors.New("no BlbE magic at the end of the blob")
	}
	if tailLen != bloblen {
		return nil, fmt.Errorf("blob head declares %d bytes, tail declares %d", bloblen, tailLen)
	}
	// rpm's update_adler32 is RFC 1950 adler32 over the head, the data and
	// the zero padding — everything but the tail itself — which is exactly
	// what Go's stdlib hash/adler32 computes, so there is nothing to
	// hand-roll.
	if got := adler32.Checksum(region[:len(region)-ndbBlobTailSize]); got != adler {
		return nil, fmt.Errorf("adler32 checksum %#08x does not match the stored %#08x; the blob is damaged", got, adler)
	}

	data := make([]byte, bloblen)
	copy(data, region[ndbBlobHeadSize:uint64(ndbBlobHeadSize)+uint64(bloblen)])
	return data, nil
}
