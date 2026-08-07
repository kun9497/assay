package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrBDB means the BerkeleyDB database could not be read as a whole. Like
// ErrSQLite it fails the scan: one unreadable record is a counted skip, but a
// file we cannot walk tells us nothing about how many records we did not see.
var ErrBDB = errors.New("unreadable berkeleydb rpmdb")

// BerkeleyDB on-disk constants, from the format's own headers
// (dbinc/db_page.h). Only what a read-only sequential enumeration needs.
const (
	// bdbHashMagic identifies a hash database. It sits at offset 12 of the
	// metadata page and is written in HOST byte order, which is what makes it
	// serve as the byte-order probe as well as the format check.
	bdbHashMagic = 0x00061561
	// bdbBtreeMagic is every OTHER file in /var/lib/rpm — Name, Basenames,
	// Providename and sixteen more are btree indices. Recognized so that being
	// handed one produces "this is an index, not the package database" instead
	// of "not a BerkeleyDB file".
	bdbBtreeMagic = 0x00053162

	bdbPageHeaderLen = 26 // lsn(8) pgno(4) prev(4) next(4) entries(2) hf(2) level(1) type(1)

	// Page types. A hash database holds exactly these four.
	bdbHashMeta      = 8
	bdbHash          = 13
	bdbHashUnsorted  = 2 // RHEL 5 era; identical layout, unsorted keys
	bdbOverflow      = 7
	bdbHashMetaAtOff = 25 // where the type byte lives in the metadata page

	// Hash item types, the first byte of an item.
	bdbKeyData = 1 // inline: type(1) followed by the value
	bdbOffPage = 3 // type(1) unused(3) pgno(4) tlen(4)

	bdbOffPageLen = 12
)

// maxBDBPages bounds a walk. A real Packages file is a few thousand pages —
// ubi8's is 2,724 — so the cap is far above anything genuine and exists to
// stop a corrupt next-page pointer from spinning.
const maxBDBPages = 1 << 22

// bdbFile is an opened database: the bytes plus the two facts every offset in
// the format is computed from.
type bdbFile struct {
	data     []byte
	order    binary.ByteOrder
	pageSize int
	lastPgno uint32
	pages    int
}

// ReadBDB reads a BerkeleyDB hash rpmdb — /var/lib/rpm/Packages on RHEL 8 and
// older, and on Amazon Linux 2 — and returns the packages it holds.
//
// There is no sibling-file question here, and that is worth stating because
// the SQLite backend's answer is the opposite (D45). BerkeleyDB keeps its
// shared-memory regions in __db.00N and its transaction logs in log.*, and
// NEITHER holds durable package data: the regions are caches and locks, and
// rpm's Packages is written directly. Checked against a real ubi8 image — the
// layer carries Packages, nineteen btree index files and two zero-byte lock
// files, and no __db or log entry at all.
//
// The rest is D44's argument, unchanged. A scanner only ever enumerates, so
// the hash function is never computed, the bucket array is never consulted,
// and the btree indices beside this file are never opened. That is what makes
// this ~300 lines rather than the ~850 of rpm's own read-only backend.
func ReadBDB(db []byte, ecosystem, path string) (Result, error) {
	f, err := openBDB(db)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s: %v", ErrBDB, path, err)
	}

	var (
		out        Result
		nextHdrNum int64 = -1
		records    int
	)
	for pgno := uint32(1); pgno <= f.lastPgno; pgno++ {
		p, err := f.page(pgno)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s: %v", ErrBDB, path, err)
		}
		typ := p[bdbHashMetaAtOff]
		if typ != bdbHash && typ != bdbHashUnsorted {
			continue
		}
		items, err := f.items(p, pgno)
		if err != nil {
			return Result{}, fmt.Errorf("%w: %s: %v", ErrBDB, path, err)
		}
		// Items alternate key, data. The odd ones are the values, and the
		// values are the RPM header blobs.
		for i := 0; i+1 < len(items); i += 2 {
			key, val := items[i], items[i+1]
			records++
			// Key 0 is reserved: its value is the next header number rpm will
			// hand out. It is not a package, and reading it as one would put a
			// four-byte record through the header parser on every scan.
			if isBDBZeroKey(f, key) {
				if v, ok := f.inlineUint32(val); ok {
					nextHdrNum = int64(v)
				}
				continue
			}
			blob, err := f.value(val)
			if err != nil {
				out.Skipped = append(out.Skipped, fmt.Sprintf("page %d item %d: %v", pgno, i+1, err))
				continue
			}
			h, err := parseHeader(blob)
			if err != nil {
				out.Skipped = append(out.Skipped, fmt.Sprintf("page %d item %d: %v", pgno, i+1, err))
				continue
			}
			if isPubkey(h) {
				continue
			}
			pkg, err := toPackage(h, ecosystem, path)
			if err != nil {
				out.Skipped = append(out.Skipped, fmt.Sprintf("page %d item %d: %v", pgno, i+1, err))
				continue
			}
			out.Packages = append(out.Packages, pkg)
		}
	}

	if records == 0 {
		return Result{}, fmt.Errorf(
			"%w: %s holds no hash records; a %d-page database with no packages is a read that "+
				"went wrong, not an empty machine", ErrBDB, path, f.pages)
	}
	// The format's own free consistency check, used in the ONE direction it
	// actually constrains. Key 0 holds the next header number rpm will
	// allocate, so it counts numbers HANDED OUT, not packages present: erasing
	// a package leaves its number spent, and a long-lived host legitimately
	// has far fewer records than the counter. Recovering MORE than were ever
	// allocated is the impossible direction, and it means the walk is
	// inventing records.
	if nextHdrNum >= 0 && int64(records) > nextHdrNum+1 {
		return Result{}, fmt.Errorf(
			"%w: %s yielded %d records but rpm has only ever allocated %d header numbers; "+
				"the page walk is reading something that is not a record",
			ErrBDB, path, records, nextHdrNum)
	}
	return out, nil
}

func openBDB(db []byte) (*bdbFile, error) {
	if len(db) < 512 {
		return nil, fmt.Errorf("file is %d bytes, too short for a metadata page", len(db))
	}
	f := &bdbFile{data: db}
	// The magic is written in host byte order, so reading it both ways is what
	// establishes the order for every other field. Doing it the other way
	// round — assuming little-endian because x86 is — would read a database
	// written on s390x as garbage rather than as a big-endian file.
	switch {
	case binary.LittleEndian.Uint32(db[12:16]) == bdbHashMagic:
		f.order = binary.LittleEndian
	case binary.BigEndian.Uint32(db[12:16]) == bdbHashMagic:
		f.order = binary.BigEndian
	case binary.LittleEndian.Uint32(db[12:16]) == bdbBtreeMagic,
		binary.BigEndian.Uint32(db[12:16]) == bdbBtreeMagic:
		return nil, errors.New("this is a BerkeleyDB BTREE database — one of rpm's index " +
			"files (Name, Basenames, Providename…), not the Packages database")
	default:
		return nil, fmt.Errorf("not a BerkeleyDB hash database (magic 0x%08x)",
			binary.LittleEndian.Uint32(db[12:16]))
	}
	if t := db[bdbHashMetaAtOff]; t != bdbHashMeta {
		return nil, fmt.Errorf("metadata page has type %d, want %d", t, bdbHashMeta)
	}

	f.pageSize = int(f.order.Uint32(db[20:24]))
	if f.pageSize < 512 || f.pageSize > 1<<16 || f.pageSize&(f.pageSize-1) != 0 {
		return nil, fmt.Errorf("page size %d is not a power of two between 512 and 65536", f.pageSize)
	}
	f.lastPgno = f.order.Uint32(db[32:36])
	f.pages = len(db) / f.pageSize
	// The truncation check, and the one that matters most. last_pgno is the
	// database's own statement about how far it extends; a file shorter than
	// that has been cut off, and walking what is left would produce a shorter
	// package list with no error attached.
	if int64(f.lastPgno)+1 > int64(f.pages) {
		return nil, fmt.Errorf(
			"database says its last page is %d but the file holds only %d pages of %d bytes; "+
				"it is truncated", f.lastPgno, f.pages, f.pageSize)
	}
	if f.lastPgno > maxBDBPages {
		return nil, fmt.Errorf("database claims %d pages", f.lastPgno)
	}
	return f, nil
}

func (f *bdbFile) page(n uint32) ([]byte, error) {
	if int64(n) >= int64(f.pages) {
		return nil, fmt.Errorf("page %d out of range (the file has %d)", n, f.pages)
	}
	off := int(n) * f.pageSize
	return f.data[off : off+f.pageSize], nil
}

// items returns each item on a hash page, as a slice of the page.
//
// The slot array holds one 2-byte offset per item, and an item's LENGTH is
// implied by the offset of the item allocated before it:
//
//	len(i) = (i == 0 ? pageSize : inp[i-1]) - inp[i]
//
// which is BDB's own LEN_HITEM. It works because the content area fills from
// the end of the page downward, so the offsets descend — and that is checked
// rather than assumed, because a page whose offsets do not descend would
// otherwise yield a negative length and a slice panic.
func (f *bdbFile) items(p []byte, pgno uint32) ([][]byte, error) {
	n := int(f.order.Uint16(p[20:22]))
	if n == 0 {
		return nil, nil
	}
	if bdbPageHeaderLen+n*2 > len(p) {
		return nil, fmt.Errorf("page %d claims %d items, whose offset array does not fit", pgno, n)
	}
	out := make([][]byte, 0, n)
	prev := f.pageSize
	for i := 0; i < n; i++ {
		off := int(f.order.Uint16(p[bdbPageHeaderLen+i*2 : bdbPageHeaderLen+i*2+2]))
		if off < bdbPageHeaderLen+n*2 || off > prev {
			return nil, fmt.Errorf(
				"page %d item %d is at offset %d, which is outside the content area or not "+
					"below the item before it (%d)", pgno, i, off, prev)
		}
		out = append(out, p[off:prev])
		prev = off
	}
	return out, nil
}

// isBDBZeroKey reports whether an item is the reserved key 0.
func isBDBZeroKey(f *bdbFile, item []byte) bool {
	v, ok := f.inlineUint32(item)
	return ok && v == 0
}

// inlineUint32 reads an inline item whose value is exactly four bytes.
func (f *bdbFile) inlineUint32(item []byte) (uint32, bool) {
	if len(item) != 5 || item[0] != bdbKeyData {
		return 0, false
	}
	return f.order.Uint32(item[1:5]), true
}

// value returns one data item's bytes, following the overflow chain when the
// item does not hold them inline.
//
// Both forms are handled, and the inline one is not theoretical politeness:
// anchore/go-rpmdb implements only the off-page form, and on the two images
// measured the sole inline data item is key 0's four-byte counter — safe
// today, and not guaranteed by the format. A package whose header happened to
// fit on a page would be silently dropped by an off-page-only reader.
func (f *bdbFile) value(item []byte) ([]byte, error) {
	if len(item) == 0 {
		return nil, errors.New("empty item")
	}
	switch item[0] {
	case bdbKeyData:
		return item[1:], nil
	case bdbOffPage:
		if len(item) < bdbOffPageLen {
			return nil, fmt.Errorf("off-page item is %d bytes, want %d", len(item), bdbOffPageLen)
		}
		// Bytes 1-3 are padding and are NOT zero in real files — ubi8's carry
		// leftover data — so they are skipped rather than checked.
		pgno := f.order.Uint32(item[4:8])
		tlen := f.order.Uint32(item[8:12])
		return f.overflow(pgno, tlen)
	default:
		return nil, fmt.Errorf("item type %d is not one this build reads", item[0])
	}
}

// overflow walks a chain of P_OVERFLOW pages, collecting tlen bytes.
//
// Each page's hf_offset field holds how many of its bytes are used, and
// next_pgno points on; the last page in a chain has next_pgno 0. The chains
// are long: the largest blob in a real ubi8 database is 1,140,980 bytes across
// roughly 280 pages, so this is the normal path rather than an edge case, the
// same way it is for the SQLite backend.
func (f *bdbFile) overflow(pgno, tlen uint32) ([]byte, error) {
	if int64(tlen) > int64(len(f.data)) {
		return nil, fmt.Errorf("item claims %d bytes, more than the whole file", tlen)
	}
	out := make([]byte, 0, tlen)
	seen := map[uint32]bool{}
	for uint32(len(out)) < tlen {
		if pgno == 0 {
			return nil, fmt.Errorf("overflow chain ended after %d of %d bytes", len(out), tlen)
		}
		if seen[pgno] {
			return nil, fmt.Errorf("overflow page %d is reachable twice; the chain has a cycle", pgno)
		}
		seen[pgno] = true
		p, err := f.page(pgno)
		if err != nil {
			return nil, err
		}
		if p[bdbHashMetaAtOff] != bdbOverflow {
			return nil, fmt.Errorf("page %d has type %d where an overflow page was expected",
				pgno, p[bdbHashMetaAtOff])
		}
		used := int(f.order.Uint16(p[22:24]))
		if used > f.pageSize-bdbPageHeaderLen {
			return nil, fmt.Errorf("overflow page %d says it holds %d bytes, more than a page", pgno, used)
		}
		want := int(tlen) - len(out)
		if want > used {
			want = used
		}
		out = append(out, p[bdbPageHeaderLen:bdbPageHeaderLen+want]...)
		pgno = f.order.Uint32(p[16:20])
	}
	return out, nil
}
