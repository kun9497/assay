package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// ErrSQLite means the database could not be read as a whole — a wrong format,
// a lying length, a damaged page. Unlike ErrHeader it fails the scan: one
// unreadable record is a counted skip, but a file we cannot walk tells us
// nothing about how many records we did not see.
var ErrSQLite = errors.New("unreadable sqlite rpmdb")

// ErrWALNotChecked is returned when the caller did not say whether a
// write-ahead log exists. It is a programming error, not a data error, and it
// exists because the alternative — defaulting to "no log" — is the exact
// silent miss D45 was written about.
var ErrWALNotChecked = errors.New("the sibling -wal file was not checked")

// SQLite file-format constants. Only what a read needs; there is no write path
// and no journal handling.
const (
	sqliteMagic     = "SQLite format 3"
	sqliteHeaderLen = 100
	// walHeaderLen is the size of a write-ahead log that contains no frames.
	// Anything larger holds at least one page image that is not in the main
	// file (D45).
	walHeaderLen = 32
	// WALAbsent is the walSize a caller passes when the image carries no -wal
	// sibling at all, as distinct from one that exists and is empty. Exported
	// because the caller has to name it: a bare 0 would be a plausible-looking
	// "no log" that actually means "an empty one", and the difference is the
	// whole of D45.
	WALAbsent = -1

	// B-tree page types. Index pages are never decoded — a scanner enumerates
	// the table and never looks a row up — but they are still walked
	// structurally, because a damaged index is evidence the file is damaged.
	pageInteriorIndex = 0x02
	pageInteriorTable = 0x05
	pageLeafIndex     = 0x0a
	pageLeafTable     = 0x0d
)

// maxPagesWalked bounds a traversal so a cyclic child pointer in a damaged
// file cannot spin forever. Real rpmdbs run to a few thousand pages; the ubi9
// database is 488 and its largest blob alone spans about 1,220 overflow pages,
// so the cap is set far above both.
const maxPagesWalked = 1 << 22

// Result is what one database yielded: the packages, and the records that
// could not be read.
//
// Skipped is a slice rather than a count because the report has to be able to
// say WHICH record it could not read. A bare number tells a reader that
// something is missing without telling them whether it matters.
type Result struct {
	Packages []pkgmeta.Package
	Skipped  []string
}

// ReadSQLite reads an rpmdb.sqlite and returns the packages it holds.
//
// walSize is the size in bytes of the sibling rpmdb.sqlite-wal file, or
// WALAbsent (-1) when there is no such file. It is a REQUIRED argument rather
// than something this function discovers, and that is the whole of D45:
//
// rpm always opens its database in WAL mode. Every rpmdb.sqlite measured —
// ten of them, across seven distributions — carries file-format write and read
// version bytes of exactly 2, which is the WAL encoding. So the obvious guard,
// "refuse if the header says WAL", refuses every RPM database ever written,
// and the guard that avoids that mistake by testing `> 2` can never fire at
// all. A research prototype shipped exactly that, with a comment above it
// saying it refused rather than silently reporting a stale package list, and
// it was demonstrated returning 186 packages against a true 189 with a live
// 28,872-byte log — exit 0, no error, one installed package invisible.
//
// The only guard that works reads the OTHER FILE, which is why this signature
// takes a size instead of a bare []byte.
func ReadSQLite(db []byte, walSize int64, ecosystem, path string) (Result, error) {
	if walSize < WALAbsent {
		return Result{}, ErrWALNotChecked
	}
	if walSize > walHeaderLen {
		// Refused, not replayed. Replaying the log would be the better answer
		// and is recorded as deferred; refusing is the answer that cannot be
		// quietly wrong, and this path has never been observed on a real image.
		return Result{}, fmt.Errorf(
			"%w: %s has a %d-byte write-ahead log, so the database file alone is not current; "+
				"copy the -wal and -shm files alongside it, or checkpoint the database first",
			ErrSQLite, path, walSize)
	}

	f, err := openSQLite(db)
	if err != nil {
		return Result{}, err
	}
	roots, packagesRoot, err := f.schemaRoots()
	if err != nil {
		return Result{}, err
	}
	if packagesRoot == 0 {
		return Result{}, fmt.Errorf("%w: %s has no Packages table", ErrSQLite, path)
	}
	// Every b-tree in the file is walked structurally before any of it is
	// trusted, not just the one this cataloger reads. An ubi9 database holds
	// roughly twenty tables and twenty-five indices; overwriting the root page
	// of ONE index (Recommendname, page 41) with 0xFF left the Packages walk
	// untouched and produced 186 packages and no error, where real SQLite
	// calls the image malformed. Corruption is rarely confined to the pages
	// you happen to read.
	if err := f.validate(roots); err != nil {
		return Result{}, fmt.Errorf("%w: %s: %v", ErrSQLite, path, err)
	}

	var out Result
	err = f.walkTable(packagesRoot, func(rowid int64, cols [][]byte) error {
		// Packages is (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT
		// NULL). The blob is the last column rather than a fixed index because
		// an INTEGER PRIMARY KEY is stored as a NULL column whose value is the
		// rowid, so counting from the front is one schema change away from
		// reading the wrong thing.
		if len(cols) == 0 {
			out.Skipped = append(out.Skipped, fmt.Sprintf("row %d: no columns", rowid))
			return nil
		}
		h, err := parseHeader(cols[len(cols)-1])
		if err != nil {
			out.Skipped = append(out.Skipped, fmt.Sprintf("row %d: %v", rowid, err))
			return nil
		}
		if isPubkey(h) {
			return nil
		}
		p, err := toPackage(h, ecosystem, path)
		if err != nil {
			out.Skipped = append(out.Skipped, fmt.Sprintf("row %d: %v", rowid, err))
			return nil
		}
		out.Packages = append(out.Packages, p)
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s: %v", ErrSQLite, path, err)
	}
	return out, nil
}

// sqliteFile is a database opened for reading: the bytes, plus the two sizes
// every offset in the format is computed from.
type sqliteFile struct {
	data     []byte
	pageSize int // as declared in the header
	usable   int // pageSize minus the reserved tail; every payload formula uses this, not pageSize
	pages    int
}

func openSQLite(db []byte) (*sqliteFile, error) {
	if len(db) < sqliteHeaderLen {
		return nil, fmt.Errorf("%w: file is %d bytes, shorter than the 100-byte header", ErrSQLite, len(db))
	}
	if string(db[:len(sqliteMagic)]) != sqliteMagic || db[15] != 0 {
		return nil, fmt.Errorf("%w: not a SQLite file (wrong magic)", ErrSQLite)
	}
	pageSize := int(binary.BigEndian.Uint16(db[16:18]))
	if pageSize == 1 {
		// The one special case in the field: 1 encodes 65536, which does not
		// fit the 16 bits it is stored in.
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d is not a power of two of at least 512", ErrSQLite, pageSize)
	}
	usable := pageSize - int(db[20])
	if usable < 480 {
		return nil, fmt.Errorf("%w: usable page size %d is below the format's minimum of 480", ErrSQLite, usable)
	}
	if len(db)%pageSize != 0 {
		return nil, fmt.Errorf("%w: file is %d bytes, not a whole number of %d-byte pages",
			ErrSQLite, len(db), pageSize)
	}
	return &sqliteFile{data: db, pageSize: pageSize, usable: usable, pages: len(db) / pageSize}, nil
}

// page returns the bytes of page n, which is 1-based. Only the usable prefix
// is returned: the reserved tail is not part of any structure, and including
// it would let a cell pointer address bytes the format says are not there.
func (f *sqliteFile) page(n uint32) ([]byte, error) {
	if n == 0 || int(n) > f.pages {
		return nil, fmt.Errorf("page %d out of range (the file has %d)", n, f.pages)
	}
	off := (int(n) - 1) * f.pageSize
	return f.data[off : off+f.usable], nil
}

// btreeOffset is where a page's b-tree header starts. Page 1 carries the
// 100-byte database header first; every other page starts at zero.
func btreeOffset(n uint32) int {
	if n == 1 {
		return sqliteHeaderLen
	}
	return 0
}

// btreePage is one page's decoded b-tree header plus its cell pointer array.
type btreePage struct {
	num      uint32
	typ      byte
	cells    []int  // byte offsets into the page, one per cell
	rightPtr uint32 // interior pages only
	data     []byte
}

func (f *sqliteFile) btree(n uint32) (btreePage, error) {
	p, err := f.page(n)
	if err != nil {
		return btreePage{}, err
	}
	off := btreeOffset(n)
	if off+12 > len(p) {
		return btreePage{}, fmt.Errorf("page %d is too short to hold a b-tree header", n)
	}
	b := btreePage{num: n, typ: p[off], data: p}
	hdrLen := 8
	switch b.typ {
	case pageInteriorIndex, pageInteriorTable:
		hdrLen = 12
		b.rightPtr = binary.BigEndian.Uint32(p[off+8 : off+12])
	case pageLeafIndex, pageLeafTable:
	default:
		// A page whose type byte is not one of the four is the shape a
		// zero-filled or overwritten page takes, and it is exactly what the
		// corrupted-page fixture produces.
		return btreePage{}, fmt.Errorf("page %d has b-tree type 0x%02x, which is not a b-tree page", n, b.typ)
	}
	ncells := int(binary.BigEndian.Uint16(p[off+3 : off+5]))
	ptrStart := off + hdrLen
	if ptrStart+ncells*2 > len(p) {
		return btreePage{}, fmt.Errorf("page %d claims %d cells, whose pointer array does not fit", n, ncells)
	}
	b.cells = make([]int, 0, ncells)
	for i := 0; i < ncells; i++ {
		c := int(binary.BigEndian.Uint16(p[ptrStart+i*2 : ptrStart+i*2+2]))
		if c < ptrStart+ncells*2 || c >= len(p) {
			return btreePage{}, fmt.Errorf("page %d cell %d points to offset %d, outside the content area", n, i, c)
		}
		b.cells = append(b.cells, c)
	}
	return b, nil
}

// walkTable calls visit for every row of the table rooted at root, in b-tree
// order. Only table pages are accepted: an index page reached from a table
// root means the schema and the file disagree.
func (f *sqliteFile) walkTable(root uint32, visit func(rowid int64, cols [][]byte) error) error {
	seen := map[uint32]bool{}
	budget := maxPagesWalked
	var walk func(n uint32) error
	walk = func(n uint32) error {
		if seen[n] {
			return fmt.Errorf("page %d is reachable twice; the b-tree has a cycle", n)
		}
		seen[n] = true
		if budget--; budget < 0 {
			return errors.New("walked more pages than the file can hold")
		}
		b, err := f.btree(n)
		if err != nil {
			return err
		}
		switch b.typ {
		case pageInteriorTable:
			for i, c := range b.cells {
				if c+4 > len(b.data) {
					return fmt.Errorf("page %d cell %d has no child pointer", n, i)
				}
				if err := walk(binary.BigEndian.Uint32(b.data[c : c+4])); err != nil {
					return err
				}
			}
			return walk(b.rightPtr)
		case pageLeafTable:
			for i, c := range b.cells {
				rowid, payload, err := f.leafCell(b, c)
				if err != nil {
					return fmt.Errorf("page %d cell %d: %w", n, i, err)
				}
				cols, err := decodeRecord(payload)
				if err != nil {
					return fmt.Errorf("page %d cell %d: %w", n, i, err)
				}
				if err := visit(rowid, cols); err != nil {
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("page %d has type 0x%02x where a table page was expected", n, b.typ)
		}
	}
	return walk(root)
}

// leafCell reads one table-leaf cell, following the overflow chain when the
// payload does not fit on the page.
//
// Overflow is the NORMAL path here, not an edge case: 187 of 188 blobs in a
// ubi9 database exceed one page and the largest is 5,008,200 bytes across
// roughly 1,220 overflow pages, because an RPM header carries the package's
// whole file list. A reader that handles only the local case silently
// truncates almost every header it meets, and a truncated header does not
// error — it parses, with whatever tags happened to land in the first 4 KB.
func (f *sqliteFile) leafCell(b btreePage, off int) (int64, []byte, error) {
	cell := b.data[off:]
	size, n1, ok := uvarint(cell)
	if !ok {
		return 0, nil, errors.New("payload size varint is truncated")
	}
	rowid, n2, ok := uvarint(cell[n1:])
	if !ok {
		return 0, nil, errors.New("rowid varint is truncated")
	}
	body := cell[n1+n2:]
	if size > uint64(len(f.data)) {
		return 0, nil, fmt.Errorf("cell claims a %d-byte payload, larger than the file", size)
	}

	// The format's own thresholds, spelled as the specification spells them so
	// they can be checked against it. Getting K wrong does not fail — it moves
	// the overflow boundary by a few bytes and corrupts the tail of every
	// large payload, which reads as a damaged header rather than as a bug here.
	u := f.usable
	x := u - 35
	local := int(size)
	if int(size) > x {
		m := ((u-12)*32)/255 - 23
		k := m + (int(size)-m)%(u-4)
		if k <= x {
			local = k
		} else {
			local = m
		}
	}
	if local < 0 || local > len(body) {
		return 0, nil, fmt.Errorf("cell's local payload of %d bytes does not fit in %d remaining", local, len(body))
	}
	out := make([]byte, 0, size)
	out = append(out, body[:local]...)
	if uint64(local) == size {
		return int64(rowid), out, nil
	}

	if local+4 > len(body) {
		return 0, nil, errors.New("cell overflows but has no overflow page pointer")
	}
	next := binary.BigEndian.Uint32(body[local : local+4])
	seen := map[uint32]bool{}
	for uint64(len(out)) < size {
		if next == 0 {
			return 0, nil, fmt.Errorf("overflow chain ended after %d of %d bytes", len(out), size)
		}
		if seen[next] {
			return 0, nil, fmt.Errorf("overflow page %d is reachable twice; the chain has a cycle", next)
		}
		seen[next] = true
		p, err := f.page(next)
		if err != nil {
			return 0, nil, err
		}
		// An overflow page is a 4-byte next-page pointer followed by content.
		// The last page in a chain is not truncated on disk, so the copy is
		// bounded by what is still owed rather than by the page.
		want := int(size) - len(out)
		if want > u-4 {
			want = u - 4
		}
		out = append(out, p[4:4+want]...)
		next = binary.BigEndian.Uint32(p[0:4])
	}
	return int64(rowid), out, nil
}

// decodeRecord splits one row's payload into its column values.
//
// Integers are returned in their stored big-endian form rather than decoded:
// the only column this cataloger reads is a BLOB, and a decoder that also
// converted integers would be code with no caller and no test that could fail
// on it.
func decodeRecord(payload []byte) ([][]byte, error) {
	hdrLen, n, ok := uvarint(payload)
	if !ok || hdrLen < uint64(n) || hdrLen > uint64(len(payload)) {
		return nil, errors.New("record header length is missing or out of range")
	}
	var (
		types []uint64
		at    = n
	)
	for at < int(hdrLen) {
		t, m, ok := uvarint(payload[at:])
		if !ok {
			return nil, errors.New("record header ends mid-varint")
		}
		types = append(types, t)
		at += m
	}
	body := payload[hdrLen:]
	cols := make([][]byte, 0, len(types))
	for _, t := range types {
		n, err := serialSize(t)
		if err != nil {
			return nil, err
		}
		if n > len(body) {
			return nil, fmt.Errorf("column of %d bytes runs past the %d remaining", n, len(body))
		}
		cols = append(cols, body[:n])
		body = body[n:]
	}
	return cols, nil
}

// serialSize is the on-disk width of one SQLite serial type. Types 8 and 9 are
// the integers 0 and 1 stored in no bytes at all, and 10 and 11 are reserved —
// a file using them is not one this build can read, which is a refusal rather
// than a guess.
func serialSize(t uint64) (int, error) {
	switch {
	case t <= 4:
		return int(t), nil // NULL, and 8/16/24/32-bit integers
	case t == 5:
		return 6, nil
	case t == 6, t == 7:
		return 8, nil // 64-bit integer, IEEE float
	case t == 8, t == 9:
		return 0, nil // the literals 0 and 1
	case t < 12:
		return 0, fmt.Errorf("serial type %d is reserved", t)
	default:
		return int((t - 12) / 2), nil // BLOB when even, TEXT when odd
	}
}

// schemaRoots reads sqlite_master, returning every b-tree root in the file and
// the one belonging to the Packages table.
//
// The Packages rootpage is looked up rather than hardcoded to 2. It is 2 on
// every image measured, and it would stay 2 right up until the day an rpm
// release adds a table before it — at which point a hardcoded reader would
// walk an index as though it were the package table and either error or, worse,
// decode something.
func (f *sqliteFile) schemaRoots() (roots []uint32, packages uint32, err error) {
	err = f.walkTable(1, func(_ int64, cols [][]byte) error {
		// sqlite_master is (type, name, tbl_name, rootpage, sql).
		if len(cols) < 4 {
			return nil
		}
		root := beInt(cols[3])
		if root <= 0 || root > int64(f.pages) {
			return nil
		}
		roots = append(roots, uint32(root))
		if string(cols[0]) == "table" && string(cols[1]) == "Packages" {
			packages = uint32(root)
		}
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading the schema: %v", ErrSQLite, err)
	}
	return roots, packages, nil
}

// validate walks every b-tree in the file for structure alone — page types,
// cell counts, cell pointers, child pointers — without decoding a single
// record. It is what turns a damaged page anywhere in the file into a refusal
// rather than a shorter package list (D45).
func (f *sqliteFile) validate(roots []uint32) error {
	seen := map[uint32]bool{}
	budget := maxPagesWalked
	var walk func(n uint32) error
	walk = func(n uint32) error {
		if seen[n] {
			// Sharing is not an error between separate trees the way it is
			// within one: a page already validated needs no second visit.
			return nil
		}
		seen[n] = true
		if budget--; budget < 0 {
			return errors.New("walked more pages than the file can hold")
		}
		b, err := f.btree(n)
		if err != nil {
			return err
		}
		if b.typ != pageInteriorTable && b.typ != pageInteriorIndex {
			return nil
		}
		for i, c := range b.cells {
			if c+4 > len(b.data) {
				return fmt.Errorf("page %d cell %d has no child pointer", n, i)
			}
			if err := walk(binary.BigEndian.Uint32(b.data[c : c+4])); err != nil {
				return err
			}
		}
		return walk(b.rightPtr)
	}
	for _, r := range roots {
		if err := walk(r); err != nil {
			return err
		}
	}
	return nil
}

// uvarint reads SQLite's big-endian base-128 varint: up to eight bytes
// carrying seven bits each, and a ninth carrying all eight.
func uvarint(b []byte) (uint64, int, bool) {
	var v uint64
	for i := 0; i < 8; i++ {
		if i >= len(b) {
			return 0, 0, false
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1, true
		}
	}
	if len(b) < 9 {
		return 0, 0, false
	}
	return v<<8 | uint64(b[8]), 9, true
}

// beInt reads a big-endian two's-complement integer of the width SQLite stored
// it in. Zero-width columns are the literals 0 and 1, which sqlite_master's
// rootpage never uses, so they read as 0 and are rejected by the caller's
// range check rather than by a special case here.
func beInt(b []byte) int64 {
	if len(b) == 0 {
		return 0
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	return v
}
