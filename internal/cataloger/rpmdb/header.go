// Package rpmdb turns an RPM installed-package database into the normalized
// inventory.
//
// Three things make this different from every cataloger before it, and all
// three are why D44 exists:
//
//   - The database is BINARY, not a text stanza file. apk and dpkg are read
//     line by line; this walks pages.
//   - The container format changed mid-lineage, and diverged again outside
//     it. RHEL 8 and older keep a BerkeleyDB hash database, RHEL 9 and newer
//     a SQLite one, and openSUSE and SLES a third (ndb, D76) that no Red Hat
//     distro uses.
//   - The record inside is the same in all of them: an RPM header blob, which
//     this file reads.
//
// What is NOT here is any lookup by name. rpm's own read-only BerkeleyDB
// backend is ~850 lines of C because `rpm -q openssl` is a point lookup and
// needs the hash index; a scanner only ever enumerates, so the index, the
// btree backend and the SQL layer are all dead weight (D44). That single
// observation is what turns a third dependency into a few hundred lines.
package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// ErrHeader means one header blob could not be read. It never fails a scan on
// its own: the caller counts it and reports the package as skipped, because a
// database whose 187th record is damaged still knows about the other 186.
var ErrHeader = errors.New("unreadable rpm header")

// RPM header tags. Only the six that make a NEVRA plus its source are read —
// a header carries around ninety, and storing fields nothing looks at would
// mean deciding what "count" means for every one of them.
const (
	tagName      = 1000
	tagVersion   = 1001
	tagRelease   = 1002
	tagEpoch     = 1003
	tagArch      = 1022
	tagSourceRPM = 1044
	// tagModularityLabel (RPMTAG_MODULARITYLABEL) is a plain STRING holding
	// "name:stream:version:context", present only on packages installed from
	// a module stream (D80). Absent on every non-modular package — measured
	// 0 of 1,049 across five real images, with the tag present on exactly
	// the 13 packages whose RELEASE carries a module build marker.
	tagModularityLabel = 5096
)

// RPM header data types. Four of the ten are enough for a NEVRA; the rest
// (NULL, CHAR, INT8, INT16, INT64, BIN) appear in real headers but never on a
// tag read here, so they are rejected at the read rather than half-decoded.
const (
	typeInt32       = 4
	typeString      = 6
	typeStringArray = 8
	typeI18NString  = 9
)

// headerLimits bound what a header is allowed to claim about itself before any
// allocation happens. A damaged length field is the one input that turns a
// parse error into an out-of-memory kill, and the caps are far above anything
// real: the largest header measured across seven images had 141 index entries
// and a 5 MB data store, and a header is a package's file list, so it grows
// with the package.
const (
	maxIndexEntries = 1 << 16 // 65,536 tags in one header
	maxDataStore    = 1 << 28 // 256 MiB of tag data
)

// header is one parsed RPM header blob, held only long enough to pull the six
// tags out of it.
type header struct {
	index []indexEntry
	data  []byte
}

// indexEntry is the 16-byte record that says where one tag's value lives.
// Offsets are relative to the start of the data store, not to the blob.
type indexEntry struct {
	tag    uint32
	typ    uint32
	offset uint32
	count  uint32
}

// parseHeader reads one header blob as it is stored in the rpmdb.
//
// The blob has NO 8-byte lead magic. That form (0x8eade801 followed by four
// reserved bytes) belongs to .rpm files and to headerExport-with-magic; what
// the database stores starts directly at the index count. Reading the stored
// form as though it had a lead consumes the first two length fields as magic
// and then indexes into nothing, which is a confident wrong answer rather than
// an error, so the shape is asserted here rather than assumed.
func parseHeader(blob []byte) (header, error) {
	if len(blob) < 8 {
		return header{}, fmt.Errorf("%w: blob is %d bytes, too short for the 8-byte prefix", ErrHeader, len(blob))
	}
	nindex := binary.BigEndian.Uint32(blob[0:4])
	hsize := binary.BigEndian.Uint32(blob[4:8])
	if nindex == 0 {
		return header{}, fmt.Errorf("%w: header claims no index entries", ErrHeader)
	}
	if nindex > maxIndexEntries {
		return header{}, fmt.Errorf("%w: header claims %d index entries", ErrHeader, nindex)
	}
	if hsize > maxDataStore {
		return header{}, fmt.Errorf("%w: header claims a %d-byte data store", ErrHeader, hsize)
	}
	// Computed in uint64 because nindex*16 overflows uint32 well below the cap
	// above on a 32-bit build, and an overflowed length compares as small
	// enough — the arithmetic itself has to be the check, not the value.
	want := 8 + uint64(nindex)*16 + uint64(hsize)
	if uint64(len(blob)) < want {
		return header{}, fmt.Errorf("%w: header claims %d bytes (%d index entries + %d data) but the blob is %d",
			ErrHeader, want, nindex, hsize, len(blob))
	}

	h := header{
		index: make([]indexEntry, 0, nindex),
		data:  blob[8+nindex*16 : 8+nindex*16+hsize],
	}
	for i := uint32(0); i < nindex; i++ {
		e := blob[8+i*16 : 8+i*16+16]
		h.index = append(h.index, indexEntry{
			tag:    binary.BigEndian.Uint32(e[0:4]),
			typ:    binary.BigEndian.Uint32(e[4:8]),
			offset: binary.BigEndian.Uint32(e[8:12]),
			count:  binary.BigEndian.Uint32(e[12:16]),
		})
	}
	return h, nil
}

// find returns the index entry for tag. The first match wins: a real header
// carries a region trailer (tag 63) and, rarely, a tag repeated between the
// immutable region and the mutable tail, and the region's copy is the one rpm
// itself trusts.
func (h header) find(tag uint32) (indexEntry, bool) {
	for _, e := range h.index {
		if e.tag == tag {
			return e, true
		}
	}
	return indexEntry{}, false
}

// str reads a STRING, I18NSTRING or STRING_ARRAY tag, returning the first
// element of the last two.
//
// Absent is not an error — SOURCERPM is genuinely missing from some records,
// and EPOCH from most — so the caller distinguishes "no such tag" from "a tag
// this build cannot read" by the bool, and only the second is worth a skip.
func (h header) str(tag uint32) (string, bool) {
	e, ok := h.find(tag)
	if !ok {
		return "", false
	}
	switch e.typ {
	case typeString, typeI18NString, typeStringArray:
	default:
		return "", false
	}
	if uint64(e.offset) >= uint64(len(h.data)) {
		return "", false
	}
	rest := h.data[e.offset:]
	// NUL-terminated inside the data store. A string that runs to the end of
	// the store without a terminator is truncated data, not a value: returning
	// the remainder would hand the matcher a package name with a megabyte of
	// somebody else's tags appended.
	for i := 0; i < len(rest); i++ {
		if rest[i] == 0 {
			return string(rest[:i]), true
		}
	}
	return "", false
}

// i32 reads an INT32 tag. Used only for EPOCH, whose absence means zero (D46)
// — which is why this returns the bool separately rather than folding a
// missing tag into a zero value the caller could not tell apart from a stored
// one.
func (h header) i32(tag uint32) (int32, bool) {
	e, ok := h.find(tag)
	if !ok || e.typ != typeInt32 || e.count == 0 {
		return 0, false
	}
	if uint64(e.offset)+4 > uint64(len(h.data)) {
		return 0, false
	}
	return int32(binary.BigEndian.Uint32(h.data[e.offset : e.offset+4])), true
}

// toPackage turns one header into a normalized package.
//
// ecosystem is passed in for apkdb's and dpkgdb's reason: this function never
// sees /etc/os-release, and a cataloger that guessed its own ecosystem key
// would be inventing the release the whole lookup depends on (D6). For a RHEL
// scan it is "" today, because D43 ships no provider — the packages are
// catalogued unkeyed and the matcher reports every one of them as skipped.
func toPackage(h header, ecosystem, path string) (pkgmeta.Package, error) {
	name, ok := h.str(tagName)
	if !ok || name == "" {
		return pkgmeta.Package{}, fmt.Errorf("%w: no readable NAME tag", ErrHeader)
	}
	version, ok := h.str(tagVersion)
	if !ok {
		return pkgmeta.Package{}, fmt.Errorf("%w: package %q has no readable VERSION tag", ErrHeader, name)
	}
	release, ok := h.str(tagRelease)
	if !ok {
		return pkgmeta.Package{}, fmt.Errorf("%w: package %q has no readable RELEASE tag", ErrHeader, name)
	}

	p := pkgmeta.Package{
		Name:      name,
		Version:   evr(h, version, release),
		Type:      "rpm",
		Ecosystem: ecosystem,
		Locations: []pkgmeta.Location{{Path: path}},
	}
	// D8. SOURCERPM names the source package an advisory may be keyed on, and
	// unlike dpkg's Source: field it is a filename rather than a name, so the
	// version has to be stripped back off it. Absent means the binary is its
	// own source, which is what dpkg's absent Source: field means too — filling
	// both in rather than leaving them empty is what lets the matcher treat
	// every ecosystem the same way.
	src := sourceName(h)
	if src == "" {
		src = name
	}
	p.Source = &pkgmeta.SourcePackage{Name: src, Version: p.Version}
	// D80. Only NAME:STREAM is kept — the label's VERSION and CONTEXT differ
	// between builds of one installed stream (see Package.ModuleStream's own
	// doc). A label that does not split into at least four fields is mapped
	// to "" rather than guessed at; the matcher still refuses to judge such
	// a package, because its RELEASE carries the module marker and a module
	// build with no readable stream is reported not evaluated there.
	if label, ok := h.str(tagModularityLabel); ok {
		parts := strings.SplitN(label, ":", 4)
		if len(parts) == 4 && parts[0] != "" && parts[1] != "" {
			p.ModuleStream = parts[0] + ":" + parts[1]
		}
	}
	return p, nil
}

// evr assembles epoch:version-release, the string the RPM comparer orders.
//
// The epoch is written ONLY when it is present and non-zero, which matches how
// the advisory side is split: AlmaLinux omits it when zero (52,290 of 67,076
// fixed events) while Red Hat and Rocky always emit it, and on the installed
// side 145 of 158 real packages in almalinux:9 carry no EPOCH tag at all. D46
// puts the reconciliation in the comparer, where an absent epoch is zero on
// both sides, rather than here — normalizing one side to "0:" would make the
// two strings agree by construction and hide whether the comparer can actually
// do it.
func evr(h header, version, release string) string {
	v := version + "-" + release
	if epoch, ok := h.i32(tagEpoch); ok && epoch != 0 {
		return fmt.Sprintf("%d:%s", epoch, v)
	}
	return v
}

// sourceName strips a SOURCERPM filename back to the source package name:
// "audit-3.1.5-8.el9.src.rpm" -> "audit". The stripping itself is
// pkgmeta.SourceRPMName (D83) — shared with the cyclonedx cataloger, which
// reads the identical shape off a purl's "upstream" qualifier — so this is
// left as the thin header-reading half.
func sourceName(h header) string {
	s, ok := h.str(tagSourceRPM)
	if !ok {
		return ""
	}
	return pkgmeta.SourceRPMName(s)
}

// isPubkey reports whether a header is a gpg-pubkey row rather than an
// installed package. Every rpmdb carries 0-3 of them; they are keyring entries
// with no architecture and a SOURCERPM of "(none)", and reporting one as a
// package would put a key fingerprint in the inventory where a version belongs.
func isPubkey(h header) bool {
	name, _ := h.str(tagName)
	if name != "gpg-pubkey" {
		return false
	}
	// Checked rather than assumed: a real package named gpg-pubkey would be
	// indistinguishable by name alone, and dropping a real package is silent.
	_, hasArch := h.str(tagArch)
	return !hasArch
}
