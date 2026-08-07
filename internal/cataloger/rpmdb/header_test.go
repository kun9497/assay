package rpmdb

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// tagVal is one tag to write into a synthetic header. Fixtures are built here
// rather than committed as binary because the interesting cases — an offset
// past the data store, a string with no terminator, a length field that
// overflows — cannot be produced by any real rpm and so cannot be extracted
// from a real image.
type tagVal struct {
	id  uint32
	typ uint32
	s   string
	n   int32
}

func strTag(id uint32, s string) tagVal  { return tagVal{id: id, typ: typeString, s: s} }
func i32Tag(id uint32, n int32) tagVal   { return tagVal{id: id, typ: typeInt32, n: n} }
func arrTag(id uint32, s string) tagVal  { return tagVal{id: id, typ: typeStringArray, s: s} }
func i18nTag(id uint32, s string) tagVal { return tagVal{id: id, typ: typeI18NString, s: s} }

// buildHeader assembles a well-formed header blob. INT32 values are aligned to
// a 4-byte boundary the way rpm writes them, so the fixtures exercise the same
// offsets a real header produces even though the reader does not require it.
func buildHeader(tags ...tagVal) []byte {
	var (
		data  []byte
		index []indexEntry
	)
	for _, t := range tags {
		switch t.typ {
		case typeInt32:
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
			index = append(index, indexEntry{tag: t.id, typ: t.typ, offset: uint32(len(data)), count: 1})
			data = binary.BigEndian.AppendUint32(data, uint32(t.n))
		default:
			index = append(index, indexEntry{tag: t.id, typ: t.typ, offset: uint32(len(data)), count: 1})
			data = append(data, t.s...)
			data = append(data, 0) // NUL, as a byte — never as an escape in a string (CLAUDE.md)
		}
	}
	return assemble(index, data)
}

// assemble writes the prefix, index and data store without validating any of
// it, so a test can hand parseHeader a blob whose length fields lie.
func assemble(index []indexEntry, data []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(index)))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	for _, e := range index {
		out = binary.BigEndian.AppendUint32(out, e.tag)
		out = binary.BigEndian.AppendUint32(out, e.typ)
		out = binary.BigEndian.AppendUint32(out, e.offset)
		out = binary.BigEndian.AppendUint32(out, e.count)
	}
	return append(out, data...)
}

func mustParse(t *testing.T, blob []byte) header {
	t.Helper()
	h, err := parseHeader(blob)
	if err != nil {
		t.Fatalf("parseHeader: %v", err)
	}
	return h
}

// The NEVRA and its source, which is every field this cataloger reads. Values
// are real: audit-libs from a ubi9 image, whose source package name differs
// from its own and whose SOURCERPM therefore has to be stripped correctly.
func TestToPackage_NEVRAAndSource(t *testing.T) {
	h := mustParse(t, buildHeader(
		strTag(tagName, "audit-libs"),
		strTag(tagVersion, "3.1.5"),
		strTag(tagRelease, "8.el9"),
		strTag(tagArch, "x86_64"),
		strTag(tagSourceRPM, "audit-3.1.5-8.el9.src.rpm"),
	))
	p, err := toPackage(h, "", "/var/lib/rpm/rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "audit-libs" {
		t.Errorf("Name = %q, want audit-libs", p.Name)
	}
	if p.Version != "3.1.5-8.el9" {
		t.Errorf("Version = %q, want 3.1.5-8.el9 — version and release are one string to the comparer", p.Version)
	}
	if p.Source == nil {
		t.Fatal("Source is nil; an absent SOURCERPM means the binary is its own source, not nothing")
	}
	// Asserted against the exact string rather than with Contains: "audit" is a
	// substring of "audit-libs", so a Contains check would pass from the name
	// column even if the source were never read at all (CLAUDE.md).
	if p.Source.Name != "audit" {
		t.Errorf("Source.Name = %q, want audit — this is the name D8 looks the advisory up under", p.Source.Name)
	}
	if p.Type != "rpm" {
		t.Errorf("Type = %q, want rpm", p.Type)
	}
	if len(p.Locations) != 1 || p.Locations[0].Path != "/var/lib/rpm/rpmdb.sqlite" {
		t.Errorf("Locations = %+v, want the database it was read from", p.Locations)
	}
}

// The epoch, which D46 calls the highest-risk row in the comparer table. Both
// halves of the split are asserted: written when non-zero, omitted when zero
// or absent, because 145 of 158 real packages in almalinux:9 carry no EPOCH
// tag and normalizing them to "0:" here would make the comparer's job look
// done when it is not.
func TestEVR_EpochWrittenOnlyWhenNonZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		tags []tagVal
		want string
	}{
		{"absent", nil, "1.2.3-4.el9"},
		{"explicit zero", []tagVal{i32Tag(tagEpoch, 0)}, "1.2.3-4.el9"},
		{"non-zero", []tagVal{i32Tag(tagEpoch, 1)}, "1:1.2.3-4.el9"},
		{"two digits", []tagVal{i32Tag(tagEpoch, 12)}, "12:1.2.3-4.el9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := append([]tagVal{
				strTag(tagName, "x"),
				strTag(tagVersion, "1.2.3"),
				strTag(tagRelease, "4.el9"),
			}, tc.tags...)
			p, err := toPackage(mustParse(t, buildHeader(tags...)), "", "p")
			if err != nil {
				t.Fatal(err)
			}
			if p.Version != tc.want {
				t.Errorf("Version = %q, want %q", p.Version, tc.want)
			}
		})
	}
}

// SOURCERPM's shapes. The interior-hyphen row is the one that fails apart from
// the others: stripping everything after the first hyphen satisfies every
// simple case and turns python3-perf into python3.
func TestSourceName(t *testing.T) {
	for _, tc := range []struct {
		sourcerpm string
		want      string
		why       string
	}{
		{"audit-3.1.5-8.el9.src.rpm", "audit", "the plain case"},
		{"python3-perf-3.10.0-1.el9.src.rpm", "python3-perf",
			"an interior hyphen: only the LAST TWO fields are version and release"},
		{"cracklib-2.9.6-27.el9.src.rpm", "cracklib", "real ubi9: cracklib-dicts comes from this"},
		{"chkconfig-1.24-1.el9.src.rpm", "chkconfig", "real ubi9: alternatives comes from this"},
		{"gcc-toolset-13-gcc-13.3.1-2.el9.src.rpm", "gcc-toolset-13-gcc", "three interior hyphens"},
		{"(none)", "", "gpg-pubkey's literal placeholder is not a filename"},
		{"audit-3.1.5-8.el9.rpm", "", "a binary rpm, not a source one"},
		{"noversion.src.rpm", "", "no hyphen at all"},
		{"-1.0-1.src.rpm", "", "an empty name is not a name"},
	} {
		t.Run(tc.sourcerpm, func(t *testing.T) {
			h := mustParse(t, buildHeader(strTag(tagSourceRPM, tc.sourcerpm)))
			if got := sourceName(h); got != tc.want {
				t.Errorf("sourceName(%q) = %q, want %q — %s", tc.sourcerpm, got, tc.want, tc.why)
			}
		})
	}
}

// An absent SOURCERPM means the binary is its own source. Dropping the Source
// entirely would make the matcher's D8 lookup skip these packages, and a
// skipped lookup is a false negative.
func TestToPackage_AbsentSourceRPMIsSelf(t *testing.T) {
	p, err := toPackage(mustParse(t, buildHeader(
		strTag(tagName, "selfsourced"),
		strTag(tagVersion, "1.0"),
		strTag(tagRelease, "1.el9"),
	)), "", "p")
	if err != nil {
		t.Fatal(err)
	}
	if p.Source == nil || p.Source.Name != "selfsourced" {
		t.Errorf("Source = %+v, want the package's own name", p.Source)
	}
	if p.Source.Version != p.Version {
		t.Errorf("Source.Version = %q, want %q", p.Source.Version, p.Version)
	}
}

// STRING_ARRAY and I18NSTRING read like STRING. Both appear on real tags, and
// a reader that accepted only type 6 would drop whichever tag an image happened
// to store as an array.
func TestHeaderStr_AcceptsArrayAndI18N(t *testing.T) {
	h := mustParse(t, buildHeader(
		arrTag(tagName, "arrayname"),
		i18nTag(tagVersion, "i18nversion"),
	))
	if got, ok := h.str(tagName); !ok || got != "arrayname" {
		t.Errorf("STRING_ARRAY read as (%q, %v)", got, ok)
	}
	if got, ok := h.str(tagVersion); !ok || got != "i18nversion" {
		t.Errorf("I18NSTRING read as (%q, %v)", got, ok)
	}
}

// gpg-pubkey rows are keyring entries, not packages. The arch check is what
// keeps a hypothetical real package of that name: dropping a real package is
// silent, and this is the only guard between the two.
func TestIsPubkey(t *testing.T) {
	keyring := mustParse(t, buildHeader(
		strTag(tagName, "gpg-pubkey"),
		strTag(tagVersion, "fd431d51"),
		strTag(tagRelease, "4ae0493b"),
		strTag(tagSourceRPM, "(none)"),
	))
	if !isPubkey(keyring) {
		t.Error("a gpg-pubkey row with no ARCH was not recognized as a keyring entry")
	}
	realPkg := mustParse(t, buildHeader(
		strTag(tagName, "gpg-pubkey"),
		strTag(tagVersion, "1.0"),
		strTag(tagRelease, "1.el9"),
		strTag(tagArch, "x86_64"),
	))
	if isPubkey(realPkg) {
		t.Error("a package named gpg-pubkey WITH an arch was dropped; dropping a real package is a silent miss")
	}
	other := mustParse(t, buildHeader(strTag(tagName, "openssl")))
	if isPubkey(other) {
		t.Error("openssl was treated as a keyring entry")
	}
}

// Damaged and hostile blobs. Each of these is a shape that must produce an
// error rather than a plausible package: a scanner that invents a name and
// version from garbage reports a finding nobody can act on, and one that
// invents nothing reports a clean image.
func TestParseHeader_Rejects(t *testing.T) {
	good := buildHeader(strTag(tagName, "x"), strTag(tagVersion, "1"), strTag(tagRelease, "1"))

	// A blob carrying the 8-byte lead magic that .rpm FILES use. The stored
	// form has no lead, so this must be refused rather than read with the
	// lengths shifted by eight bytes — which is the shape a first attempt
	// naturally produces and which yields nonsense, not an error, if the
	// prefix is merely skipped.
	withLead := append([]byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0}, good...)

	// Length fields that lie, built through assemble so no validation runs.
	claimsTooMuchData := assemble([]indexEntry{{tag: tagName, typ: typeString, offset: 0, count: 1}}, nil)
	binary.BigEndian.PutUint32(claimsTooMuchData[4:8], 1<<20)

	tooManyEntries := assemble(nil, nil)
	binary.BigEndian.PutUint32(tooManyEntries[0:4], maxIndexEntries+1)

	// Exactly at the uint32 boundary: nindex*16 overflows a 32-bit multiply,
	// so a length check done in uint32 would compute a small number and let
	// the slice below run off the end.
	overflowingCount := assemble(nil, nil)
	binary.BigEndian.PutUint32(overflowingCount[0:4], 1<<28)

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"empty", nil},
		{"shorter than the prefix", good[:6]},
		{"no index entries", assemble(nil, nil)},
		{"truncated mid-index", good[:12]},
		{"truncated mid-data", good[:len(good)-2]},
		{"carries the .rpm file lead magic", withLead},
		{"claims more data than it has", claimsTooMuchData},
		{"claims more index entries than any header holds", tooManyEntries},
		{"index count overflows a 32-bit size computation", overflowingCount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The contract is an error WRAPPING ErrHeader: the caller counts
			// these as skipped packages and lets the scan continue, and it
			// distinguishes them from a database-level failure by matching on it.
			if _, err := parseHeader(tc.blob); !errors.Is(err, ErrHeader) {
				t.Errorf("parseHeader err = %v, want one wrapping ErrHeader", err)
			}
		})
	}
}

// Tags whose value is unreachable read as absent, and a package missing any of
// the three NEVRA parts is an error rather than a package with a hole in it.
func TestHeaderStr_OutOfBoundsAndUnterminated(t *testing.T) {
	// An offset past the end of the data store.
	past := assemble([]indexEntry{{tag: tagName, typ: typeString, offset: 500, count: 1}}, []byte("abc"))
	h := mustParse(t, past)
	if _, ok := h.str(tagName); ok {
		t.Error("a tag whose offset is past the data store was read as a value")
	}

	// A string that runs to the end of the store with no NUL. Returning the
	// remainder would append every following tag's bytes to the package name.
	unterminated := assemble([]indexEntry{{tag: tagName, typ: typeString, offset: 0, count: 1}}, []byte("openssl"))
	if got, ok := mustParse(t, unterminated).str(tagName); ok {
		t.Errorf("an unterminated string read as %q; it has no end inside the store", got)
	}

	// A NEVRA part missing is a skip, not a package.
	for _, missing := range []string{"NAME", "VERSION", "RELEASE"} {
		t.Run("missing "+missing, func(t *testing.T) {
			tags := []tagVal{strTag(tagName, "x"), strTag(tagVersion, "1"), strTag(tagRelease, "1")}
			switch missing {
			case "NAME":
				tags = tags[1:]
			case "VERSION":
				tags = []tagVal{tags[0], tags[2]}
			case "RELEASE":
				tags = tags[:2]
			}
			_, err := toPackage(mustParse(t, buildHeader(tags...)), "", "p")
			if !errors.Is(err, ErrHeader) {
				t.Errorf("toPackage err = %v, want one wrapping ErrHeader", err)
			}
			// And the error names the package where it can, so a skipped-count
			// line in the report can say which one.
			if missing != "NAME" && err != nil && !strings.Contains(err.Error(), "\"x\"") {
				t.Errorf("error %q does not name the package it is about", err)
			}
		})
	}
}

// An INT32 tag stored as some other type is not an epoch. Reading four bytes
// of a string as a big-endian integer produces a large plausible number, and
// an epoch of 1,869,375,809 sorts above every real version.
func TestHeaderI32_RejectsWrongType(t *testing.T) {
	h := mustParse(t, buildHeader(strTag(tagEpoch, "notanumber")))
	if n, ok := h.i32(tagEpoch); ok {
		t.Errorf("a STRING epoch read as the integer %d", n)
	}
	truncated := assemble([]indexEntry{{tag: tagEpoch, typ: typeInt32, offset: 2, count: 1}}, []byte{0, 0, 0})
	if n, ok := mustParse(t, truncated).i32(tagEpoch); ok {
		t.Errorf("an epoch with only one byte left in the store read as %d", n)
	}
}
