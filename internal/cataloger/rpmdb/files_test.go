package rpmdb

import (
	"encoding/binary"
	"os"
	"testing"
)

// Array tags for the file-list tests (D162): buildHeader writes one element
// per tagVal, so these assemble a multi-element STRING_ARRAY or INT32 array
// by hand through assemble.
func fileListHeader(t *testing.T, bases, dirs []string, idx []int32, extra ...tagVal) []byte {
	t.Helper()
	var (
		data  []byte
		index []indexEntry
	)
	for _, tv := range extra {
		index = append(index, indexEntry{tag: tv.id, typ: tv.typ, offset: uint32(len(data)), count: 1})
		data = append(data, tv.s...)
		data = append(data, 0)
	}
	strs := func(tag uint32, ss []string) {
		index = append(index, indexEntry{tag: tag, typ: typeStringArray, offset: uint32(len(data)), count: uint32(len(ss))})
		for _, s := range ss {
			data = append(data, s...)
			data = append(data, 0)
		}
	}
	if bases != nil {
		strs(tagBaseNames, bases)
	}
	if dirs != nil {
		strs(tagDirNames, dirs)
	}
	if idx != nil {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		index = append(index, indexEntry{tag: tagDirIndexes, typ: typeInt32, offset: uint32(len(data)), count: uint32(len(idx))})
		for _, n := range idx {
			data = binary.BigEndian.AppendUint32(data, uint32(n))
		}
	}
	return assemble(index, data)
}

func nevra() []tagVal {
	return []tagVal{strTag(tagName, "passwd"), strTag(tagVersion, "0.80"), strTag(tagRelease, "4.el8"), strTag(tagArch, "x86_64")}
}

// The caller first: an ndb whose one package owns two files puts both in
// Result.Files against that package's index, spelled as rpm spells them.
func TestReadNDB_FilesAreOwnedByTheirPackage(t *testing.T) {
	h := fileListHeader(t, []string{"passwd", "passwd.1.gz"}, []string{"/usr/bin/", "/usr/share/man/man1/"}, []int32{0, 1}, nevra()...)
	res, err := ReadNDB(buildNDB(t, 2, []ndbEntry{{pkgidx: 1, blob: h}}), "RHEL:8", "Packages.db")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "passwd" {
		t.Fatalf("packages = %+v", res.Packages)
	}
	want := map[string]int{"/usr/bin/passwd": 0, "/usr/share/man/man1/passwd.1.gz": 0}
	if len(res.Files) != len(want) {
		t.Fatalf("files = %v, want %v", res.Files, want)
	}
	for p, i := range want {
		if got, ok := res.Files[p]; !ok || got != i {
			t.Errorf("Files[%q] = %d, %v; want %d", p, got, ok, i)
		}
	}
}

// The real BerkeleyDB fixture: passwd owns /usr/bin/passwd.
func TestReadBDB_FixtureOwnsUsrBinPasswd(t *testing.T) {
	db, err := os.ReadFile("testdata/Packages")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ReadBDB(db, "RHEL:8", "Packages")
	if err != nil {
		t.Fatal(err)
	}
	i, ok := res.Files["/usr/bin/passwd"]
	if !ok {
		t.Fatalf("Files has no /usr/bin/passwd (%d files)", len(res.Files))
	}
	if p := res.Packages[i]; p.Name != "passwd" || p.Version != "0.80-4.el8" {
		t.Errorf("/usr/bin/passwd -> %s %s, want passwd 0.80-4.el8", p.Name, p.Version)
	}
}

// files refuses a header whose three tags disagree rather than guessing.
func TestFiles_DisagreeingTagsOwnNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bases []string
		dirs  []string
		idx   []int32
	}{
		{"no basenames", nil, []string{"/usr/bin/"}, []int32{0}},
		{"no dirnames", []string{"passwd"}, nil, []int32{0}},
		{"no dirindexes", []string{"passwd"}, []string{"/usr/bin/"}, nil},
		{"index count differs", []string{"passwd", "chage"}, []string{"/usr/bin/"}, []int32{0}},
		{"index past dirnames", []string{"passwd"}, []string{"/usr/bin/"}, []int32{1}},
		{"negative index", []string{"passwd"}, []string{"/usr/bin/"}, []int32{-1}},
		{"empty basenames", []string{}, []string{"/usr/bin/"}, []int32{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := mustParse(t, fileListHeader(t, tc.bases, tc.dirs, tc.idx, nevra()...))
			if got := files(h); got != nil {
				t.Errorf("files = %v, want nil", got)
			}
		})
	}
	h := mustParse(t, fileListHeader(t, []string{"a", "b", "c"}, []string{"/x/", "/y/"}, []int32{1, 0, 1}, nevra()...))
	if got := files(h); len(got) != 3 || got[0] != "/y/a" || got[1] != "/x/b" || got[2] != "/y/c" {
		t.Errorf("files = %v", got)
	}
}

// A STRING_ARRAY whose last element runs off the data store is unreadable
// as a whole, like str's own rule, and an INT32 array past the store too.
func TestStrArrayAndI32Array_TruncatedStoreIsUnreadable(t *testing.T) {
	blob := fileListHeader(t, []string{"passwd", "chage"}, []string{"/usr/bin/"}, []int32{0, 0}, nevra()...)
	// Cut the final NUL: the last basename element has no terminator.
	h := mustParse(t, blob)
	e, _ := h.find(tagBaseNames)
	// Find where BASENAMES ends and chop the data there (the arrays after
	// it move out of range too).
	short := header{index: h.index, data: h.data[:int(e.offset)+len("passwd")+1+len("chage")]}
	if _, ok := short.strArray(tagBaseNames); ok {
		t.Error("strArray read an array whose last element has no terminator")
	}
	if _, ok := short.i32Array(tagDirIndexes); ok {
		t.Error("i32Array read an INT32 array past the data store")
	}
	if got := files(short); got != nil {
		t.Errorf("files = %v on a truncated store", got)
	}
}
