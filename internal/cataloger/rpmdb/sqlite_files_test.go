package rpmdb

import (
	"os"
	"testing"
)

// The SQLite backend reads file lists too (D162). The committed rpmdb.sqlite
// fixture's headers carry no BASENAMES, so this one is generated: a WAL-mode
// database (version bytes 2/2, as every real rpmdb.sqlite) whose Packages
// table holds two headers with the three file tags -- passwd owning
// /usr/bin/passwd and a manual page, bash owning /usr/bin/bash. Built with
// Python's sqlite3 module from the same header layout fileListHeader writes;
// regenerate it the same way if the layout ever changes.
func TestReadSQLite_FilesAreOwnedByTheirPackage(t *testing.T) {
	db, err := os.ReadFile("testdata/rpmdb-files.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ReadSQLite(db, WALAbsent, "RHEL:9", "rpmdb.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 2 {
		t.Fatalf("packages = %d (%v), want 2", len(res.Packages), res.Skipped)
	}
	want := map[string]string{"/usr/bin/passwd": "passwd", "/usr/share/man/man1/passwd.1.gz": "passwd", "/usr/bin/bash": "bash"}
	if len(res.Files) != len(want) {
		t.Fatalf("files = %v, want %v", res.Files, want)
	}
	for p, name := range want {
		i, ok := res.Files[p]
		if !ok || res.Packages[i].Name != name {
			t.Errorf("Files[%q] -> %v (%v), want %s", p, i, ok, name)
		}
	}
}

// strArray reads STRING_ARRAY tags only: a STRING tag asked for as an array
// is refused rather than read as a one-element array, so a header whose
// BASENAMES carries the wrong type owns nothing.
func TestStrArray_RefusesOtherTypes(t *testing.T) {
	h := mustParse(t, buildHeader(nevra()...))
	if _, ok := h.strArray(tagName); ok {
		t.Error("strArray read a STRING tag")
	}
	if _, ok := h.i32Array(tagName); ok {
		t.Error("i32Array read a STRING tag")
	}
	// BASENAMES typed INT32: files must not read it as names.
	blob := fileListHeader(t, nil, []string{"/usr/bin/"}, []int32{0}, append(nevra(), tagVal{id: tagBaseNames, typ: typeInt32, n: 7})...)
	if got := files(mustParse(t, blob)); got != nil {
		t.Errorf("files = %v with INT32 BASENAMES, want nil", got)
	}
}
