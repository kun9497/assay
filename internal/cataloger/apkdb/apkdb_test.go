package apkdb

import (
	"os"
	"strings"
	"testing"
)

const testEcosystem = "Alpine:v3.19"

// The real file, all 15 records, matching what syft reports for this image.
func TestParse_RealDatabase(t *testing.T) {
	f, err := os.Open("testdata/installed")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pkgs, err := Parse(f, testEcosystem)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 15 {
		t.Fatalf("len(pkgs) = %d, want 15", len(pkgs))
	}

	byName := map[string]int{}
	for i, p := range pkgs {
		byName[p.Name] = i
	}
	mustPkg := func(name string) int {
		i, ok := byName[name]
		if !ok {
			t.Fatalf("package %q not cataloged; have %+v", name, pkgs)
		}
		return i
	}

	bl := pkgs[mustPkg("alpine-baselayout")]
	if bl.Version != "3.4.3-r2" {
		t.Errorf("alpine-baselayout Version = %q, want 3.4.3-r2", bl.Version)
	}
	if bl.Source == nil || bl.Source.Name != "alpine-baselayout" {
		t.Errorf("alpine-baselayout Source = %+v, want Name alpine-baselayout", bl.Source)
	}
	if bl.Source != nil && bl.Source.Version != "" {
		t.Errorf("alpine-baselayout Source.Version = %q, want empty: apk sets only Name (D8)",
			bl.Source.Version)
	}
	// The ecosystem argument comes from the caller (Distro.Ecosystem()); a
	// package has no way to derive it on its own (D6, D7).
	if bl.Ecosystem != testEcosystem {
		t.Errorf("alpine-baselayout Ecosystem = %q, want %q", bl.Ecosystem, testEcosystem)
	}
	if bl.Type != "apk" {
		t.Errorf("alpine-baselayout Type = %q, want apk", bl.Type)
	}
	// Location.Path is part of Evidence (D10): a finding that cannot point back
	// at the file it came from is not explainable.
	if len(bl.Locations) != 1 || bl.Locations[0].Path != "/lib/apk/db/installed" {
		t.Errorf("alpine-baselayout Locations = %+v, want Path /lib/apk/db/installed", bl.Locations)
	}

	// Every one of the 15 real records carries an o: line, so every package
	// must carry a non-nil Source. A single missed one would silently drop
	// that package out of D8 indirect matching.
	for _, p := range pkgs {
		if p.Source == nil {
			t.Errorf("package %q has nil Source; every record in the real file has o:", p.Name)
		}
	}
}

// D8, on the packages that actually diverge from their source in this image.
// Without Package.Source these six are unreachable from the openssl/busybox/musl
// advisories that name the source package, not the binary one.
func TestParse_SourcePackageDiffersFromBinary(t *testing.T) {
	f, err := os.Open("testdata/installed")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	pkgs, err := Parse(f, testEcosystem)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]string{
		"busybox-binsh": "busybox",
		"ssl_client":    "busybox",
		"musl-utils":    "musl",
	}
	got := map[string]string{}
	for _, p := range pkgs {
		if p.Source != nil {
			got[p.Name] = p.Source.Name
		}
	}
	for name, source := range want {
		if got[name] != source {
			t.Errorf("%s Source.Name = %q, want %q", name, got[name], source)
		}
	}
}

// The case trap: 57 a: lines against 15 A: in the real file. A parser that
// folds case before dispatching reads a file's owner triple as the package
// architecture. Arch has no home on pkgmeta.Package, so this checks the
// unexported record straight from the internal parser — the only place the
// value is observable at all.
func TestParse_KeysAreCaseSensitive(t *testing.T) {
	const rec = "P:x\nV:1-r0\nA:x86_64\no:x\na:0:0:755\nt:1695795276\nT:desc\n"

	recs, err := parseRecords(strings.NewReader(rec))
	if err != nil {
		t.Fatalf("parseRecords: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("len(recs) = %d, want 1", len(recs))
	}
	if recs[0].arch != "x86_64" {
		t.Errorf("arch = %q, want x86_64 (a: file-owner line must not overwrite A:)", recs[0].arch)
	}

	// Name and Origin both live on pkgmeta.Package, so the same collision is
	// checked there too: a case-folding dispatch would also fold 'o' (origin)
	// into whatever its uppercase arm does.
	pkgs, err := Parse(strings.NewReader(rec), testEcosystem)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1", len(pkgs))
	}
	if pkgs[0].Name != "x" {
		t.Errorf("Name = %q, want x", pkgs[0].Name)
	}
	if pkgs[0].Source == nil || pkgs[0].Source.Name != "x" {
		t.Errorf("Source = %+v, want Name x", pkgs[0].Source)
	}
}

// Records are separated by a blank line. A doubled blank line between two
// records must not fabricate a phantom empty package, and a trailing blank
// line at EOF (which the real file has) must not be treated as a parse error.
func TestParse_RecordBoundaries(t *testing.T) {
	const doc = "P:a\nV:1-r0\no:a\n\n\nP:b\nV:2-r0\no:b\n\n"

	pkgs, err := Parse(strings.NewReader(doc), testEcosystem)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("len(pkgs) = %d, want 2 (doubled blank line must not add a phantom record)", len(pkgs))
	}
	if pkgs[0].Name != "a" || pkgs[0].Version != "1-r0" {
		t.Errorf("pkgs[0] = %+v, want a/1-r0", pkgs[0])
	}
	if pkgs[1].Name != "b" || pkgs[1].Version != "2-r0" {
		t.Errorf("pkgs[1] = %+v, want b/2-r0", pkgs[1])
	}
}

// A record with no P: line is not a package — it is either a malformed block
// or (in principle) some other apk-db block this parser does not know about.
// Emitting one with an empty Name would hand the matcher a lookup key of ""
// that can only ever miss silently.
func TestParse_RecordWithoutNameIsSkipped(t *testing.T) {
	const doc = "V:1-r0\no:a\n\nP:b\nV:2-r0\no:b\n\n"

	pkgs, err := Parse(strings.NewReader(doc), testEcosystem)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1 (the nameless record must be skipped)", len(pkgs))
	}
	if pkgs[0].Name != "b" {
		t.Errorf("pkgs[0].Name = %q, want b", pkgs[0].Name)
	}
}
