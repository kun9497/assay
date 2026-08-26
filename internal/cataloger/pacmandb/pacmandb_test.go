package pacmandb

import (
	"os"
	"strings"
	"testing"
)

const testEcosystem = "Arch:rolling"
const testPath = "var/lib/pacman/local/acl-2.4.0-1/desc"

func openFixture(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// TestParseDesc_RealFile is the ordinary case: a single-value desc file
// (acl, not a split package -- BASE repeats NAME) parses into one Package
// with no Source.
func TestParseDesc_RealFile(t *testing.T) {
	pkgs, err := ParseDesc(openFixture(t, "acl-desc"), testEcosystem, testPath)
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1: %+v", len(pkgs), pkgs)
	}
	p := pkgs[0]
	if p.Name != "acl" {
		t.Errorf("Name = %q, want acl", p.Name)
	}
	if p.Version != "2.4.0-1" {
		t.Errorf("Version = %q, want 2.4.0-1", p.Version)
	}
	if p.Type != "alpm" {
		t.Errorf("Type = %q, want alpm", p.Type)
	}
	// The ecosystem argument comes from the caller (Distro.Ecosystem()); a
	// package has no way to derive it on its own (D6, D7).
	if p.Ecosystem != testEcosystem {
		t.Errorf("Ecosystem = %q, want %q", p.Ecosystem, testEcosystem)
	}
	// Location.Path is part of Evidence (D10): a finding that cannot point
	// back at the file it came from is not explainable.
	if len(p.Locations) != 1 || p.Locations[0].Path != testPath {
		t.Errorf("Locations = %+v, want Path %q", p.Locations, testPath)
	}
	// acl is not a split package -- BASE repeats NAME -- so Source must stay
	// nil, not point at itself.
	if p.Source != nil {
		t.Errorf("Source = %+v, want nil (BASE == NAME for acl)", p.Source)
	}
}

// TestParseDesc_BaseDiffersFromNameSetsSource is D8's exact analogue for
// pacman (D97): libelf's own desc names BASE=elfutils, and elfutils is
// where Arch's security tracker actually files libelf's CVEs (6 live
// packages measured 2026-08-26 whose only advisory route is their base
// name, elfutils among them).
func TestParseDesc_BaseDiffersFromNameSetsSource(t *testing.T) {
	pkgs, err := ParseDesc(openFixture(t, "libelf-desc"), testEcosystem,
		"var/lib/pacman/local/libelf-0.196-1/desc")
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1", len(pkgs))
	}
	p := pkgs[0]
	if p.Name != "libelf" {
		t.Errorf("Name = %q, want libelf", p.Name)
	}
	if p.Source == nil || p.Source.Name != "elfutils" {
		t.Fatalf("Source = %+v, want Name elfutils", p.Source)
	}
	// D8: only Name is set. A split package's BASE carries no version of its
	// own -- the binary's own Version is what a comparer uses.
	if p.Source.Version != "" {
		t.Errorf("Source.Version = %q, want empty (D8: pacman BASE carries no version)", p.Source.Version)
	}
}

// TestParseDesc_MultiValueSectionDoesNotCorruptSingleValueFields proves the
// parser tolerates gcc-libs' own desc file, which carries a MULTI-LINE
// %LICENSE% section (two values) and a many-line %DEPENDS% section sitting
// between %BASE% and the end of the file -- if parseSections mistook one of
// those extra lines for a new section's value, or let it leak into a later
// single-valued section, NAME/VERSION/BASE below would come out wrong or
// empty.
func TestParseDesc_MultiValueSectionDoesNotCorruptSingleValueFields(t *testing.T) {
	pkgs, err := ParseDesc(openFixture(t, "gcc-libs-desc"), testEcosystem,
		"var/lib/pacman/local/gcc-libs-16.2.1+r23+gd564253eb6c8-1/desc")
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1", len(pkgs))
	}
	p := pkgs[0]
	if p.Name != "gcc-libs" {
		t.Errorf("Name = %q, want gcc-libs", p.Name)
	}
	if p.Version != "16.2.1+r23+gd564253eb6c8-1" {
		t.Errorf("Version = %q, want 16.2.1+r23+gd564253eb6c8-1", p.Version)
	}
	if p.Source == nil || p.Source.Name != "gcc" {
		t.Fatalf("Source = %+v, want Name gcc (gcc-libs' own BASE)", p.Source)
	}
}

// TestParseDesc_BashDependsIsMultiLineToo is a second, independent real-file
// proof of the same multi-value tolerance bash's own desc exercises with
// %DEPENDS% (four lines) sitting between %LICENSE% and %OPTDEPENDS%/
// %PROVIDES% -- covering the ordinary (non-split, BASE == NAME) shape most
// of a real image's packages actually have (89 of 137 measured 2026-08-26),
// so the multi-value tolerance is proven on the common case, not only the
// split-package one gcc-libs covers.
func TestParseDesc_BashDependsIsMultiLineToo(t *testing.T) {
	pkgs, err := ParseDesc(openFixture(t, "bash-desc"), testEcosystem,
		"var/lib/pacman/local/bash-5.3.15-1/desc")
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("len(pkgs) = %d, want 1", len(pkgs))
	}
	p := pkgs[0]
	if p.Name != "bash" || p.Version != "5.3.15-1" {
		t.Errorf("Name/Version = %q/%q, want bash/5.3.15-1", p.Name, p.Version)
	}
	if p.Source != nil {
		t.Errorf("Source = %+v, want nil (bash is not a split package)", p.Source)
	}
}

// TestParseDesc_NotADescFileProducesNoPackage covers the sibling file the
// real local/ directory carries alongside every package directory,
// ALPM_DB_VERSION -- a bare integer with no %SECTION% grammar at all. This
// package does not decide which files under local/ are package directories
// (that is source.FilesNamed's job), but ParseDesc itself must not
// fabricate a package out of content that never named one.
func TestParseDesc_NotADescFileProducesNoPackage(t *testing.T) {
	pkgs, err := ParseDesc(strings.NewReader("9\n"), testEcosystem, "var/lib/pacman/local/ALPM_DB_VERSION")
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("pkgs = %+v, want none for a file with no %%NAME%% section", pkgs)
	}
}

// TestParseDesc_EmptyReaderProducesNoPackage is the boundary case
// TestParseDesc_NotADescFileProducesNoPackage approaches from real data --
// nothing at all, not even a malformed line.
func TestParseDesc_EmptyReaderProducesNoPackage(t *testing.T) {
	pkgs, err := ParseDesc(strings.NewReader(""), testEcosystem, "empty")
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("pkgs = %+v, want none", pkgs)
	}
}
