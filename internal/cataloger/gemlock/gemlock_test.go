package gemlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Gemfile.lock")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParse_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.lock")

	_, _, err := Parse(path)
	if err == nil {
		t.Fatal("err = nil, want a read error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want it to name %s", err, path)
	}
}

func TestParse_EmptyFileIsNotAnError(t *testing.T) {
	path := write(t, "")

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 || stats.Components != 0 {
		t.Errorf("pkgs = %+v, stats = %+v; want nothing", pkgs, stats)
	}
}

// The exact boundary the caller-side test cannot pin down on its own: a spec
// line one space short of 4, exactly at 4, and one space past it (into the
// 6-space dependency-constraint depth) must be treated differently, not just
// "4 or more" or "not 6".
func TestParse_IndentBoundaryIsExactlyFour(t *testing.T) {
	cases := []struct {
		name   string
		indent string
		want   int // want packages cataloged
	}{
		{"three spaces", "   ", 0},
		{"four spaces", "    ", 1},
		{"five spaces", "     ", 0},
		{"six spaces", "      ", 0},
		{"seven spaces", "       ", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "GEM\n  remote: https://rubygems.org/\n  specs:\n" +
				tc.indent + "indent-fixture (1.0.0)\n"
			path := write(t, body)

			pkgs, _, err := Parse(path)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(pkgs) != tc.want {
				t.Errorf("indent %q: got %d packages, want %d: %+v",
					tc.indent, len(pkgs), tc.want, pkgs)
			}
		})
	}
}

// Indented correctly (4 spaces) but not "name (version)" shape - counted as
// a component, not silently dropped.
func TestParse_MalformedSpecLineIsCountedAndSkipped(t *testing.T) {
	path := write(t, `GEM
  remote: https://rubygems.org/
  specs:
    not-a-valid-spec-line-fixture
    valid-fixture (1.0.0)
`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "valid-fixture" {
		t.Fatalf("packages = %+v, want valid-fixture alone", pkgs)
	}
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 2 components, 1 cataloged, 1 skipped", stats)
	}
}

// PATH gets the same treatment as GIT: a local checkout, not rubygems.org.
func TestParse_PathSectionIsCountedAndSkippedLikeGit(t *testing.T) {
	path := write(t, `PATH
  remote: ../local-gem-fixture
  specs:
    local-gem-fixture (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    real-fixture (2.0.0)
`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "real-fixture" {
		t.Fatalf("packages = %+v, want real-fixture alone", pkgs)
	}
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 2 components, 1 cataloged, 1 skipped", stats)
	}
}

// Sections end at an unindented line - PLATFORMS and DEPENDENCIES following
// GEM must not be read as if they were still inside it, even though bundler
// never nests a "specs:" block header identically named there.
func TestParse_UnindentedLineEndsTheSection(t *testing.T) {
	path := write(t, `GEM
  remote: https://rubygems.org/
  specs:
    ends-fixture (1.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  ends-fixture
`)

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "ends-fixture" {
		t.Fatalf("packages = %+v, want ends-fixture alone", pkgs)
	}
}

func TestSpecLine(t *testing.T) {
	cases := []struct {
		line        string
		wantName    string
		wantVersion string
		ok          bool
	}{
		{"rails (7.0.4)", "rails", "7.0.4", true},
		// A native gem's platform suffix is kept as part of the version -
		// the Comparer owns what counts as equivalent, not this cataloger.
		{"nokogiri (1.13.8-x86_64-linux)", "nokogiri", "1.13.8-x86_64-linux", true},
		{"no-parens-here", "", "", false},
		{"missing-close (1.0.0", "", "", false},
		{"() ", "", "", false},
		{" (1.0.0)", "", "", false},
		{"name ()", "", "", false},
	}
	for _, tc := range cases {
		name, version, ok := specLine(tc.line)
		if name != tc.wantName || version != tc.wantVersion || ok != tc.ok {
			t.Errorf("specLine(%q) = %q, %q, %v; want %q, %q, %v",
				tc.line, name, version, ok, tc.wantName, tc.wantVersion, tc.ok)
		}
	}
}

func TestParse_EcosystemAndPURL(t *testing.T) {
	path := write(t, "GEM\n  remote: https://rubygems.org/\n  specs:\n    serde-fixture (1.0.196)\n")

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v, want one", pkgs)
	}
	p := pkgs[0]
	if p.Type != "gem" {
		t.Errorf("Type = %q, want gem", p.Type)
	}
	if p.Ecosystem != "RubyGems" {
		t.Errorf("Ecosystem = %q, want RubyGems", p.Ecosystem)
	}
	if p.PURL != "pkg:gem/serde-fixture@1.0.196" {
		t.Errorf("PURL = %q, want pkg:gem/serde-fixture@1.0.196", p.PURL)
	}
}
