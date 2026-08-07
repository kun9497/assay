package dpkgdb

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// nl is a newline, assembled rather than typed. CLAUDE.md records the hazard
// and it fired four times in the session that added this package.
var nl = string(rune(10))

// stanzas joins lines with real newlines without any escape appearing in this
// file's source.
func stanzas(lines ...string) string { return strings.Join(lines, nl) + nl }

func byName(pkgs []pkgmeta.Package) map[string]pkgmeta.Package {
	m := map[string]pkgmeta.Package{}
	for _, p := range pkgs {
		m[p.Name] = p
	}
	return m
}

// The three Source forms, which are D8 and D41 in one field. Measured across
// four real images: absent 26-29%, bare name 60-71%, "name (version)" 1-15%.
func TestParse_SourceForms(t *testing.T) {
	in := stanzas(
		// Absent: the source name and version are the binary's own.
		"Package: apt",
		"Status: install ok installed",
		"Version: 2.6.1",
		"",
		// Bare name: D8's indirection, and the exact stanza
		// gcr.io/distroless/base-debian12 ships.
		"Package: libssl3",
		"Status: install ok installed",
		"Source: openssl",
		"Version: 3.0.20-1~deb12u2",
		"",
		// Name with a DIFFERENT version: a binNMU. Real bookworm bash.
		"Package: bash",
		"Status: install ok installed",
		"Source: bash (5.2.15-2)",
		"Version: 5.2.15-2+b13",
		"",
		// The shape where the source version drops an epoch the binary carries.
		// Real bookworm bsdutils, and the case that makes D41 necessary rather
		// than merely tidy.
		"Package: bsdutils",
		"Status: install ok installed",
		"Source: util-linux (2.38.1-5+deb12u3)",
		"Version: 1:2.38.1-5+deb12u3",
	)
	pkgs, err := Parse(strings.NewReader(in), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	got := byName(pkgs)
	if len(got) != 4 {
		t.Fatalf("parsed %d packages, want 4: %+v", len(got), pkgs)
	}
	for _, tc := range []struct{ pkg, srcName, srcVersion, version string }{
		{"apt", "apt", "2.6.1", "2.6.1"},
		{"libssl3", "openssl", "3.0.20-1~deb12u2", "3.0.20-1~deb12u2"},
		{"bash", "bash", "5.2.15-2", "5.2.15-2+b13"},
		{"bsdutils", "util-linux", "2.38.1-5+deb12u3", "1:2.38.1-5+deb12u3"},
	} {
		p := got[tc.pkg]
		if p.Version != tc.version {
			t.Errorf("%s Version = %q, want %q", tc.pkg, p.Version, tc.version)
		}
		if p.Source == nil {
			t.Errorf("%s has no Source; an absent field means the binary's own name and version, not nothing", tc.pkg)
			continue
		}
		if p.Source.Name != tc.srcName {
			t.Errorf("%s Source.Name = %q, want %q", tc.pkg, p.Source.Name, tc.srcName)
		}
		// Asserted separately from the name because the two fail apart: a
		// parser that reads the name and drops the parenthesised version
		// satisfies every D8 assertion and still compares the wrong version.
		if p.Source.Version != tc.srcVersion {
			t.Errorf("%s Source.Version = %q, want %q — this is the version D41 compares", tc.pkg, p.Source.Version, tc.srcVersion)
		}
	}
	// bash and bsdutils are the rows that distinguish D41 from D8. If a change
	// made Source.Version mirror Version, every row above still passes except
	// these two, so the difference is asserted explicitly.
	if got["bash"].Source.Version == got["bash"].Version {
		t.Error("bash's source and binary versions are equal; the binNMU case is not being exercised")
	}
	if got["bsdutils"].Source.Version == got["bsdutils"].Version {
		t.Error("bsdutils' source and binary versions are equal; the epoch case is not being exercised")
	}
}

// The Status field, read on its THIRD word only. The first two rows are the
// packages syft and trivy each drop.
func TestParse_StatusThirdWordOnly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		want   bool
		why    string
	}{
		{"ordinary", "install ok installed", true, ""},
		{"marked for removal but still on disk", "deinstall ok installed", true,
			"syft substring-matches 'deinstall' and drops this; the files are present"},
		{"marked for purge but still on disk", "purge ok installed", true,
			"trivy scans for a word equal to 'purge' and drops this"},
		{"held", "hold ok installed", true, ""},
		{"unpacked", "install ok unpacked", true, "files are on disk before configuration"},
		{"half-configured", "install ok half-configured", true, ""},
		{"half-installed", "install ok half-installed", true,
			"files may be present; over-reporting here is loud and under-reporting is silent"},
		{"triggers awaited", "install ok triggers-awaited", true, ""},
		{"config files only", "deinstall ok config-files", false,
			"the package's own files are gone; only its configuration remains"},
		{"not installed", "purge ok not-installed", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := stanzas("Package: x", "Status: "+tc.status, "Version: 1.0-1")
			pkgs, err := Parse(strings.NewReader(in), "Debian:12")
			if err != nil {
				t.Fatal(err)
			}
			if got := len(pkgs) == 1; got != tc.want {
				t.Errorf("Status %q -> cataloged=%v, want %v (%s)", tc.status, got, tc.want, tc.why)
			}
		})
	}
}

// An absent Status means installed. Every package in a distroless image is in
// that state, so reading absence as "not installed" reports those images as
// having no packages at all — a clean verdict for a scan that checked nothing.
func TestParse_AbsentStatusIsInstalled(t *testing.T) {
	in := stanzas("Package: libssl3", "Source: openssl", "Version: 3.0.20-1~deb12u2")
	pkgs, err := Parse(strings.NewReader(in), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("parsed %d packages, want 1 — a distroless stanza carries no Status field", len(pkgs))
	}
}

// deb822, not RFC822. Each of these is a shape dpkg accepts and a
// textproto-style reader does not.
func TestParse_Deb822Quirks(t *testing.T) {
	in := stanzas(
		// Whitespace before the colon.
		"Package : spaced",
		"Version: 1.0-1",
		"",
		// Field names are case-insensitive, which is the opposite of the apk
		// database's P:/p: rule.
		"PACKAGE: shouty",
		"VERSION: 2.0-1",
		"source: upstream-shouty",
		"",
		// Continuation on a TAB, not a space. syft tests only for a leading
		// space, so it would read the second line as a new field, fail to find
		// a colon, and silently drop it -- taking the rest of the stanza's
		// fields with it if the tab happened to precede Version.
		"Package: tabbed",
		"Description: first line",
		string(rune(9))+"continued on a tab",
		"Version: 3.0-1",
		"",
		// Runs of blank lines separate stanzas; they do not create empty ones.
		"",
		"",
		"Package: after-blanks",
		"Version: 4.0-1",
	)
	pkgs, err := Parse(strings.NewReader(in), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	got := byName(pkgs)
	for _, want := range []struct{ name, version string }{
		{"spaced", "1.0-1"},
		{"shouty", "2.0-1"},
		{"tabbed", "3.0-1"},
		{"after-blanks", "4.0-1"},
	} {
		p, ok := got[want.name]
		if !ok {
			t.Errorf("%s was not cataloged: %+v", want.name, pkgs)
			continue
		}
		if p.Version != want.version {
			t.Errorf("%s Version = %q, want %q", want.name, p.Version, want.version)
		}
	}
	if len(pkgs) != 4 {
		t.Errorf("parsed %d packages, want exactly 4 — a run of blank lines must not create an empty stanza", len(pkgs))
	}
	if got["shouty"].Source == nil || got["shouty"].Source.Name != "upstream-shouty" {
		t.Errorf("a lower-case 'source:' field was not read: %+v", got["shouty"].Source)
	}
}

// A stanza with no Package is not a package. status.d directories carry
// sibling files that parse as stanzas of nothing.
func TestParse_StanzaWithoutPackageIsNotOne(t *testing.T) {
	in := stanzas("Version: 1.0-1", "Description: an orphan stanza", "", "Package: real", "Version: 2.0-1")
	pkgs, err := Parse(strings.NewReader(in), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "real" {
		t.Errorf("parsed %+v, want only the stanza that names a package", pkgs)
	}
}

// ParseStanza records the file it read, so a report can name where a package
// came from on an image whose database is a directory.
func TestParseStanza_RecordsItsOwnPath(t *testing.T) {
	const p = "/var/lib/dpkg/status.d/libssl3"
	pkgs, err := ParseStanza(strings.NewReader(stanzas("Package: libssl3", "Version: 3.0.20-1~deb12u2")), "Debian:12", p)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("parsed %d packages, want 1", len(pkgs))
	}
	if len(pkgs[0].Locations) != 1 || pkgs[0].Locations[0].Path != p {
		t.Errorf("Locations = %+v, want the file it was read from", pkgs[0].Locations)
	}
	// And the whole-file reader records the canonical path rather than that one.
	whole, err := Parse(strings.NewReader(stanzas("Package: x", "Version: 1.0-1")), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if whole[0].Locations[0].Path != installedPath {
		t.Errorf("Parse recorded %q, want %q", whole[0].Locations[0].Path, installedPath)
	}
}

// A package with no Version is emitted rather than dropped: the matcher already
// reports it as unevaluable, which is loud, and dropping it would be silent.
func TestParse_MissingVersionIsEmittedNotDropped(t *testing.T) {
	in := stanzas("Package: broken", "Status: install ok half-installed")
	pkgs, err := Parse(strings.NewReader(in), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("parsed %d packages, want 1 — dropping it would be a silent miss", len(pkgs))
	}
	if pkgs[0].Version != "" {
		t.Errorf("Version = %q, want empty rather than invented", pkgs[0].Version)
	}
}
