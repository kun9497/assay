package jar

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// zipEntry is one file to write into a fixture archive.
type zipEntry struct {
	name string
	data []byte
}

// buildZip returns the raw bytes of a zip archive holding entries, written in
// the order given - Parse is asserted to walk them in that same order, so a
// fixture that puts the interesting entry second (not first) actually
// exercises that.
func buildZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("create %s: %v", e.name, err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatalf("write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

// writeZip builds a fixture archive and writes it to a fresh temp file,
// returning the path Parse should be called with.
func writeZip(t *testing.T, name string, entries []zipEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buildZip(t, entries), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// pomProps renders a minimal, valid pom.properties body.
func pomProps(groupID, artifactID, version string) []byte {
	return []byte(fmt.Sprintf("groupId=%s\nartifactId=%s\nversion=%s\n", groupID, artifactID, version))
}

// A shaded (fat) jar carries its dependencies' pom.properties alongside its
// own — every one of them is a component, which is the whole reason jar
// scanning exists: it is how a shaded log4j gets caught even though the
// outer jar's own filename says nothing about it.
func TestParse_ShadedJarSurfacesEveryEmbeddedComponent(t *testing.T) {
	path := writeZip(t, "shaded.jar", []zipEntry{
		{"META-INF/maven/com.example.shadedapp/shaded-app/pom.properties",
			pomProps("com.example.shadedapp", "shaded-app", "1.0.0")},
		{"META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties",
			pomProps("org.apache.logging.log4j", "log4j-core", "2.14.1")},
	})

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d package(s), want 2 (the app's own identity and its "+
			"shaded dependency's): %+v", len(pkgs), pkgs)
	}
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.Name] = true
		if len(p.Locations) != 1 || p.Locations[0].Path != path {
			t.Errorf("%s: Locations = %+v, want exactly one entry naming %q",
				p.Name, p.Locations, path)
		}
		if p.Type != "maven" || p.Ecosystem != "Maven" {
			t.Errorf("%s: Type/Ecosystem = %q/%q, want maven/Maven", p.Name, p.Type, p.Ecosystem)
		}
	}
	if !names["com.example.shadedapp:shaded-app"] || !names["org.apache.logging.log4j:log4j-core"] {
		t.Errorf("packages = %v, want both com.example.shadedapp:shaded-app and "+
			"org.apache.logging.log4j:log4j-core", names)
	}
	if stats.Components != 2 || stats.Cataloged != 2 || stats.SkippedNoVersion != 0 {
		t.Errorf("stats = %+v, want 2 components, 2 cataloged, 0 skipped", stats)
	}
	// PURL uses "/" between group and artifact even though the OSV-facing
	// Name above uses ":" (D68's own split between the two spellings).
	want := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	var gotPURL string
	for _, p := range pkgs {
		if p.Name == "org.apache.logging.log4j:log4j-core" {
			gotPURL = p.PURL
		}
	}
	if gotPURL != want {
		t.Errorf("PURL = %q, want %q", gotPURL, want)
	}
}

// A nested archive (Spring Boot's BOOT-INF/lib/*.jar shape, but the rule is
// general — any .jar/.war entry) is recursed into, and its component's
// Location carries both the outer path and the inner one. The outer jar
// itself named no identity, so it must be counted as its own skip rather than
// silently absorbed into the nested component's count.
func TestParse_NestedJarSurfacesWithCompositeLocationAndOuterIsSkipped(t *testing.T) {
	inner := buildZip(t, []zipEntry{
		{"META-INF/maven/org.fixture.inner/inner-lib/pom.properties",
			pomProps("org.fixture.inner", "inner-lib", "1.2.3")},
	})
	path := writeZip(t, "app.jar", []zipEntry{
		{"BOOT-INF/lib/inner-lib-1.2.3.jar", inner},
	})

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d package(s), want 1: %+v", len(pkgs), pkgs)
	}
	p := pkgs[0]
	if p.Name != "org.fixture.inner:inner-lib" || p.Version != "1.2.3" {
		t.Errorf("package = %s@%s, want org.fixture.inner:inner-lib@1.2.3", p.Name, p.Version)
	}
	wantLoc := path + "!BOOT-INF/lib/inner-lib-1.2.3.jar"
	if len(p.Locations) != 1 || p.Locations[0].Path != wantLoc {
		t.Errorf("Locations = %+v, want exactly one entry naming %q", p.Locations, wantLoc)
	}
	// Components=2: the outer archive's own "no pom.properties" skip, plus
	// the one component cataloged from inside the nested jar.
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 2 components (outer skip + inner catalog), "+
			"1 cataloged, 1 skipped", stats)
	}
}

// A nested jar that has no pom.properties of its own must still recurse into
// whatever it contains - the BUT clause in D70's design. This fixture puts a
// pom.properties two levels down (outer has none, middle has none, inner
// has one) so the assertion would fail if recursion stopped at the first
// jar with no identity of its own.
func TestParse_ANestedJarWithNoIdentityOfItsOwnStillRecurses(t *testing.T) {
	inner := buildZip(t, []zipEntry{
		{"META-INF/maven/org.fixture.deepinner/deep-lib/pom.properties",
			pomProps("org.fixture.deepinner", "deep-lib", "5.0.0")},
	})
	middle := buildZip(t, []zipEntry{
		{"lib/inner.jar", inner},
	})
	path := writeZip(t, "outer.jar", []zipEntry{
		{"lib/middle.jar", middle},
	})

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "org.fixture.deepinner:deep-lib" {
		t.Fatalf("packages = %+v, want exactly one org.fixture.deepinner:deep-lib "+
			"- recursion must continue through jars with no pom.properties of "+
			"their own", pkgs)
	}
	wantLoc := path + "!lib/middle.jar!lib/inner.jar"
	if pkgs[0].Locations[0].Path != wantLoc {
		t.Errorf("Location = %q, want %q", pkgs[0].Locations[0].Path, wantLoc)
	}
}

// maxNestedDepth caps recursion at 3 levels below the outer archive. A
// 4-deep chain, with every level carrying its OWN valid pom.properties so the
// only possible skip is attributable to the cap and nothing else, proves the
// deepest jar is refused rather than followed.
func TestParse_DepthCapStopsAFourDeepChain(t *testing.T) {
	level3 := buildZip(t, []zipEntry{
		{"META-INF/maven/com.chainthree.gthree/level-three/pom.properties",
			pomProps("com.chainthree.gthree", "level-three", "3.0.0")},
		{"nested/level4.jar", buildZip(t, []zipEntry{
			// Never opened: the depth cap must refuse level4.jar before its
			// own contents are examined, so a valid pom.properties in here
			// must NOT surface as a component.
			{"META-INF/maven/com.chainfour.gfour/level-four/pom.properties",
				pomProps("com.chainfour.gfour", "level-four", "4.0.0")},
		})},
	})
	level2 := buildZip(t, []zipEntry{
		{"META-INF/maven/com.chaintwo.gtwo/level-two/pom.properties",
			pomProps("com.chaintwo.gtwo", "level-two", "2.0.0")},
		{"nested/level3.jar", level3},
	})
	level1 := buildZip(t, []zipEntry{
		{"META-INF/maven/com.chainone.gone/level-one/pom.properties",
			pomProps("com.chainone.gone", "level-one", "1.0.0")},
		{"nested/level2.jar", level2},
	})
	path := writeZip(t, "outer.jar", []zipEntry{
		{"META-INF/maven/com.chainzero.gzero/level-zero/pom.properties",
			pomProps("com.chainzero.gzero", "level-zero", "0.0.0")},
		{"nested/level1.jar", level1},
	})

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, p := range pkgs {
		if p.Name == "com.chainfour.gfour:level-four" {
			t.Errorf("level-four surfaced despite being 4 levels deep, past "+
				"maxNestedDepth=%d", maxNestedDepth)
		}
	}
	if len(pkgs) != 4 {
		t.Fatalf("got %d package(s), want 4 (levels zero through three; level "+
			"four is past the cap): %+v", len(pkgs), pkgs)
	}
	// Levels zero through three each carry their own valid pom.properties, so
	// the ONLY skip this fixture can produce is level four - proving the
	// count comes from the depth cap, not from a missing identity elsewhere
	// in the chain.
	if stats.Cataloged != 4 || stats.SkippedNoVersion != 1 || stats.Components != 5 {
		t.Errorf("stats = %+v, want 4 cataloged and exactly 1 skip (the level "+
			"past maxNestedDepth=%d)", stats, maxNestedDepth)
	}
}

// A pom.properties missing any one of the three required keys is counted and
// skipped, never patched with a fabricated value.
func TestParse_PomPropertiesMissingAKeyIsCountedAndSkipped(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
	}{
		{"missing version", "groupId=com.example.missingversion\nartifactId=no-version\n"},
		{"missing artifactId", "groupId=com.example.missingartifact\nversion=1.0.0\n"},
		{"missing groupId", "artifactId=no-group\nversion=1.0.0\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := writeZip(t, "incomplete.jar", []zipEntry{
				{"META-INF/maven/whatever/whatever/pom.properties", []byte(tt.body)},
			})
			pkgs, stats, err := Parse(path)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(pkgs) != 0 {
				t.Fatalf("got %d package(s), want 0 - an incomplete identity must "+
					"never be partially guessed: %+v", len(pkgs), pkgs)
			}
			if stats.Components != 1 || stats.Cataloged != 0 || stats.SkippedNoVersion != 1 {
				t.Errorf("stats = %+v, want 1 component, 0 cataloged, 1 skipped", stats)
			}
		})
	}
}

// An empty file and a file that is not a zip at all both reach a loud error
// naming the path, not a panic or a silent empty inventory.
func TestParse_EmptyOrGarbageZip(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.jar")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Parse(path); err == nil {
			t.Error("Parse(empty file) = nil error, want one")
		}
	})
	t.Run("garbage bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "garbage.jar")
		if err := os.WriteFile(path, []byte("this is not a zip file at all\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, err := Parse(path)
		if err == nil {
			t.Fatal("Parse(garbage) = nil error, want one")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("err = %v, want it to name %s", err, path)
		}
	})
}

// bufio.Scanner's ScanLines strips a trailing "\r", so CRLF-terminated
// pom.properties (real Windows-built jars carry these) must parse the same
// as LF-terminated ones, and "#" comment lines must be skipped rather than
// misread as a malformed key=value pair.
func TestParse_PropertiesWithCRLFAndCommentsParse(t *testing.T) {
	body := "#\r\n# Generated by Maven\r\n#\r\ngroupId=com.example.crlffixture\r\n" +
		"artifactId=crlf-fixture\r\nversion=9.9.9\r\n"
	path := writeZip(t, "crlf.jar", []zipEntry{
		{"META-INF/maven/com.example.crlffixture/crlf-fixture/pom.properties", []byte(body)},
	})

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d package(s), want 1: %+v", len(pkgs), pkgs)
	}
	p := pkgs[0]
	if p.Name != "com.example.crlffixture:crlf-fixture" || p.Version != "9.9.9" {
		t.Errorf("package = %s@%s, want com.example.crlffixture:crlf-fixture@9.9.9",
			p.Name, p.Version)
	}
	if stats.Cataloged != 1 || stats.SkippedNoVersion != 0 {
		t.Errorf("stats = %+v, want 1 cataloged, 0 skipped - comments and CRLF "+
			"must not be misread as data", stats)
	}
}

// A key written with trailing spaces before "=" (java.util.Properties
// accepts this; nothing forbids a build tool from emitting it) must still be
// recognized rather than treated as an unknown key with a mangled name.
func TestParse_KeysWithTrailingSpacesParse(t *testing.T) {
	body := "groupId =com.example.trailingspace\nartifactId\t=trailing-fixture\nversion=1.0.0\n"
	path := writeZip(t, "trailing.jar", []zipEntry{
		{"META-INF/maven/com.example.trailingspace/trailing-fixture/pom.properties", []byte(body)},
	})

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "com.example.trailingspace:trailing-fixture" {
		t.Fatalf("packages = %+v, want exactly one "+
			"com.example.trailingspace:trailing-fixture", pkgs)
	}
	if pkgs[0].Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", pkgs[0].Version)
	}
}

// The final package list is sorted (by name, then version, then location)
// regardless of the order entries appear in the archive - dirscan's
// sortPackages precedent. The fixture writes the entries in the opposite
// order so an implementation that just appended in archive order would fail.
func TestParse_PackagesAreSortedNotArchiveOrder(t *testing.T) {
	path := writeZip(t, "unsorted.jar", []zipEntry{
		{"META-INF/maven/com.example.zzzfixture/zzz/pom.properties",
			pomProps("com.example.zzzfixture", "zzz", "1.0.0")},
		{"META-INF/maven/com.example.aaafixture/aaa/pom.properties",
			pomProps("com.example.aaafixture", "aaa", "1.0.0")},
	})

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d package(s), want 2: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "com.example.aaafixture:aaa" || pkgs[1].Name != "com.example.zzzfixture:zzz" {
		t.Errorf("order = [%s, %s], want aaa before zzz - the merge must sort, "+
			"not just append in archive order", pkgs[0].Name, pkgs[1].Name)
	}
}

// readEntryCapped's declared-size fast path is tested directly rather than
// through Parse: reaching it through a real archive would need an actual
// 512 MiB fixture, which is impractical for a unit test and would not
// exercise anything the direct check does not already cover. zip.File
// embeds FileHeader by value, so its UncompressedSize64 can be forged in
// memory on a real (tiny) entry without needing the archive's bytes to
// agree with it - the fast path fires before the entry is ever opened.
func TestReadEntryCapped_RefusesADeclaredSizePastTheCap(t *testing.T) {
	data := buildZip(t, []zipEntry{{"whatever", []byte("small")}})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	f.UncompressedSize64 = maxEntrySize + 1

	if _, err := readEntryCapped(f); err == nil {
		t.Fatal("readEntryCapped did not refuse a declared size past the cap")
	}
}

// zeroReader streams n zero bytes without ever materializing them all at
// once, so a fixture larger than maxEntrySize can be built without holding a
// 512+ MiB []byte in the test process.
type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= int64(len(p))
	return len(p), nil
}

// TestParse_RefusesAPomPropertiesPastTheSizeCap is the caller-side proof for
// readEntryCapped's cap that TestReadEntryCapped_RefusesADeclaredSizePastTheCap
// above deliberately does not give: that test's own comment explains why it
// drives the helper directly rather than through Parse -- reaching the cap
// through a real archive "would need an actual 512 MiB fixture, which is
// impractical." That leaves addComponent's own call site (jar.go) unheld:
// nothing proves Parse, walking a real archive, ever reaches the cap rather
// than an unbounded read of whatever a crafted pom.properties entry claims.
//
// The fixture writes a genuinely valid, complete set of properties FIRST,
// then pads past the cap with zero bytes carrying no newline -- so a full
// (uncapped) read would parse groupId/artifactId/version successfully and
// catalog a package, and only the size cap stops it. A padding fixture that
// never wrote valid properties at all would pass under the mutation for the
// wrong reason: an all-zero payload parses to zero properties either way, so
// "no package" would come from D70's missing-key skip regardless of whether
// the cap ran -- the trap CLAUDE.md calls "asserting presence when order (or
// cause) is the point." A run of zero bytes compresses to a few hundred
// bytes under DEFLATE, so the fixture is tiny on disk despite decompressing
// past the cap -- streamed through zeroReader rather than built as one
// []byte, so the test itself does not need to hold 512+ MiB either.
func TestParse_RefusesAPomPropertiesPastTheSizeCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.jar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/maven/com.example.huge/huge/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	valid := []byte("groupId=com.example.huge\nartifactId=huge\nversion=1.0.0\n")
	if _, err := w.Write(valid); err != nil {
		t.Fatal(err)
	}
	// Zero bytes with no newline: one token far longer than
	// bufio.Scanner's default line-length limit, so a CAPPED read never
	// gets far enough to notice that, while an UNCAPPED one reads it all
	// and still finds the three valid lines already scanned above it.
	if _, err := io.Copy(w, &zeroReader{n: maxEntrySize + 1 - int64(len(valid))}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("got %d package(s), want 0 -- an oversized pom.properties must be "+
			"refused, not read in full and cataloged: %+v", len(pkgs), pkgs)
	}
	if stats.SkippedNoVersion != 1 {
		t.Errorf("SkippedNoVersion = %d, want 1 -- the size cap must count as a "+
			"skip, the same as any other unreadable pom.properties", stats.SkippedNoVersion)
	}
}
