package jar

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/source"
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

// A trailing "\r" is stripped from each line, so CRLF-terminated
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

// QA 2026-10-30: parseProperties split lines with bufio.Scanner and never
// read Err(), so a comment line over 64 KiB stopped it and the keys after it
// were never read. The jar was then counted as having no version and not
// evaluated, though its pom.properties named one.
func TestParse_PropertiesAfterALongLineAreRead(t *testing.T) {
	body := "# " + strings.Repeat("x", 70*1024) + "\ngroupId=com.example.longline\n" +
		"artifactId=longline-fixture\nversion=1.2.3\n"
	path := writeZip(t, "longline.jar", []zipEntry{
		{"META-INF/maven/com.example.longline/longline-fixture/pom.properties", []byte(body)},
	})
	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Version != "1.2.3" || stats.SkippedNoVersion != 0 {
		t.Errorf("pkgs = %+v, stats = %+v: want the one package at 1.2.3, nothing skipped", pkgs, stats)
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

// readEntry's declared-size fast path is tested directly rather than
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
	f.UncompressedSize64 = uint64(source.MaxFileBytes) + 1

	if _, err := newParser("x.jar").readEntry(f, "x.jar"); err == nil {
		t.Fatal("readEntry did not refuse a declared size past the cap")
	}
}

// zeroReader streams n zero bytes without ever materializing them all at
// once, so a fixture larger than source.MaxFileBytes can be built without holding a
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
// readEntry's cap that TestReadEntryCapped_RefusesADeclaredSizePastTheCap
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
	if _, err := io.Copy(w, &zeroReader{n: source.MaxFileBytes + 1 - int64(len(valid))}); err != nil {
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

// lowerFileLimit lowers D112's per-file limit for one test and restores it
// after — internal/source's lowerLimit, which this package cannot reach.
func lowerFileLimit(t *testing.T, v int64) {
	t.Helper()
	prev := source.MaxFileBytes
	source.MaxFileBytes = v
	t.Cleanup(func() { source.MaxFileBytes = prev })
}

// D112's revision: the archive itself is bounded before zip.OpenReader reads
// its central directory, not only the entries read out of it. The fixture is
// a real archive; only the limit moves.
//
// The exactly-the-limit row is the boundary: a file the size of the limit is
// inside it, as readEntry's limit+1 read already treats one, so a check
// written >= refuses an archive the limit allows. And the error is the
// limit's own sentence, whole — FileLimitError already names the path, so a
// wrapper of "open <path>: " in front of it says the path twice and turns a
// size refusal into what reads like an I/O failure.
func TestParse_RefusesAnArchivePastTheFileLimit(t *testing.T) {
	path := writeZip(t, "app.jar", []zipEntry{
		{"META-INF/maven/com.example.archivelimit/limit/pom.properties",
			pomProps("com.example.archivelimit", "limit", "1.0.0")},
	})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("exactly the limit is read", func(t *testing.T) {
		lowerFileLimit(t, info.Size())
		pkgs, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse(archive of exactly the limit): %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "com.example.archivelimit:limit" {
			t.Errorf("pkgs = %+v, want the one component", pkgs)
		}
	})

	t.Run("one byte past the limit is refused", func(t *testing.T) {
		lowerFileLimit(t, info.Size()-1)
		pkgs, _, err := Parse(path)
		if err == nil {
			t.Fatalf("Parse(archive past the limit) = %+v, nil; want D112's per-file limit error", pkgs)
		}
		msg := err.Error()
		if !strings.Contains(msg, "exceeds the") || !strings.Contains(msg, path) {
			t.Errorf("err = %q, want the limit's error naming %s", msg, path)
		}
		if strings.Contains(msg, "open ") {
			t.Errorf("err = %q, want the limit's sentence unwrapped - it already names the path", msg)
		}
		if want := source.FileLimitError(path).Error(); msg != want {
			t.Errorf("err = %q, want %q", msg, want)
		}
	})

	// Order is the subject of the revision, not only presence: the size is
	// checked BEFORE zip.NewReader, because the central directory is the read
	// it bounds. Both rows above use a valid archive, so a check moved to after
	// a successful open still refuses it with the same sentence and they stay
	// green. This file has the local-header magic and no central directory, so
	// only a check made first answers with the limit — one made after the open
	// never runs, and the open's "not a valid zip file" comes out instead.
	t.Run("past the limit is refused before the central directory is read", func(t *testing.T) {
		junk := filepath.Join(t.TempDir(), "junk.jar")
		body := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 4096)...)
		if err := os.WriteFile(junk, body, 0o600); err != nil {
			t.Fatal(err)
		}
		// Within the limit the open is what fails, which is what makes the row
		// below able to tell the two orders apart.
		if _, _, err := Parse(junk); !errors.Is(err, zip.ErrFormat) {
			t.Fatalf("Parse(fixture within the limit) err = %v, want zip.ErrFormat - the fixture must "+
				"have no readable central directory", err)
		}

		lowerFileLimit(t, int64(len(body))-1)
		_, _, err := Parse(junk)
		if want := source.FileLimitError(junk).Error(); err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q - the central directory was read before the size was checked", err, want)
		}
	})
}

// One number, not two that happen to agree (D112's revision): the cap on an
// entry's decompressed bytes is the same variable as the cap on the archive.
// Lowering MaxFileBytes alone must move it. A private constant of 512 MiB —
// what the cap was until the revision — reads this entry in full and catalogs
// it, because a few KiB is nowhere near 512 MiB.
//
// Driven through Parse first, so addComponent's call is held and not only the
// helper; then readEntry directly for the read-time check's boundary,
// which Parse's skip count cannot tell apart from the declared-size one.
func TestEntryCap_IsTheFileLimit(t *testing.T) {
	const limit = 4 << 10
	valid := pomProps("com.example.onenumber", "one-number", "1.0.0")
	body := append(append([]byte{}, valid...), bytes.Repeat([]byte{0}, limit+1-len(valid))...)
	path := writeZip(t, "one-number.jar", []zipEntry{
		{"META-INF/maven/com.example.onenumber/one-number/pom.properties", body},
	})
	lowerFileLimit(t, limit)

	// Zeros compress to almost nothing, so the archive is far inside the
	// limit its entry exceeds — the archive check passes and the entry's is
	// the one under test.
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat fixture archive: %v", err)
	} else if info.Size() >= limit {
		t.Fatalf("fixture archive is %d bytes, want it under the %d limit", info.Size(), limit)
	}
	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 || stats.SkippedNoVersion != 1 {
		t.Errorf("pkgs = %+v, stats = %+v; want the entry past MaxFileBytes refused and "+
			"counted, not read in full and cataloged", pkgs, stats)
	}

	data := buildZip(t, []zipEntry{
		{"at", bytes.Repeat([]byte{'a'}, limit)},
		{"past", bytes.Repeat([]byte{'a'}, limit+1)},
	})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newParser("x.jar").readEntry(zr.File[0], "x.jar"); err != nil {
		t.Errorf("readEntry(entry of exactly MaxFileBytes): %v, want it read", err)
	}
	if _, err := newParser("x.jar").readEntry(zr.File[1], "x.jar"); err == nil {
		t.Error("readEntry(entry one byte past MaxFileBytes) = nil error, want the cap")
	}
}

// The nested half of the same number. recurseIntoNested's readEntry is
// the only thing that bounds a jar-in-jar before zip.NewReader reads ITS
// central directory into memory — the archive check in Parse sees only the
// outer file on disk, and a nested archive is never on disk. So the call is
// held here, through Parse, and not only the helper: TestEntryCap_IsTheFileLimit
// drives addComponent's call, and deleting this one left every test green.
//
// The inner jar is padded with its zip comment to an exact size, so the two
// rows sit either side of the limit by one byte: the at-limit one is read and
// its component cataloged, which is what proves the over-limit one was refused
// by the cap and not by anything else about the fixture. The outer archive
// carries an identity of its own so the counts are exact: the inner refusal
// is the only skip, counted once — a silent drop reads 0, a double count 2.
// The outer is deflated, so a few KiB of comment costs it almost nothing and
// Parse's archive check passes in both rows.
func TestNestedArchive_EntryCapIsTheFileLimit(t *testing.T) {
	const limit = 4 << 10
	innerOfSize := func(t *testing.T, size int) []byte {
		t.Helper()
		build := func(comment string) []byte {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			w, err := zw.Create("META-INF/maven/com.example.nestedcap/inner/pom.properties")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(pomProps("com.example.nestedcap", "inner", "2.0.0")); err != nil {
				t.Fatal(err)
			}
			if err := zw.SetComment(comment); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			return buf.Bytes()
		}
		bare := build("")
		data := build(strings.Repeat("a", size-len(bare)))
		if len(data) != size {
			t.Fatalf("inner jar is %d bytes, want exactly %d", len(data), size)
		}
		return data
	}

	for _, tc := range []struct {
		name          string
		innerSize     int
		wantInner     bool
		wantCataloged int
		wantSkipped   int
	}{
		{"exactly the limit", limit, true, 2, 0},
		{"one byte past the limit", limit + 1, false, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeZip(t, "outer.jar", []zipEntry{
				{"META-INF/maven/com.example.nestedcap/outer/pom.properties",
					pomProps("com.example.nestedcap", "outer", "1.0.0")},
				{"lib/inner.jar", innerOfSize(t, tc.innerSize)},
			})
			lowerFileLimit(t, limit)
			if info, err := os.Stat(path); err != nil {
				t.Fatalf("stat fixture archive: %v", err)
			} else if info.Size() >= limit {
				t.Fatalf("fixture archive is %d bytes, want it under the %d limit", info.Size(), limit)
			}

			pkgs, stats, err := Parse(path)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			gotInner := false
			for _, p := range pkgs {
				if p.Name == "com.example.nestedcap:inner" {
					gotInner = true
				}
			}
			if gotInner != tc.wantInner {
				t.Errorf("inner component cataloged = %v, want %v (pkgs %+v)", gotInner, tc.wantInner, pkgs)
			}
			if stats.Components != 2 || stats.Cataloged != tc.wantCataloged || stats.SkippedNoVersion != tc.wantSkipped {
				t.Errorf("stats = %+v, want Components 2, Cataloged %d, SkippedNoVersion %d",
					stats, tc.wantCataloged, tc.wantSkipped)
			}
		})
	}
}

// lowerScanLimit lowers D112's per-scan figure, which this cataloger reads as
// its per-archive budget (QA 2026-11-02), for one test.
func lowerScanLimit(t *testing.T, v int64) {
	t.Helper()
	prev := source.MaxScanBytes
	source.MaxScanBytes = v
	t.Cleanup(func() { source.MaxScanBytes = prev })
}

// paddedEntry is a valid pom.properties body padded with zeros to exactly
// size, so every entry parses and only a bound can stop it.
func paddedEntry(groupID, artifactID string, size int) []byte {
	body := pomProps(groupID, artifactID, "1.0.0")
	return append(body, make([]byte, size-len(body))...)
}

// QA 2026-11-02: the per-entry cap bounded one entry and nothing bounded the
// sum. The budget is MaxScanBytes across every entry of one Parse, and the
// boundary is exact: entries that add up to the budget are read and
// cataloged, one byte more is the error naming the entry that went over.
// Each entry here is far under the per-entry cap (its default), so the sum
// is the only thing that can refuse it -- a check against the entry alone,
// or a budget never charged, catalogs all three in both rows.
func TestParse_InflateBudgetIsTheSumAcrossEntries(t *testing.T) {
	const entrySize = 2 << 10
	entries := []zipEntry{
		{"META-INF/maven/com.example.budget/first/pom.properties", paddedEntry("com.example.budget", "first", entrySize)},
		{"META-INF/maven/com.example.budget/second/pom.properties", paddedEntry("com.example.budget", "second", entrySize)},
		{"META-INF/maven/com.example.budget/third/pom.properties", paddedEntry("com.example.budget", "third", entrySize)},
	}

	t.Run("exactly the budget is read", func(t *testing.T) {
		path := writeZip(t, "exact.jar", entries)
		lowerScanLimit(t, 3*entrySize)
		pkgs, stats, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse(entries summing to exactly the budget): %v", err)
		}
		if len(pkgs) != 3 || stats.Cataloged != 3 {
			t.Errorf("pkgs = %d, stats = %+v; want all three cataloged", len(pkgs), stats)
		}
	})

	t.Run("one byte past the budget names the entry that crossed it", func(t *testing.T) {
		path := writeZip(t, "over.jar", entries)
		lowerScanLimit(t, 3*entrySize-1)
		pkgs, stats, err := Parse(path)
		if err == nil {
			t.Fatalf("Parse = %d package(s), %+v, nil; want the budget's error", len(pkgs), stats)
		}
		var be *budgetError
		if !errors.As(err, &be) {
			t.Errorf("err = %T %v, want a *budgetError", err, err)
		}
		want := source.ArchiveLimitError(path, "META-INF/maven/com.example.budget/third/pom.properties").Error()
		if err.Error() != want {
			t.Errorf("err = %q, want %q", err, want)
		}
		if pkgs != nil || stats != (cyclonedx.Stats{}) {
			t.Errorf("pkgs = %+v, stats = %+v; want nothing returned beside the error -- a partial "+
				"inventory of the archive is the shape the error exists to refuse", pkgs, stats)
		}
	})
}

// A nested archive is read into memory before its own entries are, so its
// bytes are the budget's too -- at every depth, not only the outer archive's
// own entries. The outer carries nothing but the nested jar, so the sum here
// is the nested archive's bytes plus the one entry read out of it; the
// budget sits between the two, and the error names the inner entry by its
// composite path.
func TestParse_InflateBudgetChargesNestedArchives(t *testing.T) {
	inner := buildZip(t, []zipEntry{
		{"META-INF/maven/com.example.nestedbudget/inner/pom.properties", paddedEntry("com.example.nestedbudget", "inner", 1<<10)},
	})
	path := writeZip(t, "outer.jar", []zipEntry{{"lib/inner.jar", inner}})

	t.Run("the nested archive and its entry together fit", func(t *testing.T) {
		lowerScanLimit(t, int64(len(inner))+(1<<10))
		pkgs, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(pkgs) != 1 || pkgs[0].Name != "com.example.nestedbudget:inner" {
			t.Errorf("pkgs = %+v, want the inner component", pkgs)
		}
	})

	t.Run("the nested archive's own bytes count", func(t *testing.T) {
		// Room for the nested archive and all but one byte of its entry: a
		// budget charged only at depth 0 reads the entry in full.
		lowerScanLimit(t, int64(len(inner))+(1<<10)-1)
		_, _, err := Parse(path)
		want := source.ArchiveLimitError(path, "lib/inner.jar!META-INF/maven/com.example.nestedbudget/inner/pom.properties").Error()
		if err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q", err, want)
		}
	})
}

// What a failed read inflated is charged too. An entry refused on its
// declared size costs nothing -- it is never opened -- but a header that
// lies low is opened, inflated past its declaration and refused by
// archive/zip mid-stream; those bytes were inflated, and twelve such entries
// are the probe's shape with a different refusal. The header is forged in
// memory on a real entry, the way TestReadEntry_RefusesADeclaredSizePastTheCap
// forges it high.
func TestReadEntry_ChargesWhatAFailedReadInflated(t *testing.T) {
	data := buildZip(t, []zipEntry{{"liar", make([]byte, 64<<10)}})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	f.UncompressedSize64 = 1 << 10
	p := newParser("x.jar")
	const budget = 1 << 20
	p.budget = budget

	if _, err := p.readEntry(f, "x.jar"); err == nil {
		t.Fatal("readEntry read an entry past its declared size without error")
	}
	// archive/zip hands back what it inflated before the read that crossed
	// the declared size, and drops that read's own bytes; whatever reached
	// the parser is what it holds in memory, and that is what is charged. The
	// exact count is io.ReadAll's buffer growth, not a contract.
	if p.budget >= budget {
		t.Errorf("budget after the failed read = %d, want it below %d: the bytes a failed read "+
			"inflated were not charged", p.budget, budget)
	}
	if p.budget < budget-(1<<10) {
		t.Errorf("budget after the failed read = %d; more than the declared 1 KiB was charged, "+
			"so the read ran past archive/zip's own refusal", p.budget)
	}
}

// The read is bounded by what the budget has left, not only by the cap:
// with a kilobyte of budget left, an entry is read a kilobyte and one byte,
// not up to the half-gigabyte cap, before the parse learns it is over.
func TestReadEntry_ReadsNoFurtherThanTheBudgetLeaves(t *testing.T) {
	data := buildZip(t, []zipEntry{{"big", make([]byte, 64<<10)}})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	p := newParser("x.jar")
	p.budget = 1 << 10
	if _, err := p.readEntry(zr.File[0], "x.jar"); err == nil {
		t.Fatal("readEntry read a 64 KiB entry against a 1 KiB budget without error")
	}
	// The budget records what was read: the bound plus the one byte past it.
	if p.budget != -1 {
		t.Errorf("budget after the read = %d, want -1: the read must stop one byte past what "+
			"the budget allowed, not run to the entry's end or the cap", p.budget)
	}
}
