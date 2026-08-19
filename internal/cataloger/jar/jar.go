// Package jar turns a Java archive (.jar or .war) into the normalized
// package inventory the matcher consumes (D70). Unlike a lockfile, nothing in
// a jar names the whole archive's own dependency set up front — identity has
// to be read back out of whichever META-INF/maven/*/*/pom.properties entries
// the build tooling embedded, one per Maven artifact that went into the
// archive.
//
// A shaded (fat) jar carries every one of its dependencies' pom.properties
// alongside its own — that is how a shaded log4j is caught even though the
// outer jar's own name says nothing about it — and Spring Boot's
// BOOT-INF/lib/*.jar is an ordinary nested archive, not a special case: any
// entry ending .jar or .war is recursed into the same way.
package jar

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/pkgmeta"
)

const (
	// maxNestedDepth caps how many levels of jar-in-jar nesting Parse follows.
	// The outer archive Parse opens is depth 0; a nested jar found inside it is
	// depth 1, and so on. An entry that would be depth 4 or deeper (a jar
	// found inside a jar inside a jar inside the outer one) is a counted skip
	// rather than followed forever — Spring Boot's BOOT-INF/lib/*.jar is depth
	// 1, so 3 levels covers every real packaging shape seen and still bounds a
	// crafted or accidentally self-referential archive to a fixed amount of
	// work.
	maxNestedDepth = 3

	// maxEntrySize caps how large a single zip entry's DECOMPRESSED content
	// may be before Parse reads it into memory. A zip entry's declared and
	// actual size are both attacker-controlled — a small compressed entry can
	// claim, or actually inflate to, an enormous decompressed size (a "zip
	// bomb") — so this is checked against the entry's declared size before
	// allocating, and enforced again while copying in case the header lied.
	maxEntrySize = 512 * 1024 * 1024 // 512 MiB
)

// jarLocationSeparator joins an outer archive's path with the path of a
// nested archive entry inside it, one level at a time, so a component found
// three jars deep carries every step: "app.jar!BOOT-INF/lib/inner.jar!a/b.jar".
// This is the one place that separator is spelled, so Location construction
// cannot drift between the top-level call and the recursive one.
const jarLocationSeparator = "!"

// pomPropertiesPrefix and pomPropertiesSuffix bound the entry names Parse
// reads identity from: META-INF/maven/<groupId>/<artifactId>/pom.properties.
// Matched by prefix and suffix rather than by splitting on "/" and counting
// segments, because groupId itself is a single path segment ("org.apache.commons",
// dots and all, never turned into directories) and MANIFEST.MF or a jar's own
// class files must never be mistaken for one of these no matter how a build
// tool laid out the rest of META-INF/.
const (
	pomPropertiesPrefix = "META-INF/maven/"
	pomPropertiesSuffix = "/pom.properties"
)

// Parse reads path as a Java archive and returns the Maven components its
// pom.properties entries name, recursing into nested jars and wars up to
// maxNestedDepth. Distro stays nil — a jar is not an operating system (D7).
//
// Identity comes from pom.properties ONLY (D70): a jar or war entry with none
// is a real component the scan saw and could not identify, not a package
// whose name and version can be guessed from a filename or MANIFEST.MF — a
// fabricated GAV is either a false positive against a package nobody ships or
// a false negative clearing one they do, either way silent. It is counted
// instead, the same "loud skip, not a guess" rule pom.properties missing one
// of its three required keys gets below.
func Parse(path string) ([]pkgmeta.Package, cyclonedx.Stats, error) {
	zrc, err := zip.OpenReader(path)
	if err != nil {
		return nil, cyclonedx.Stats{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer zrc.Close()

	var (
		pkgs  []pkgmeta.Package
		stats cyclonedx.Stats
	)
	parseArchive(&zrc.Reader, path, 0, &pkgs, &stats)

	sortPackages(pkgs)
	return pkgs, stats, nil
}

// parseArchive extracts every component named directly by zr's own entries
// (not by entries inside a nested jar it recurses into — those are that
// nested call's own responsibility) and recurses into every entry that looks
// like a nested archive. location is what a component or skip found directly
// in zr is attributed to: the path this call was reached at, built one
// "!nested/entry" segment per level of recursion.
//
// zr.File is read in the archive's own entry order — Parse only sorts the
// FINAL merged package list (item 6), not the order components are
// discovered in, so recursion and skip accounting stay deterministic on their
// own before that sort ever runs.
func parseArchive(zr *zip.Reader, location string, depth int, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	sawPomProperties := false

	for _, f := range zr.File {
		switch {
		case isPomProperties(f.Name):
			sawPomProperties = true
			addComponent(f, location, pkgs, stats)

		case isNestedArchive(f.Name):
			// A nested jar that has no pom.properties of its own yet contains
			// DEEPER jars still recurses (D70's explicit carve-out) — that
			// falls out naturally here, since this switch processes every
			// entry regardless of whether this call ever sets
			// sawPomProperties.
			recurseIntoNested(f, location, depth, pkgs, stats)
		}
	}

	if !sawPomProperties {
		// This archive — outer or nested — named no Maven identity at all.
		// It was still a real thing the scan opened and looked inside, so it
		// is counted once here rather than vanishing: an archive that turns
		// out to hold nothing recognizable must look different in Stats from
		// one that was never opened.
		stats.Components++
		stats.SkippedNoVersion++
	}
}

// recurseIntoNested handles one zip entry that looks like a nested archive:
// enforcing the depth and size caps, reading it into memory, and recursing.
// Every refusal path here is a counted skip (Components++, SkippedNoVersion++)
// rather than a silent drop or a truncated read — "exceeding either [cap] is
// a counted skip naming the entry, never silent truncation" is D70's own
// requirement, and f.Name is what the surrounding doc comments on
// maxNestedDepth and maxEntrySize name when explaining why a given entry hit
// one.
//
// A successful recursion does NOT increment stats.Components for the nested
// entry itself: parseArchive's own recursive call already accounts for
// everything reachable inside it (either real components, or its own
// "sawPomProperties == false" skip if it turns out to hold none) — counting
// the entry a second time here would double it against what its contents
// already contribute.
func recurseIntoNested(f *zip.File, location string, depth int, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	if depth+1 > maxNestedDepth {
		// f.Name is one level past maxNestedDepth from location — named in
		// this comment rather than in Stats because cyclonedx.Stats (D70's
		// fixed Parse signature) carries only counts, no per-entry detail;
		// the count itself is what reaches the report.
		stats.Components++
		stats.SkippedNoVersion++
		return
	}

	data, err := readEntryCapped(f)
	if err != nil {
		// Either the size cap refused it or the entry could not be read at
		// all (a corrupt zip stream). Either way this archive was seen and
		// could not be examined further — the same "counted, not guessed"
		// treatment as a nested archive with no pom.properties, because from
		// here nothing more can be said about what it contains.
		stats.Components++
		stats.SkippedNoVersion++
		return
	}

	nested, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		// f.Name ends .jar or .war but is not actually a readable zip.
		stats.Components++
		stats.SkippedNoVersion++
		return
	}

	parseArchive(nested, location+jarLocationSeparator+f.Name, depth+1, pkgs, stats)
}

// addComponent reads one META-INF/maven/*/*/pom.properties entry and, if it
// carries all three required keys, appends the Maven component it names.
func addComponent(f *zip.File, location string, pkgs *[]pkgmeta.Package, stats *cyclonedx.Stats) {
	stats.Components++

	data, err := readEntryCapped(f)
	if err != nil {
		// Unreadable or larger than the cap: the identity cannot be trusted,
		// so this is a skip rather than a guess — the same rule a missing key
		// gets below.
		stats.SkippedNoVersion++
		return
	}

	props := parseProperties(data)
	groupID := props["groupId"]
	artifactID := props["artifactId"]
	version := props["version"]
	if groupID == "" || artifactID == "" || version == "" {
		// D70: never partially guess an identity from two of the three keys.
		// A pom.properties missing one is counted and skipped, not patched
		// with a fabricated value.
		stats.SkippedNoVersion++
		return
	}

	stats.Cataloged++
	*pkgs = append(*pkgs, pkgmeta.Package{
		Name:      groupID + ":" + artifactID,
		Version:   version,
		Type:      "maven",
		Ecosystem: "Maven",
		PURL:      "pkg:maven/" + groupID + "/" + artifactID + "@" + version,
		Locations: []pkgmeta.Location{{Path: location}},
	})
}

// readEntryCapped reads f's full decompressed content, refusing anything
// larger than maxEntrySize. The check runs twice: once against f's declared
// UncompressedSize64 before any allocation (cheap, and enough to refuse an
// entry that is honest about being oversized), and again while copying, in
// case the declared size understates what actually comes out — never
// silently truncated in either case, an oversized entry is always an error
// the caller turns into a counted skip.
func readEntryCapped(f *zip.File) ([]byte, error) {
	if f.UncompressedSize64 > maxEntrySize {
		return nil, fmt.Errorf("%s: declared decompressed size %d exceeds the %d byte cap",
			f.Name, f.UncompressedSize64, maxEntrySize)
	}

	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer rc.Close()

	// io.LimitReader lets one byte past the cap through and then stops (with
	// a plain io.EOF, indistinguishable from a genuinely short stream) rather
	// than erroring on its own — so the length is what is checked below, not
	// whether ReadAll returned an error. Reading maxEntrySize+1 rather than
	// exactly maxEntrySize is what makes an entry whose actual output exceeds
	// the declared size (a lying header) still detectable instead of being
	// silently truncated to precisely the cap.
	data, err := io.ReadAll(io.LimitReader(rc, maxEntrySize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Name, err)
	}
	if int64(len(data)) > maxEntrySize {
		return nil, fmt.Errorf("%s: decompressed size exceeds the %d byte cap", f.Name, maxEntrySize)
	}
	return data, nil
}

// isPomProperties reports whether name is a Maven identity file: exactly the
// META-INF/maven/.../pom.properties shape, matched by prefix and suffix (see
// the package-level doc comment on why segment-counting is not needed).
func isPomProperties(name string) bool {
	return strings.HasPrefix(name, pomPropertiesPrefix) && strings.HasSuffix(name, pomPropertiesSuffix)
}

// isNestedArchive reports whether name looks like a jar or war to recurse
// into, case-insensitively — a build tool can write "app.WAR" on a
// case-preserving filesystem, and the archive's own entry name is whatever
// was zipped, not something this project controls.
func isNestedArchive(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") || strings.HasSuffix(lower, ".war")
}

// parseProperties reads the Java .properties subset pom.properties uses:
// key=value lines, "#" comments, blank lines ignored, and a key's trailing
// spaces before "=" trimmed (Maven's own writer does not emit these, but
// nothing about the format forbids them, and a strict parser here would
// refuse a file the JVM's own java.util.Properties reads without complaint).
// bufio.Scanner's default split function strips a trailing "\r", so CRLF line
// endings are handled without any separate case.
func parseProperties(data []byte) map[string]string {
	props := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(line[:i])
		if key == "" {
			continue
		}
		props[key] = strings.TrimSpace(line[i+1:])
	}
	return props
}

// sortPackages orders the final component list by lessPackage so two Parse
// calls against the same archive agree, regardless of the archive's own
// entry order (dirscan's sortPackages precedent — see its own doc comment).
func sortPackages(pkgs []pkgmeta.Package) {
	sort.Slice(pkgs, func(i, j int) bool { return lessPackage(pkgs[i], pkgs[j]) })
}

// lessPackage is the total order sortPackages sorts by: name, then version,
// then the first location path. Every jar-sourced package shares Ecosystem
// "Maven", so that key would never break a tie and is left out rather than
// carried along for no effect.
func lessPackage(a, b pkgmeta.Package) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return locationPath(a) < locationPath(b)
}

func locationPath(p pkgmeta.Package) string {
	if len(p.Locations) == 0 {
		return ""
	}
	return p.Locations[0].Path
}
