package scancmd

// Caller-first for D70's dispatch: the assertions below drive Run, not
// jar.Parse directly, so deleting the `case source.TargetJar:` arm (or the
// `looksLikeJar` sniff it depends on in internal/source/classify.go) must
// turn these red. jar.Parse's own exhaustive behaviour (shading, nesting,
// depth cap, and so on) is covered directly in
// internal/cataloger/jar/jar_test.go; what belongs here is only that Run
// actually reaches it and reports what it found.

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// writeJarFixture builds a minimal jar naming one Maven component and writes
// it to name inside a fresh temp directory, returning the full path. Never a
// committed binary fixture (CLAUDE.md) — built in-test with archive/zip.
func writeJarFixture(t *testing.T, name, groupID, artifactID, version string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/maven/" + groupID + "/" + artifactID + "/pom.properties")
	if err != nil {
		t.Fatalf("create pom.properties: %v", err)
	}
	if _, err := w.Write([]byte("groupId=" + groupID + "\nartifactId=" + artifactID +
		"\nversion=" + version + "\n")); err != nil {
		t.Fatalf("write pom.properties: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// buildMavenDB writes one advisory covering the Maven package name, the same
// shape buildRoutingDB gives every other TargetKind — enough to prove the
// scan reached the matcher with the right identity, not just that SOME
// cataloger produced SOME component.
func buildMavenDB(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(advisory.Advisory{
		ID:   "GHSA-jar-routing",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			// D68: Maven ranges are almost entirely ECOSYSTEM-typed, and its
			// OSV-facing name is "groupId:artifactId" - exactly what
			// jar.Parse's own Name construction produces.
			Ecosystem: "Maven",
			Name:      name,
			Ranges: []advisory.Range{{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "99.0.0"}},
			}},
		}},
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Maven"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// A bare path ending .jar, content-sniffed with no prefix at all, reaches
// jar.Parse: the component it names reaches the matcher, and the D22
// disclosure names the kind on stderr — not stdout, so `--output json | jq`
// stays clean.
func TestRun_ClassifiesAndScansABareJarPath(t *testing.T) {
	const mavenName = "com.example.scancmdfixture:jar-routing-fixture"
	jarPath := writeJarFixture(t, "app.jar", "com.example.scancmdfixture", "jar-routing-fixture", "1.0.0")
	db := buildMavenDB(t, mavenName)

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, jarPath, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "as a jar") {
		t.Errorf("stderr does not say the target was classified as a jar:\n%s", errOut.String())
	}
	if strings.Contains(out.String(), "as a jar") {
		t.Errorf("the classification leaked onto stdout:\n%s", out.String())
	}
	if !strings.Contains(out.String(), mavenName) {
		t.Errorf("stdout does not name %s - jar.Parse's component did not reach "+
			"the matcher:\n%s", mavenName, out.String())
	}
}

// The explicit jar: prefix reaches the same place as the content sniff.
func TestRun_ClassifiesAndScansAnExplicitJarPrefix(t *testing.T) {
	const mavenName = "com.example.explicitprefix:jar-routing-fixture"
	// A name with neither .jar nor .war, and no META-INF/ entry the sniff
	// could catch on its own - so this row can only pass through the jar:
	// prefix, not through content sniffing.
	jarPath := writeJarFixture(t, "component.bin", "com.example.explicitprefix", "jar-routing-fixture", "2.0.0")
	db := buildMavenDB(t, mavenName)

	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, "jar:"+jarPath, Options{}, &out, &errOut); code != 0 {
		t.Fatalf("Run = %d, want 0; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "as a jar") {
		t.Errorf("stderr does not say the target was classified as a jar:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), mavenName) {
		t.Errorf("stdout does not name %s:\n%s", mavenName, out.String())
	}
}

// A zip that names neither a jar-like extension nor a META-INF/ entry is
// none of the four kinds Classify knows, and the error it reaches must name
// jar among the candidates - not just the original three - so a caller
// reading the message can tell it has that override available.
func TestRun_APlainZipTargetErrorsNamingJarAmongTheCandidateKinds(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("not a jar")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "archive.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	db := buildMavenDB(t, "unused:unused")
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), db, path, Options{}, &out, &errOut); code != 2 {
		t.Fatalf("Run = %d, want 2 - a plain zip matches none of the four kinds; "+
			"stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "jar") {
		t.Errorf("stderr does not name jar among the candidate kinds:\n%s", errOut.String())
	}
	if !strings.Contains(errOut.String(), "jar:") {
		t.Errorf("stderr does not name the jar: override prefix:\n%s", errOut.String())
	}
}

// D112's revision: a jar past the per-file limit is refused before its central
// directory is read, and the scan says so as exit 2 naming the file and the
// number — the limit's own sentence, once. Three ways in, because each reaches
// the check by a different route: jar: skips the classifier, a .jar name is
// settled by the classifier without opening the archive (so jar.Parse is what
// refuses it), and a name that says nothing is refused by the classifier's
// own content sniff before it opens the central directory to look for
// META-INF/.
//
// The limit is the fixture's own size minus one, so nothing about the fixture
// but its size is what is refused. The fixture carries a stored padding entry
// that keeps it well past the SBOM sniffs' 512-byte head: a smaller archive
// is drained by that head read alone, the SBOM sniff then reports the limit
// too, and the third row would pass with the jar sniff's size check gone.
func TestRun_AJarPastTheFileLimitExitsTwoNamingTheLimit(t *testing.T) {
	for _, tt := range []struct {
		name   string
		file   string
		prefix string
	}{
		{"an explicit jar: prefix", "component.bin", "jar:"},
		{"a bare path named .jar", "app.jar", ""},
		{"a bare path whose name says nothing", "app.bin", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := writePaddedJarFixture(t, tt.file)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() <= 2*512 {
				t.Fatalf("fixture is %d bytes, want it well past the SBOM sniffs' 512-byte head", info.Size())
			}
			lowerLimit(t, &source.MaxFileBytes, info.Size()-1)
			want := source.FileLimitError(path).Error()

			db := buildMavenDB(t, "com.example.limitfixture:limit-fixture")
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), db, tt.prefix+path, Options{}, &out, &errOut); code != 2 {
				t.Fatalf("Run = %d, want 2 - a jar past the per-file limit is a scan that "+
					"could not run; stderr:\n%s", code, errOut.String())
			}
			// The whole line, not the sentence alone: a wrapper in front of
			// it ("open <path>: ...") still contains the sentence once.
			if got := strings.Count(errOut.String(), "error: "+want); got != 1 {
				t.Errorf("stderr carries the line %q %d time(s), want exactly once:\n%s", want, got, errOut.String())
			}
			if strings.Contains(out.String(), "exceeds the") {
				t.Errorf("the limit error leaked onto stdout:\n%s", out.String())
			}
		})
	}
}

// writePaddedJarFixture is writeJarFixture's archive plus a 2 KiB entry stored
// uncompressed, for TestRun_AJarPastTheFileLimitExitsTwoNamingTheLimit — see
// its comment for why the size matters.
func writePaddedJarFixture(t *testing.T, name string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("META-INF/maven/com.example.limitfixture/limit-fixture/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("groupId=com.example.limitfixture\nartifactId=limit-fixture\nversion=1.0.0\n")); err != nil {
		t.Fatal(err)
	}
	w, err = zw.CreateHeader(&zip.FileHeader{Name: "META-INF/pad", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(bytes.Repeat([]byte{'x'}, 2<<10)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
