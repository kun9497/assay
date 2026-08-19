package dirscan

// Written before jar.Parse's own tests are consulted here, and driving
// Parse rather than the cataloger: delete the KindJarArchive arm and every
// test below must go red, because the manifest falls through to default and
// becomes an Unread. See internal/cataloger/dirscan/composer_test.go for the
// same discipline applied to composer.lock.

import (
	"archive/zip"
	"bytes"
	"path/filepath"
	"testing"
)

// buildJar returns the raw bytes of a minimal jar archive naming one Maven
// component. Never a committed binary fixture (CLAUDE.md) — built in-test
// with archive/zip.
func buildJar(t *testing.T, groupID, artifactID, version string) []byte {
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
	return buf.Bytes()
}

func TestParse_JarArchiveReachesTheDispatch(t *testing.T) {
	root := writeTree(t, map[string]string{
		"lib/example-fixture.jar": string(buildJar(t,
			"com.example.dirscanfixture", "example-fixture", "1.4.2")),
	})

	version, location := findPackage(t, root, "com.example.dirscanfixture:example-fixture")
	if version != "1.4.2" {
		t.Errorf("example-fixture version = %q, want 1.4.2", version)
	}
	wantLoc := filepath.ToSlash(filepath.Join("lib", "example-fixture.jar"))
	if location != wantLoc {
		t.Errorf("location = %q, want %q", location, wantLoc)
	}
}

// A .war is the same archive format under a different extension - one Kind
// covers both (walk.go's own doc comment on KindJarArchive), so it must
// reach the same dispatch arm.
func TestParse_WarArchiveReachesTheSameDispatch(t *testing.T) {
	root := writeTree(t, map[string]string{
		"webapp.war": string(buildJar(t,
			"com.example.warfixture", "webapp", "2.0.0")),
	})

	version, location := findPackage(t, root, "com.example.warfixture:webapp")
	if version != "2.0.0" {
		t.Errorf("webapp version = %q, want 2.0.0", version)
	}
	if location != "webapp.war" {
		t.Errorf("location = %q, want webapp.war", location)
	}
}

// The Components == Cataloged + skips invariant must survive a jar-carrying
// tree the same way it survives every other manifest kind.
func TestParse_JarArchiveStatsInvariantHolds(t *testing.T) {
	root := writeTree(t, map[string]string{
		"lib/example-fixture.jar": string(buildJar(t,
			"com.example.invariantfixture", "example-fixture", "1.0.0")),
	})

	_, stats, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, u := range found.Unread {
		t.Errorf("unexpected unread manifest %s: %s", u.Path, u.Reason)
	}
	if stats.Components != stats.Cataloged+stats.SkippedNoPURL+
		stats.SkippedNoVersion+stats.SkippedUnsupportedEcosystem {
		t.Errorf("the invariant does not survive a jar-carrying tree: %+v", stats)
	}
	if stats.Cataloged != 1 {
		t.Errorf("Cataloged = %d, want 1", stats.Cataloged)
	}
}

// A corrupt or truncated .jar must fail the scan (Unread.Failed -> AnyFailed
// -> scancmd's exit 2), not print "not read: ..." and exit 0 -- the exact
// regression Unread.Failed's own doc comment says it exists to prevent.
// Every other jar test in this file uses a VALID archive and asserts Unread
// is empty, so nothing before this one ever drove the KindJarArchive error
// arm in dirscan.go at all: setting Failed:false there (the mutation this
// test exists to catch) leaves every one of them green.
func TestParse_CorruptJarFailsTheScan(t *testing.T) {
	root := writeTree(t, map[string]string{
		"lib/broken.jar": "this is not a zip file, just garbage bytes",
	})

	target, _, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 0 {
		t.Errorf("packages = %+v, want none from an unreadable jar", target.Packages)
	}
	if len(found.Unread) != 1 {
		t.Fatalf("Unread = %+v, want exactly one entry", found.Unread)
	}
	u := found.Unread[0]
	if u.Path != "lib/broken.jar" {
		t.Errorf("Unread path = %q, want lib/broken.jar", u.Path)
	}
	if !u.Failed {
		t.Error("Failed = false; a corrupt jar means this scan saw none of its " +
			"dependencies, which must reach exit 2 (AnyFailed -> scancmd)")
	}
	if !found.AnyFailed() {
		t.Error("AnyFailed() = false, want true")
	}
}

// The same Failed:true contract, on the two other manifest kinds cheapest to
// break: composer.lock and packages.lock.json both decode as JSON and error
// loudly on truncated input (Gemfile.lock's line scanner does not -- a
// truncated one just yields fewer packages rather than an error, so it is
// not a comparable fixture). Each of these catalogers' own dirscan tests
// (composer_test.go, nuget_test.go) drive a VALID manifest through the same
// dispatch and never see the error arm either, so Failed:false on any one of
// them would leave those files green too.
func TestParse_UnreadableManifestFailsTheScan(t *testing.T) {
	for _, tc := range []struct {
		name string
		file string
		body string
	}{
		{"jar", "lib/broken2.jar", "still not a zip file"},
		{"composer.lock", "composer.lock", `{"packages": [{"name": "vendor/pkg"`},
		{"packages.lock.json", "packages.lock.json", `{"dependencies": {"net6.0": {"Some.Pkg`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{tc.file: tc.body})

			target, _, found, err := Parse(root)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(target.Packages) != 0 {
				t.Errorf("packages = %+v, want none from an unreadable manifest", target.Packages)
			}
			if len(found.Unread) != 1 {
				t.Fatalf("Unread = %+v, want exactly one entry", found.Unread)
			}
			if !found.Unread[0].Failed {
				t.Error("Failed = false; an unreadable manifest means this scan saw none " +
					"of its dependencies, which must reach exit 2 (AnyFailed -> scancmd)")
			}
			if !found.AnyFailed() {
				t.Error("AnyFailed() = false, want true")
			}
		})
	}
}

// A nested archive's composite Location ("outer!inner") must survive
// relocation to the manifest's repo-relative path with the "!inner" suffix
// intact — relocate()'s own doc comment warns that a plain overwrite would
// flatten this away, which is exactly why KindJarArchive uses relocateJar
// instead. This is the test that would fail if that distinction were lost.
func TestParse_NestedJarLocationKeepsItsCompositeSuffixAfterRelocation(t *testing.T) {
	inner := buildJar(t, "org.fixture.dirscaninner", "inner-lib", "3.3.3")
	var outerBuf bytes.Buffer
	zw := zip.NewWriter(&outerBuf)
	w, err := zw.Create("BOOT-INF/lib/inner-lib-3.3.3.jar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	root := writeTree(t, map[string]string{
		"services/app.jar": outerBuf.String(),
	})

	_, _, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, u := range found.Unread {
		t.Errorf("unexpected unread manifest %s: %s", u.Path, u.Reason)
	}
	version, location := findPackage(t, root, "org.fixture.dirscaninner:inner-lib")
	if version != "3.3.3" {
		t.Errorf("inner-lib version = %q, want 3.3.3", version)
	}
	wantLoc := filepath.ToSlash(filepath.Join("services", "app.jar")) + "!BOOT-INF/lib/inner-lib-3.3.3.jar"
	if location != wantLoc {
		t.Errorf("location = %q, want %q - the repo-relative outer path with the "+
			"nested entry's path still appended", location, wantLoc)
	}
}
