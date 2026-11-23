package dirscan

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// QA 2026-11-20. A directory walk knew a Java archive by two extensions and a
// requirements file by one exact name, and said nothing about the manifests
// it has no reader for. A tree holding app.ear, requirements-prod.txt and a
// pom.xml beside one recognized lockfile was reported as a clean, complete
// scan of that lockfile.

// earWith returns an enterprise archive holding one nested jar.
func earWith(t *testing.T, nested string, jar []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(nested)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(jar); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Create("META-INF/application.xml"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Through Parse, the caller: the archive inside a directory is read, by
// every name a Java archive goes by, and what it nests is reached.
func TestParse_JavaArchivesAreReadWhateverTheirExtension(t *testing.T) {
	jar := buildJar(t, "org.apache.logging.log4j", "log4j-core", "2.14.1")
	for _, name := range []string{"app.ear", "plugin.hpi", "plugin.jpi", "svc.sar", "unit.par", "flow.nar", "feature.kar", "bundle.lpkg", "APP.EAR"} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"dist/" + name: string(jar)})
			version, location := findPackage(t, root, "org.apache.logging.log4j:log4j-core")
			if version != "2.14.1" || location != "dist/"+name {
				t.Errorf("log4j-core = %s at %s, want 2.14.1 at dist/%s", version, location, name)
			}
		})
	}
	t.Run("an ear's nested jar", func(t *testing.T) {
		root := writeTree(t, map[string]string{"app.ear": string(earWith(t, "lib/log4j-core-2.14.1.jar", jar))})
		version, location := findPackage(t, root, "org.apache.logging.log4j:log4j-core")
		if version != "2.14.1" || !strings.HasPrefix(location, "app.ear") || !strings.Contains(location, "log4j-core-2.14.1.jar") {
			t.Errorf("log4j-core = %s at %s, want 2.14.1 inside app.ear", version, location)
		}
	})
	// Not every ZIP-shaped name: a .rar is usually not a ZIP at all, and a
	// plain .zip is not a Java archive by name.
	for _, name := range []string{"adapter.rar", "release.zip"} {
		root := writeTree(t, map[string]string{"go.mod": "module example.test/m\n\ngo 1.22\n", "dist/" + name: string(jar)})
		target, _, _, err := Parse(root)
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		for _, p := range target.Packages {
			if strings.Contains(p.Name, "log4j") {
				t.Errorf("%s was read as a Java archive", name)
			}
		}
	}
}

func TestParse_RequirementsVariantsAreReadLikeRequirementsTxt(t *testing.T) {
	for _, name := range []string{"requirements-prod.txt", "requirements_test.txt", "requirements.dev.txt"} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, map[string]string{"svc/" + name: "variant-fixture==1.2.3\n"})
			version, location := findPackage(t, root, "variant-fixture")
			if version != "1.2.3" || location != "svc/"+name {
				t.Errorf("variant-fixture = %s at %s, want 1.2.3 at svc/%s", version, location, name)
			}
		})
	}
	// The prefix alone is not the format.
	for _, name := range []string{"requirementsdev.txt", "my-requirements-dev.txt", "requirements-dev.in", "requirements-.md"} {
		ms, _, err := Walk(writeTree(t, map[string]string{"go.mod": "module example.test/m\n", name: "variant-fixture==1.2.3\n"}))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			if m.Kind == KindRequirements {
				t.Errorf("%s was recognized as a requirements file", name)
			}
		}
	}
}

// notes are the entries the walk recorded without having failed to read
// anything, by path.
func notes(t *testing.T, files map[string]string) map[string]string {
	t.Helper()
	_, unread, err := Walk(writeTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, u := range unread {
		if u.Failed {
			t.Errorf("%s was recorded as a failed read (%s); nothing was read and found unreadable", u.Path, u.Reason)
		}
		out[u.Path] = u.Reason
	}
	return out
}

func TestWalk_NamesTheManifestsItDoesNotRead(t *testing.T) {
	got := notes(t, map[string]string{
		"go.mod":                       "module example.test/m\n",
		"java/pom.xml":                 "<project/>",
		"java/gradle.lockfile":         "# lock\n",
		"web/package.json":             "{}",
		"locked/package.json":          "{}",
		"locked/yarn.lock":             "",
		"mono/package-lock.json":       "{}",
		"mono/package.json":            "{}",
		"mono/packages/a/package.json": "{}",
		"node_modules/x/package.json":  "{}",
	})
	for path, wantIn := range map[string]string{
		"java/pom.xml":         "a Maven project file",
		"java/gradle.lockfile": "a Gradle lockfile",
		"web/package.json":     "no lockfile beside or above it",
	} {
		if !strings.Contains(got[path], wantIn) {
			t.Errorf("%s noted as %q, want a reason containing %q", path, got[path], wantIn)
		}
	}
	// Resolved by a lockfile beside it, or by its workspace root's; and a
	// dependency's own package.json is inside a pruned directory.
	for _, path := range []string{"locked/package.json", "mono/package.json", "mono/packages/a/package.json", "node_modules/x/package.json"} {
		if r, ok := got[path]; ok {
			t.Errorf("%s was noted (%s), want nothing said about it", path, r)
		}
	}
	if len(got) != 3 {
		t.Errorf("notes = %v, want exactly the three above", got)
	}
}

// The notes reach the caller beside the inventory, and do not make the scan
// incomplete: Parse returns them with Failed false.
func TestParse_NotesRideBesideTheInventory(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":  "module example.test/m\n\ngo 1.22\n",
		"pom.xml": "<project/>",
	})
	_, _, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(found.Unread) != 1 || found.Unread[0].Path != "pom.xml" || found.Unread[0].Failed {
		t.Errorf("Unread = %+v, want pom.xml alone, not failed", found.Unread)
	}
}
