package dirscan

// Written before nugetlock exists, and driving Parse rather than the parser:
// delete the KindNuGetLock arm and every test below must go red, because the
// manifest falls through to default and becomes an Unread.

import "testing"

const nugetLock = `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json.Fixture": {
        "type": "Direct",
        "resolved": "13.0.1"
      },
      "ProjectRef.Fixture": {
        "type": "Project"
      }
    },
    "net7.0": {
      "Newtonsoft.Json.Fixture": {
        "type": "Direct",
        "resolved": "13.0.1"
      },
      "ProjectRef.Fixture": {
        "type": "Project"
      }
    }
  }
}
`

func TestParse_NuGetLockReachesTheDispatch(t *testing.T) {
	root := writeTree(t, map[string]string{"packages.lock.json": nugetLock})

	version, location := findPackage(t, root, "Newtonsoft.Json.Fixture")
	if version != "13.0.1" {
		t.Errorf("Newtonsoft.Json.Fixture version = %q, want 13.0.1", version)
	}
	if location != "packages.lock.json" {
		t.Errorf("location = %q, want packages.lock.json", location)
	}
}

// The same package, resolved to the same version under two frameworks, is
// one component - not two. Walking only the first framework would still find
// it once, so this asserts the stats rather than just presence.
func TestParse_NuGetLockCrossFrameworkDedupIsOneComponent(t *testing.T) {
	root := writeTree(t, map[string]string{"packages.lock.json": nugetLock})

	target, stats, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, u := range found.Unread {
		t.Errorf("unexpected unread manifest %s: %s", u.Path, u.Reason)
	}
	var count int
	for _, p := range target.Packages {
		if p.Name == "Newtonsoft.Json.Fixture" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Newtonsoft.Json.Fixture appears %d times, want 1 (net6.0 and "+
			"net7.0 resolved it to the same version)", count)
	}
	// One real package (deduped across both frameworks) cataloged, one
	// Project reference (deduped across both frameworks) counted and
	// skipped: 2 components, 1 cataloged, 1 skipped.
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 2 components, 1 cataloged, 1 skipped", stats)
	}
}

// A "type": "Project" entry is a reference to another project in the same
// solution, not a package with a released version. Counted, not dropped.
func TestParse_NuGetLockProjectReferenceIsCountedAndSkipped(t *testing.T) {
	root := writeTree(t, map[string]string{"packages.lock.json": nugetLock})

	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, p := range target.Packages {
		if p.Name == "ProjectRef.Fixture" {
			t.Errorf("ProjectRef.Fixture was cataloged as %+v; a Project reference "+
				"has no resolved version", p)
		}
	}
}

// Name is kept exactly as NuGet wrote it: NormalizeName lowercases at match
// time, and doing it here too would be a second, competing definition.
func TestParse_NuGetLockEcosystemAndPURL(t *testing.T) {
	root := writeTree(t, map[string]string{"packages.lock.json": nugetLock})

	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var checked bool
	for _, p := range target.Packages {
		if p.Name != "Newtonsoft.Json.Fixture" {
			continue
		}
		checked = true
		if p.Type != "nuget" {
			t.Errorf("Type = %q, want nuget", p.Type)
		}
		if p.Ecosystem != "NuGet" {
			t.Errorf("Ecosystem = %q, want NuGet", p.Ecosystem)
		}
		if p.PURL != "pkg:nuget/Newtonsoft.Json.Fixture@13.0.1" {
			t.Errorf("PURL = %q, want pkg:nuget/Newtonsoft.Json.Fixture@13.0.1", p.PURL)
		}
	}
	if !checked {
		t.Fatal("Newtonsoft.Json.Fixture was not found among the cataloged packages")
	}
}
