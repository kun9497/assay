package nugetlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "packages.lock.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestParse_MalformedJSONNamesTheFile(t *testing.T) {
	path := write(t, `{"dependencies": `)

	_, _, err := Parse(path)
	if err == nil {
		t.Fatal("err = nil, want a parse error")
	}
	// The full path, not "packages.lock.json": the format string already
	// contains that word, so asserting it would pass from a wrapper that
	// dropped both the real path and the cause.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want it to name %s", err, path)
	}
}

func TestParse_MissingFile(t *testing.T) {
	_, _, err := Parse(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("err = nil, want a read error")
	}
}

func TestParse_EmptyDependenciesIsNotAnError(t *testing.T) {
	path := write(t, `{"version": 1, "dependencies": {}}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 || stats.Components != 0 {
		t.Errorf("pkgs = %+v, stats = %+v; want nothing", pkgs, stats)
	}
}

// The same package resolved to the same version under two frameworks is one
// component, not two - dedup on (name, resolved) across every framework.
func TestParse_CrossFrameworkDedupSameVersionIsOneComponent(t *testing.T) {
	path := write(t, `{
  "dependencies": {
    "net6.0": {"dedup-fixture": {"type": "Direct", "resolved": "1.0.0"}},
    "net7.0": {"dedup-fixture": {"type": "Direct", "resolved": "1.0.0"}}
  }
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v, want one", pkgs)
	}
	if stats.Components != 1 || stats.Cataloged != 1 {
		t.Errorf("stats = %+v, want 1 component, 1 cataloged", stats)
	}
}

// A multi-target project can resolve the SAME package to a DIFFERENT
// version per framework. Dedup must key on (name, resolved) together, not
// name alone, or one of the two genuinely-installed versions would vanish.
func TestParse_SameNameDifferentVersionAcrossFrameworksIsTwoComponents(t *testing.T) {
	path := write(t, `{
  "dependencies": {
    "net6.0": {"split-fixture": {"type": "Direct", "resolved": "1.0.0"}},
    "net7.0": {"split-fixture": {"type": "Direct", "resolved": "2.0.0"}}
  }
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("packages = %+v, want two", pkgs)
	}
	if stats.Components != 2 || stats.Cataloged != 2 {
		t.Errorf("stats = %+v, want 2 components, 2 cataloged", stats)
	}
}

// A "type": "Project" entry naming the same project reference under two
// frameworks is counted once, not once per framework: "counted once and
// skipped" is the design brief's own wording, and multi-target projects are
// exactly where the same project reference reappears under every framework.
func TestParse_ProjectReferenceDedupedAcrossFrameworks(t *testing.T) {
	path := write(t, `{
  "dependencies": {
    "net6.0": {"ProjectRef-fixture": {"type": "Project"}},
    "net7.0": {"ProjectRef-fixture": {"type": "Project"}}
  }
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("packages = %+v, want none - a Project reference is not a package", pkgs)
	}
	if stats.Components != 1 || stats.Cataloged != 0 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %+v, want 1 component, 0 cataloged, 1 skipped - "+
			"counted once despite appearing under two frameworks", stats)
	}
}

// Name is kept exactly as NuGet wrote it - lowercasing happens once, at
// match time (pkgmeta.NormalizeName), not duplicated here.
func TestParse_NameCaseIsKeptVerbatim(t *testing.T) {
	path := write(t, `{
  "dependencies": {
    "net6.0": {"MixedCase.Fixture": {"type": "Direct", "resolved": "1.2.3"}}
  }
}`)

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "MixedCase.Fixture" {
		t.Fatalf("packages = %+v, want MixedCase.Fixture with its case intact", pkgs)
	}
}

func TestParse_EcosystemAndPURL(t *testing.T) {
	path := write(t, `{
  "dependencies": {
    "net6.0": {"eco-fixture": {"type": "Direct", "resolved": "3.2.1"}}
  }
}`)

	pkgs, _, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v, want one", pkgs)
	}
	p := pkgs[0]
	if p.Type != "nuget" {
		t.Errorf("Type = %q, want nuget", p.Type)
	}
	if p.Ecosystem != "NuGet" {
		t.Errorf("Ecosystem = %q, want NuGet", p.Ecosystem)
	}
	if p.PURL != "pkg:nuget/eco-fixture@3.2.1" {
		t.Errorf("PURL = %q, want pkg:nuget/eco-fixture@3.2.1", p.PURL)
	}
}
