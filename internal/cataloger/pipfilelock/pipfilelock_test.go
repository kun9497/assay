package pipfilelock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Pipfile.lock")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// pinnedVersion is where a fabricated version would come from, and a
// fabricated version is wrong in both directions: a false positive against a
// version nobody installed, or a false negative clearing one they did. Only
// the exact "==" pin names a single resolved version, which is what a comparer
// needs to place inside an advisory range (the argument D26 makes about
// requirements.txt, applied to the one field that can carry the same defect
// here).
func TestPinnedVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"==3.2.19", "3.2.19", true},
		{"==1.0.0b1", "1.0.0b1", true},
		{"==2.0.0.post1", "2.0.0.post1", true},
		// A range expression pins nothing, however it came to be in the file.
		{"==3.2,!=3.2.1", "", false},
		{">=3.2", "", false},
		{"~=3.2.0", "", false},
		{"<4.0", "", false},
		{"!=3.2.1", "", false},
		{"*", "", false},
		// A VCS or path entry carries no version field at all, so the zero
		// value arrives here.
		{"", "", false},
		{"==", "", false},
		// Accepted. pipenv never writes the space, but a hand-edited pin with
		// one still names exactly one version — refusing it would skip a
		// package that IS pinned, which is a false negative, where accepting
		// it invents nothing. The leniency stops there: the space is trimmed,
		// and a remaining space or operator still refuses on the next check.
		{"== 3.2.19", "3.2.19", true},
		{"==3.2.19 ", "3.2.19", true},
		{"==3.2.19 || ==4.0", "", false},
	}

	for _, tc := range cases {
		got, ok := pinnedVersion(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("pinnedVersion(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// A range that reaches Parse must be counted and skipped rather than turned
// into a package. This is the caller-side half of the test above: the two fail
// at different places, and the helper being right proves nothing about whether
// Parse consults it.
func TestParse_RangeIsCountedAndSkipped(t *testing.T) {
	path := write(t, `{
  "default": {
    "pinned-fixture": {"version": "==1.2.3"},
    "ranged-fixture": {"version": ">=2.0"}
  }
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "pinned-fixture" {
		t.Fatalf("packages = %+v, want the pinned one alone", pkgs)
	}
	if stats.Components != 2 || stats.Cataloged != 1 || stats.SkippedNoVersion != 1 {
		t.Errorf("stats = %d/%d/%d, want 2 components, 1 cataloged, 1 skipped",
			stats.Components, stats.Cataloged, stats.SkippedNoVersion)
	}
}

// The same package resolved to the same version in both sections is one
// component. Emitting it twice would double it in every finding the matcher
// produces, and counting it twice against a single Cataloged would break the
// Components == Cataloged + skips invariant.
func TestParse_PresentInBothSectionsIsOneComponent(t *testing.T) {
	path := write(t, `{
  "default": {"shared-fixture": {"version": "==1.0.0"}},
  "develop": {"shared-fixture": {"version": "==1.0.0"}}
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v, want one", pkgs)
	}
	if stats.Components != 1 || stats.Cataloged != 1 {
		t.Errorf("stats = %d components, %d cataloged; want 1 and 1", stats.Components, stats.Cataloged)
	}
}

// Two versions of one name are two components, not a duplicate. pipenv can
// resolve a develop-only pin differently from the default one, and collapsing
// them would drop a package that is genuinely installed.
func TestParse_SameNameAtTwoVersionsIsTwoComponents(t *testing.T) {
	path := write(t, `{
  "default": {"split-fixture": {"version": "==1.0.0"}},
  "develop": {"split-fixture": {"version": "==2.0.0"}}
}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("packages = %+v, want two", pkgs)
	}
	if stats.Components != 2 || stats.Cataloged != 2 {
		t.Errorf("stats = %d components, %d cataloged; want 2 and 2", stats.Components, stats.Cataloged)
	}
}

// Output order must not vary between runs of the same file: a map range here
// would reach the report and make two scans of one tree differ.
func TestParse_OrderIsDeterministic(t *testing.T) {
	body := `{
  "default": {
    "zulu-fixture": {"version": "==1.0.0"},
    "alpha-fixture": {"version": "==1.0.0"},
    "mike-fixture": {"version": "==1.0.0"}
  }
}`
	path := write(t, body)

	var first []string
	for run := 0; run < 8; run++ {
		pkgs, _, err := Parse(path)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		var names []string
		for _, p := range pkgs {
			names = append(names, p.Name)
		}
		if run == 0 {
			first = names
			continue
		}
		if strings.Join(names, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d order = %v, first run = %v", run, names, first)
		}
	}
	if strings.Join(first, ",") != "alpha-fixture,mike-fixture,zulu-fixture" {
		t.Errorf("order = %v, want sorted", first)
	}
}

func TestParse_MalformedJSONNamesTheFile(t *testing.T) {
	path := write(t, `{"default": `)

	_, _, err := Parse(path)
	if err == nil {
		t.Fatal("err = nil, want a parse error")
	}
	// The full path, not "Pipfile.lock": the format string already contains
	// that word, so asserting it would pass from a wrapper that dropped both
	// the real path and the cause.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want it to name %s", err, path)
	}
}

func TestParse_MissingFile(t *testing.T) {
	_, _, err := Parse(filepath.Join(t.TempDir(), "absent.lock"))
	if err == nil {
		t.Fatal("err = nil, want a read error")
	}
}

func TestParse_EmptySectionsAreNotAnError(t *testing.T) {
	path := write(t, `{"_meta": {"hash": {"sha256": "abc"}}, "default": {}, "develop": {}}`)

	pkgs, stats, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 || stats.Components != 0 {
		t.Errorf("pkgs = %+v, stats = %+v; want nothing", pkgs, stats)
	}
}
