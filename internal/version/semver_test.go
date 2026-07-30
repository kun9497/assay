package version

import (
	"errors"
	"testing"
)

var semverTests = []struct {
	a, b string
	want int
}{
	// Version core compares numerically, field by field (§11.2)
	{"1.0.0", "1.0.0", 0},
	{"1.0.0", "2.0.0", -1},
	{"2.0.0", "2.1.0", -1},
	{"2.1.0", "2.1.1", -1},
	{"2.1.1", "2.1.0", 1},
	{"1.0.0", "0.9.9", 1},
	{"0.0.1", "0.1.0", -1},
	{"0.1.0", "1.0.0", -1},
	{"1.9.0", "1.10.0", -1}, // numeric, not lexical
	{"1.0.9", "1.0.10", -1},
	{"2.0.0", "10.0.0", -1},
	{"1.0.0", "18446744073709551616.0.0", -1}, // 2^64: must not overflow
	{"99999999999999999999.1.0", "99999999999999999999.2.0", -1},

	// Pre-release versus normal at equal core (§11.3)
	{"1.0.0-alpha", "1.0.0", -1},
	{"1.0.0", "1.0.0-alpha", 1},
	{"1.0.0-rc.1", "1.0.0", -1},
	{"1.0.0-alpha", "1.0.0-alpha", 0},
	{"1.0.0", "1.0.1-alpha", -1},
	{"1.0.0-alpha", "0.9.9", 1},
	{"2.0.0-alpha", "1.9.9", 1},
	{"0.0.0-experimental-abc", "0.0.0", -1}, // real npm shape

	// The spec's own example chain (§11.4)
	{"1.0.0-alpha", "1.0.0-alpha.1", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
	{"1.0.0-alpha.beta", "1.0.0-beta", -1},
	{"1.0.0-beta", "1.0.0-beta.2", -1},
	{"1.0.0-beta.2", "1.0.0-beta.11", -1},
	{"1.0.0-beta.11", "1.0.0-rc.1", -1},
	{"1.0.0-rc.1", "1.0.0", -1},
	{"1.0.0-alpha", "1.0.0-rc.1", -1},

	// Numeric identifiers, numeric versus non-numeric (§11.4.1, §11.4.3)
	{"1.0.0-1", "1.0.0-2", -1},
	{"1.0.0-2", "1.0.0-10", -1},
	{"1.0.0-0", "1.0.0-1", -1},
	{"1.0.0-0", "1.0.0-0", 0},
	{"1.0.0-alpha.2", "1.0.0-alpha.10", -1},
	{"1.0.0-1", "1.0.0-alpha", -1},
	{"1.0.0-999999", "1.0.0-a", -1}, // magnitude never beats "non-numeric is higher"
	{"1.0.0-alpha.1", "1.0.0-alpha.a", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.0valid", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.01a", -1},
	{"1.0.0-18446744073709551616", "1.0.0-18446744073709551617", -1},

	// ASCII lexical order for non-numeric identifiers (§11.4.2)
	{"1.0.0-alpha", "1.0.0-beta", -1},
	{"1.0.0-alpha", "1.0.0-rc", -1},
	{"1.0.0-Alpha", "1.0.0-alpha", -1},    // case is significant
	{"1.0.0-RC.1", "1.0.0-alpha", -1},     // uppercase sorts below lowercase
	{"1.0.0-alpha10", "1.0.0-alpha9", -1}, // one identifier: string compare
	{"1.0.0-rc2", "1.0.0-rc10", 1},
	{"1.0.0-a", "1.0.0-a-", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha-1", -1}, // b is a single field "alpha-1"
	{"1.0.0-x-y-z.--", "1.0.0-x-y-z.-a", -1},
	{"1.0.0-0", "1.0.0--", -1}, // §11.4.3 overrides ASCII order

	// Running out of fields (§11.4.4)
	{"1.0.0-alpha", "1.0.0-alpha.0", -1},
	{"1.0.0-1", "1.0.0-1.0", -1},
	{"1.0.0-alpha.1", "1.0.0-alpha.1.0", -1},
	{"1.0.0-alpha.beta", "1.0.0-alpha", 1},
	{"1.0.0-a.b.c", "1.0.0-a.b", 1},
	{"1.0.0-b", "1.0.0-a.b.c.d", 1},
	{"0.0.0-0", "0.0.0-0.0", -1},
	{"0.0.0-0", "0.0.0", -1}, // global minimum valid semver

	// Build metadata is ignored for precedence (§10, §11.1)
	{"1.0.0", "1.0.0+build.1", 0},
	{"1.0.0+build.1", "1.0.0+build.2", 0},
	{"1.0.0+build.2", "1.0.0+build.1", 0},
	{"1.0.0+001", "1.0.0+999", 0},
	{"1.0.0-alpha+001", "1.0.0-alpha", 0},
	{"1.0.0-alpha+001", "1.0.0+001", -1},
	{"1.0.0+20130313144700", "1.0.0-beta+exp.sha.5114f85", 1},
	{"1.0.0+21AF26D3----117B344092BD", "1.0.0", 0},
	{"1.0.0+build", "1.0.0-alpha+build", 1},

	// Go module versions: leading v, +incompatible, pseudo-versions
	{"v1.0.0", "1.0.0", 0},
	{"v1.0.0", "v1.0.1", -1},
	{"1.0.0", "v1.0.1", -1}, // bare OSV bound versus v-prefixed artifact
	{"v1.0.0-alpha", "1.0.0", -1},
	{"v2.0.0+incompatible", "v2.0.0", 0},
	{"v2.0.0+incompatible", "2.0.0", 0},
	{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.0-20200114041708-b6a2b0a5b8b5", -1},
	{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.1", -1},
	{"v1.2.3-0.20191109021931-daa7c04131f5", "v1.2.3", -1},
	{"v1.2.2", "v1.2.3-0.20191109021931-daa7c04131f5", -1},
	{"v1.2.3-0.20191109021931-daa7c04131f5", "v1.2.3-alpha", -1},
}

func TestSemVerCompare(t *testing.T) {
	var c SemVer
	for _, tc := range semverTests {
		got, err := c.Compare(tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		// Antisymmetry is cheap to assert and catches whole classes of bug
		// that individual rows miss.
		rev, err := c.Compare(tc.b, tc.a)
		if err != nil {
			t.Errorf("Compare(%q, %q) error: %v", tc.b, tc.a, err)
			continue
		}
		if rev != -tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d (antisymmetry)", tc.b, tc.a, rev, -tc.want)
		}
	}
}

func TestSemVerInvalid(t *testing.T) {
	invalid := []string{
		"", "1", "1.0", "1.0.0.0", "v1.0.0.0",
		"01.0.0", "1.01.0", "1.0.01", "-1.0.0",
		"1.0.0-01", "1.0.0-alpha.00", "1.0.0-", "1.0.0-alpha..1",
		"1.0.0-.alpha", "1.0.0-alpha.", "1.0.0-alpha_beta", "1.0.0-α",
		"1.0.0-beta*", "1.0.0-a b", "1.0.0+", "1.0.0+build..1",
		"1.0.0+build_1", "1.0.0+build+more", "1.0.0-+build",
		" 1.0.0", "1.0.0 ", "1.2.x", "^1.2.3", "~1.2.3", ">=1.2.3", "*",
		"latest", "V1.0.0", "vv1.0.0",
		// The OSV sentinel is not a version. The range layer resolves it to
		// negative infinity before Compare is called; coercing it to 0.0.0
		// here would silently exclude every 0.0.0-prerelease build.
		"0",
	}
	for _, in := range invalid {
		if _, err := (SemVer{}).Compare(in, "1.0.0"); !errors.Is(err, ErrInvalid) {
			t.Errorf("Compare(%q, …) err = %v, want ErrInvalid", in, err)
		}
	}
}

func TestSemVerValidButUnusual(t *testing.T) {
	valid := []string{
		"1.0.0-0.3.7", "1.0.0-x.7.z.92", "1.0.0-x-y-z.--",
		"1.0.0-alpha+001", "1.0.0+21AF26D3----117B344092BD",
		"1.0.0-beta+exp.sha.5114f85", "1.0.0--", "1.0.0---",
		"1.0.0-0", "1.0.0+001", "1.0.0-01a", "1.0.0-0valid",
		"0.0.0", "0.0.0-0", "99999999999999999999.0.0",
		"v2.0.0+incompatible", "v0.0.0-20191109021931-daa7c04131f5",
	}
	for _, in := range valid {
		if _, err := (SemVer{}).Compare(in, "1.0.0"); err != nil {
			t.Errorf("Compare(%q, …) err = %v, want nil", in, err)
		}
	}
}

func TestForEcosystem(t *testing.T) {
	for _, eco := range []string{"Go", "npm"} {
		c, ok := For(eco)
		if !ok {
			t.Fatalf("For(%q) not registered", eco)
		}
		if _, ok := c.(SemVer); !ok {
			t.Errorf("For(%q) = %T, want SemVer", eco, c)
		}
	}
	if _, ok := For("Nonesuch"); ok {
		t.Error("For(Nonesuch) = ok, want not ok")
	}
}

// TestRegistryHasNoDistroComparer is a tripwire, not a behaviour test.
//
// Registering a distro comparer makes the matcher believe it can evaluate
// distro packages, but distro advisories are keyed on source packages (D8) and
// nothing in production populates Package.Source or the by-source index yet.
// The comparer alone turns a safe, counted skip into a silent under-report, so
// this fails the build until the rest of the D8 path lands with it.
func TestRegistryHasNoDistroComparer(t *testing.T) {
	want := map[string]bool{"Go": true, "npm": true, "PyPI": true}
	for eco := range registry {
		if !want[eco] {
			t.Errorf("comparer registered for %q: see the D8 note in internal/matcher — "+
				"LookupBySource, a Source-populating cataloger, and PutSourceIndex must land too",
				eco)
		}
	}
	if len(registry) != len(want) {
		t.Errorf("registry has %d entries, want %d", len(registry), len(want))
	}
}
