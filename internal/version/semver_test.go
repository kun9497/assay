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

	// D32: a bare short core is padded with zeros, exactly as
	// golang.org/x/mod/semver documents. These are real advisory bounds.
	{"4.0", "4.0.0", 0},   // lxd
	{"13.0", "13.0.0", 0}, // npm next
	{"136", "136.0.0", 0}, // esm.sh, a bare major
	{"0.46", "0.46.0", 0}, // cosmos-sdk
	{"4.0", "4.1.0", -1},
	{"4.0", "3.9.9", 1},
	{"0.46", "0.46.1", -1},
	{"136", "1360.0.0", -1}, // padded, then numeric: not a string compare
	// The padded form is a real release, so it outranks its own pre-releases.
	// Reading "0.46" as anything below them is the mistake the OSV sentinel
	// comment warns about, and this row is what separates the two.
	{"0.46", "0.46.0-rc3", 1},
	{"4.0", "4.0.0-alpha", 1},

	// D34: a leading zero in the core is normalized away rather than refused.
	{"19.03.0", "19.3.0", 0},   // the same release, written two ways
	{"19.03.0", "19.03.9", -1}, // docker's own patch line
	{"19.03.9", "19.10.0", -1}, // 3 < 10: the ordering a string sort gets right
	{"01.0.0", "1.0.0", 0},
	{"1.0.01", "1.0.1", 0},
	{"1.00.0", "1.0.0", 0}, // all-zero identifier keeps one digit, not none
	// The pair that makes normalization load-bearing rather than cosmetic.
	// compareNumeric orders digit strings by LENGTH first, so accepting "072"
	// without trimming it puts it above "72" — the same release sorting above
	// itself. Length differs here and the values are equal, which is the only
	// shape that can tell acceptance apart from acceptance-plus-normalization.
	{"4.072.0", "4.72.0", 0},
	{"1.0.007", "1.0.7", 0},
	// ...and normalization must not flatten genuinely different versions.
	{"1.0.007", "1.0.8", -1},
	{"4.072.0", "4.73.0", -1},

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
		"", "1.0.0.0", "v1.0.0.0",
		// D34 accepts a leading zero in a three-identifier core and normalizes
		// it away. It does NOT extend to the D32 shorthand: node-semver's loose
		// parser needs three identifiers and throws on these, and x/mod's
		// shorthand needs no leading zero, so nothing sanctions the pair.
		"4.072", "01.0", "1.0e5", "v4.072",
		// Pre-release identifiers keep the spec's own rule (§9); D34 changed the
		// core only, and no data asks for more.
		"1.0.0-01", "1.0.0-alpha.00",
		// D32 pads a bare short core; it does NOT pad a suffixed one. x/mod's
		// IsValid is false for both of these and node-semver refuses them in
		// strict and loose alike, so padding them would be an invention neither
		// reference makes. Four identifiers stay an error above for the opposite
		// reason: coercing 1.0.0.0 to 1.0.0 discards a component rather than
		// supplying a missing one.
		"1.0-rc.1", "1-rc.1", "1.0+meta", "1+meta", "1.0-", "1.0+",
		"-1.0.0",
		"1.0.0-", "1.0.0-alpha..1",
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
		// D32: bare short cores, real advisory bounds. github.com/canonical/lxd
		// is published at "4.0"/"6.0"/"6.5", npm's next at "13.0",
		// github.com/cosmos/cosmos-sdk at "0.46", github.com/esm-dev/esm.sh at
		// a bare "136".
		"4.0", "13.0", "0.46", "136", "v4.0", "v136",
		// D34: real GHSA range bounds. Docker tags 19.03.x, which Go's own
		// version rules cannot express — part of why it is carried as
		// +incompatible — so the string reaches us through the advisory, not
		// through a module version.
		"19.03.0", "19.03.9", "01.0.0", "1.01.0", "1.0.01", "v19.03.9",
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
// distro packages, but distro advisories are keyed on SOURCE packages (D8).
// The comparer alone turns a safe, counted skip into a silent under-report, so
// a comparer may only be reachable once a cataloger populates Package.Source
// and the matcher looks the source name up.
//
// Alpine completed that path in slice 2a and is the one permitted exception.
// This guards the next distro: dpkg and rpm need their own Source population,
// and registering their comparer first would reintroduce exactly the miss this
// test was written for. It checks For() rather than the registry map, because
// distro keys carry a release (D6) and resolve by prefix rather than by entry —
// guarding the map alone let Alpine through unnoticed.
func TestNoUnbackedDistroComparer(t *testing.T) {
	// Debian left this list when dpkgdb landed, which is the whole point of the
	// guard: the comparer, the cataloger that populates Package.Source, and the
	// image wiring that calls it had to arrive together, and moving this line
	// is the deliberate act that says they did.
	// Red Hat left this list when the CSAF VEX provider landed (D47-D49), for
	// the same reason Debian did: the comparer, the provider that populates
	// the ecosystem, and the wiring that keys the packages arrived together.
	// Ubuntu left this list under D53. It needed no new cataloger: the dpkg
	// one already populates Package.Source from the same Source: field, and
	// the matcher's source lookup is ecosystem-agnostic — so unlike Debian and
	// Red Hat, what had to arrive with the comparer was the KEY, not the
	// plumbing. The lineage keys stay unresolved on purpose and are covered
	// by TestFor_UbuntuLineageKeysDoNotResolve below.
	//
	// Rocky Linux left this list under D71, for the same reason Ubuntu did:
	// the rpmdb cataloger and Package.Source population already exist (D44,
	// shipped for Red Hat), so what had to arrive with the comparer was the
	// release-qualified KEY, not new plumbing. AlmaLinux left it under D72
	// for the identical reason — its own OSV provider is what arrived, not
	// new rpmdb or Package.Source plumbing. Amazon Linux left it under D73,
	// for the identical reason again — its own ALAS provider
	// (internal/provider/amazon) is what arrived, and D8 source indirection
	// is not even needed for it (updateinfo enumerates binary package names
	// directly, so no by-source lookup is on the critical path at all).
	// Oracle Linux left it under D74, for the identical reason again — its
	// own OVAL provider (internal/provider/oracle) is what arrived, and D8
	// source indirection is not needed for it either: the feed names every
	// package by its binary name, so LookupBySource sits idle here too.
	// Fedora left it under D75, for the identical reason again — its own
	// Bodhi provider (internal/provider/fedora) is what arrived. Unlike
	// Amazon Linux and Oracle Linux above, D8 source indirection is back on
	// the critical path here: Bodhi's builds[] name only the SOURCE package
	// Koji built, never the binary subpackages a real install carries, so
	// LookupBySource is what makes a Fedora finding reachable at all.
	for _, eco := range []string{
		"Alpine",       // unversioned: not a key we ever build (D6)
		"Debian",       // likewise
		"Red Hat",      // likewise -- the provider writes "Red Hat:9"
		"Rocky Linux",  // likewise -- the provider writes "Rocky Linux:9"
		"AlmaLinux",    // likewise -- the provider writes "AlmaLinux:9"
		"Amazon Linux", // likewise -- the provider writes "Amazon Linux:2"
		"Oracle Linux", // likewise -- the provider writes "Oracle Linux:9"
		"Fedora",       // likewise -- the provider writes "Fedora:44"
	} {
		if _, ok := For(eco); ok {
			t.Errorf("For(%q) resolves, but nothing populates Package.Source for it. "+
				"See the D8 comment in internal/matcher: the cataloger and the "+
				"matcher's source-name lookup must land in the same change, or "+
				"every package of that distro reports clean.", eco)
		}
	}

	// The language ecosystems are exactly these; a new one should be a
	// deliberate edit here rather than an accident.
	want := map[string]bool{
		"Go": true, "npm": true, "PyPI": true, "crates.io": true,
		"RubyGems": true, "Packagist": true, "NuGet": true, "Maven": true,
		// D88: "Wolfi" and "Chainguard" are plain registry entries too, even
		// though both are apk DISTROS, not language ecosystems -- unlike
		// every distro above (Alpine, Debian, Red Hat, Rocky Linux,
		// AlmaLinux, Amazon Linux, Oracle Linux, Fedora), OSV keys them bare
		// with no release suffix at all, so "Wolfi"/"Chainguard" IS the whole
		// key this project ever builds for them (D6, satisfied vacuously --
		// see pkgmeta.Distro.Ecosystem's "wolfi"/"chainguard" cases), not a
		// truncated one a prefix rule needs to guard against. The guard this
		// test exists for still holds: the apk cataloger already populates
		// Package.Source from apk's own `o:` field for every apk package
		// regardless of distro (D8, measured to ride free for Wolfi and
		// Chainguard's own packages too), so no new plumbing was needed
		// alongside this comparer the way dpkg/rpm needed their own.
		"Wolfi": true, "Chainguard": true,
		// D92: "MinimOS" is a clean clone of the Wolfi/Chainguard reasoning
		// above -- same apk distro shape, same bare no-release OSV key, same
		// free ride on the apk cataloger's existing Package.Source population.
		"MinimOS": true,
		// D92: "Echo" is the deb-based sibling -- OSV keys it bare too, with
		// no release axis (pkgmeta.Distro.Ecosystem's "echo" case), so it is
		// a plain registry entry rather than a "Debian:"-style prefix rule.
		// Unlike MinimOS it needed no new Package.Source plumbing either: the
		// dpkg cataloger already populates Source from the `Source:` field
		// for every dpkg-based system regardless of distro ID (the same free
		// ride D53 recorded for Ubuntu).
		"Echo": true,
	}
	for eco := range registry {
		if !want[eco] {
			t.Errorf("comparer registered for %q, which is not a known language ecosystem "+
				"or one of D88's release-less apk distros", eco)
		}
	}
	if len(registry) != len(want) {
		t.Errorf("registry has %d entries, want %d", len(registry), len(want))
	}
}

// TestFor_UbuntuLineageKeysDoNotResolve is the other half of D53's key
// decision, and it guards the direction that fails silently.
//
// OSV publishes 34 Ubuntu keys across six lineage families, and the Pro, FIPS
// and Realtime ones describe the SAME release as the mainline key. This build
// ingests mainline only, so a lineage key must NOT resolve a comparer: if it
// did, a package carrying that ecosystem would be evaluated against a database
// holding nothing for it and report clean. Refusing it here sends the package
// to D20's coverage skip instead, which is counted and reaches exit 2.
//
// Every key below was observed in the live OSV export on 2026-08-10, including
// the two non-canonical shapes — OSV's schema documents only the bare :Pro:
// prefix, so these spellings are convention rather than specification and a
// prefix match is not safe against them.
func TestFor_UbuntuLineageKeysDoNotResolve(t *testing.T) {
	for _, eco := range []string{
		"Ubuntu:Pro:20.04:LTS",
		"Ubuntu:Pro:FIPS:16.04:LTS",
		"Ubuntu:Pro:FIPS-updates:18.04:LTS",
		"Ubuntu:Pro:FIPS-preview:22.04:LTS",
		"Ubuntu:Pro:Realtime:22.04:LTS",
		"Ubuntu:Nvidia-BlueField:24.04:LTS",
		"Ubuntu:22.04:LTS:for:NVIDIA:BlueField",
		"Ubuntu:Pro:24.04:LTS:Realtime:Kernel",
		// The bare family name, for the reason every other distro guards it
		// (D6): it is not a key this project builds, and resolving it would
		// make a bug that dropped the release look like it worked.
		"Ubuntu", "Ubuntu:",
		// Shapes that are close enough to a real key to slip past a loose
		// pattern.
		"Ubuntu:22.04:lts", "Ubuntu:2.04:LTS", "Ubuntu:22.04:LTS:extra",
		"xUbuntu:22.04:LTS", "Ubuntu:jammy",
	} {
		if _, ok := For(eco); ok {
			t.Errorf("For(%q) resolves a comparer, but this build ingests no "+
				"advisories under that key. A package carrying it would be "+
				"evaluated against nothing and report clean (D53, D20).", eco)
		}
	}
}
