package dirscan

import (
	"testing"
)

// uvLock is shaped after a real uv.lock: a preamble, then [[package]] blocks
// whose dependencies are inline tables written one per line. Those inline
// tables are the reason the scanner takes the FIRST assignment of each field —
// `{ name = "idna" }` is a dependency, not this package's name.
const uvLock = `version = 1
requires-python = ">=3.11"

[[package]]
name = "the-project-itself"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "anyio" },
]

[[package]]
name = "anyio"
version = "4.13.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "sniffio" },
]
sdist = { url = "https://example.invalid/anyio.tar.gz", hash = "sha256:aaa", size = 158770 }
wheels = [
    { url = "https://example.invalid/anyio.whl", hash = "sha256:bbb", size = 85481 },
]

[[package]]
name = "idna"
version = "3.11"
source = { registry = "https://pypi.org/simple" }

[package.metadata]
requires-dist = [{ name = "anyio", specifier = ">=4.0" }]
`

func TestParse_UVLockReachesTheDispatch(t *testing.T) {
	root := writeTree(t, map[string]string{"uv.lock": uvLock})

	version, location := findPackage(t, root, "anyio")
	if version != "4.13.0" {
		t.Errorf("anyio version = %q, want 4.13.0", version)
	}
	if location != "uv.lock" {
		t.Errorf("location = %q, want uv.lock", location)
	}
}

// The inline tables inside `dependencies` name real packages. If one of them
// became the block's name, the lookup would still succeed — against another
// package's advisories — which is the quiet direction. Asserting the count and
// the exact set is what catches it, since "anyio is present" is true either way.
func TestParse_UVLockDependencyTablesAreNotPackages(t *testing.T) {
	root := writeTree(t, map[string]string{"uv.lock": uvLock})

	target, stats, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := map[string]string{}
	for _, p := range target.Packages {
		got[p.Name] = p.Version
	}
	want := map[string]string{
		"the-project-itself": "0.1.0",
		"anyio":              "4.13.0",
		"idna":               "3.11",
	}
	if len(got) != len(want) {
		t.Fatalf("packages = %v, want exactly %v", got, want)
	}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("%s = %q, want %q", name, got[name], version)
		}
	}
	// sniffio appears only as a dependency table and has no block of its own.
	if _, ok := got["sniffio"]; ok {
		t.Error("sniffio was cataloged; it is named in a dependencies table, not declared as a package")
	}
	if stats.Components != 3 || stats.Cataloged != 3 {
		t.Errorf("stats = %d components, %d cataloged; want 3 and 3", stats.Components, stats.Cataloged)
	}
}

// uv.lock is PyPI, not a new ecosystem. Getting this wrong is silent in the
// same way crates.io would be, and it is the one field that decides whether
// any of the advisories already in the database are reachable.
func TestParse_UVLockEcosystemIsPyPI(t *testing.T) {
	root := writeTree(t, map[string]string{"uv.lock": uvLock})

	target, _, _, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, p := range target.Packages {
		if p.Ecosystem != "PyPI" {
			t.Errorf("%s: ecosystem = %q, want PyPI", p.Name, p.Ecosystem)
		}
		if want := "pkg:pypi/" + p.Name + "@" + p.Version; p.PURL != want {
			t.Errorf("%s: PURL = %q, want %q", p.Name, p.PURL, want)
		}
	}
}

// The preamble sits above the first [[package]] and assigns both of the field
// names the scanner looks for: `version = 1` is the lockfile format version,
// not a package's. A reader that does not require an open block would turn it
// into one.
func TestParse_UVLockPreambleIsNotAPackage(t *testing.T) {
	root := writeTree(t, map[string]string{"uv.lock": "version = 1\nrequires-python = \">=3.11\"\n"})

	target, stats, found, err := Parse(root)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(target.Packages) != 0 || stats.Components != 0 {
		t.Errorf("packages = %+v, components = %d; want none", target.Packages, stats.Components)
	}
	// Read, not Unread: the file parsed fine and held no packages, which is
	// a different fact from a file that could not be read.
	if len(found.Read) != 1 || found.Read[0].Kind != KindUVLock {
		t.Errorf("Read = %+v, want one uv.lock entry", found.Read)
	}
	if found.AnyFailed() {
		t.Error("AnyFailed() = true; an empty lockfile is not a failure")
	}
}
