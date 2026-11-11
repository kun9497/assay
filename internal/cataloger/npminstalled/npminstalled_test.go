package npminstalled

import (
	"testing"
)

func TestIsInstalledPackageJSON(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"usr/lib/node_modules/npm/package.json", true},
		{"usr/lib/node_modules/npm/node_modules/minimatch/package.json", true},
		{"usr/lib/node_modules/@types/node/package.json", true},
		{"usr/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json", true},
		{"usr/lib/node_modules/npm/esm/package.json", false},           // a file inside a package
		{"usr/lib/node_modules/npm/test/fixtures/package.json", false}, // deeper inside a package
		{"usr/lib/node_modules/package.json", false},                   // the root itself is not a package
		{"usr/lib/node_modules/npm/my-package.json", false},            // not package.json
		{"usr/lib/node_modules/@types/package.json", false},            // a scope directory is not a package
		{"usr/lib/node_modules/.bin/package.json", false},              // npm's own dot directory (QA 2026-11-11)
		{"usr/lib/node_modules/.pnpm/x@1.0.0/node_modules/x/package.json", true},
		{"app/node_modules/left-pad/package.json", true},               // the rule is about shape; roots are the probe's business
	} {
		if got := IsInstalledPackageJSON(tc.path); got != tc.want {
			t.Errorf("IsInstalledPackageJSON(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestCatalog_PackagesSkipsAndOrder(t *testing.T) {
	pkgs, stats := Catalog(map[string][]byte{
		"usr/lib/node_modules/npm/node_modules/minimatch/package.json": []byte(`{"name":"minimatch","version":"3.0.4"}`),
		"usr/lib/node_modules/npm/package.json":                        []byte(`{"name":"npm","version":"8.19.4","description":"x"}`),
		"usr/lib/node_modules/@scope/pkg/package.json":                 []byte(`{"name":"@scope/pkg","version":"1.2.3"}`),
		"usr/lib/node_modules/npm/esm/package.json":                    []byte(`{"type":"module"}`), // not installed: ignored, not a component
		"usr/lib/node_modules/broken/package.json":                     []byte(`{"name":`),          // unreadable
		"usr/lib/node_modules/nameless/package.json":                   []byte(`{"version":"1.0.0"}`),
		"usr/lib/node_modules/versionless/package.json":                []byte(`{"name":"versionless"}`),
	})
	if stats.Components != 6 || stats.Cataloged != 3 || stats.SkippedNoVersion != 3 {
		t.Errorf("stats = %+v, want 6 installed files, 3 packages, 3 skips", stats)
	}
	if len(pkgs) != 3 {
		t.Fatalf("pkgs = %d, want 3", len(pkgs))
	}
	// Path order, so two runs over one image agree: @scope sorts first.
	wantOrder := []string{"@scope/pkg", "minimatch", "npm"}
	for i, p := range pkgs {
		if p.Name != wantOrder[i] {
			t.Errorf("pkgs[%d].Name = %q, want %q", i, p.Name, wantOrder[i])
		}
		if p.Ecosystem != "npm" || p.Type != "npm" || p.PURL != "pkg:npm/"+p.Name+"@"+p.Version {
			t.Errorf("pkgs[%d] = %+v, want ecosystem/type npm and the lockfile cataloger's purl spelling", i, p)
		}
		if len(p.Locations) != 1 || !IsInstalledPackageJSON(p.Locations[0].Path) {
			t.Errorf("pkgs[%d].Locations = %+v, want the package.json path", i, p.Locations)
		}
	}
	if pkgs[1].Locations[0].Path != "usr/lib/node_modules/npm/node_modules/minimatch/package.json" {
		t.Errorf("minimatch location = %q, want the nested path", pkgs[1].Locations[0].Path)
	}
}

// Two copies of one name at two versions are two packages, each at its own
// path -- npm's own tree holds 24 such names on ubi8/nodejs-18.
func TestCatalog_TwoVersionsOfOneNameAreTwoPackages(t *testing.T) {
	pkgs, _ := Catalog(map[string][]byte{
		"usr/lib/node_modules/npm/node_modules/semver/package.json":                                []byte(`{"name":"semver","version":"7.5.4"}`),
		"usr/lib/node_modules/npm/node_modules/make-fetch-happen/node_modules/semver/package.json": []byte(`{"name":"semver","version":"6.3.1"}`),
	})
	if len(pkgs) != 2 || pkgs[0].Version == pkgs[1].Version || pkgs[0].Locations[0].Path == pkgs[1].Locations[0].Path {
		t.Errorf("pkgs = %+v, want two semver packages at two versions and two paths", pkgs)
	}
}

func TestCatalog_EmptyInputIsEmpty(t *testing.T) {
	pkgs, stats := Catalog(nil)
	if len(pkgs) != 0 || stats != (stats) || stats.Components != 0 {
		t.Errorf("Catalog(nil) = %v, %+v, want nothing", pkgs, stats)
	}
}
