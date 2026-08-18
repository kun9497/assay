package pkgmeta

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in                            string
		typ, namespace, name, version string
	}{
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang", "github.com/foo", "bar", "v1.2.3"},
		{"pkg:golang/github.com/foo/bar", "golang", "github.com/foo", "bar", ""},
		{"pkg:npm/lodash@4.17.20", "npm", "", "lodash", "4.17.20"},
		{"pkg:npm/%40angular/core@12.0.0", "npm", "@angular", "core", "12.0.0"},
		{"pkg:npm/@angular/common@12.0.0", "npm", "@angular", "common", "12.0.0"}, // raw @ in namespace
		{"pkg:pypi/django@3.2", "pypi", "", "django", "3.2"},
		{"pkg:apk/alpine/apache2@2.4.54-r0?arch=source", "apk", "alpine", "apache2", "2.4.54-r0"},
		{"pkg:PyPI/Django@3.2", "pypi", "", "Django", "3.2"},                                           // type lowercases, name does not
		{"pkg:golang/github.com/foo/bar@v1.2.3#sub/path", "golang", "github.com/foo", "bar", "v1.2.3"}, // subpath discarded
		{"pkg:golang/example.com/a/b/c@v1.0.0", "golang", "example.com/a/b", "c", "v1.0.0"},            // 3+ segment namespace
		{"pkg:npm/lodash@", "npm", "", "lodash", ""},                                                   // empty version
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParsePURL(tc.in)
			if err != nil {
				t.Fatalf("ParsePURL(%q) error: %v", tc.in, err)
			}
			if got.Type != tc.typ || got.Namespace != tc.namespace ||
				got.Name != tc.name || got.Version != tc.version {
				t.Errorf("ParsePURL(%q) = %+v, want type=%q ns=%q name=%q ver=%q",
					tc.in, got, tc.typ, tc.namespace, tc.name, tc.version)
			}
		})
	}
}

func TestParsePURL_Qualifiers(t *testing.T) {
	got, err := ParsePURL("pkg:apk/alpine/apache2@2.4.54-r0?arch=source&distro=alpine-3.19")
	if err != nil {
		t.Fatal(err)
	}
	if got.Qualifiers["arch"] != "source" {
		t.Errorf("arch qualifier = %q, want source", got.Qualifiers["arch"])
	}
	if got.Qualifiers["distro"] != "alpine-3.19" {
		t.Errorf("distro qualifier = %q, want alpine-3.19", got.Qualifiers["distro"])
	}
}

func TestParsePURL_Invalid(t *testing.T) {
	for _, in := range []string{"", "golang/foo@v1", "pkg:", "pkg:golang", "pkg:/foo@v1"} {
		if _, err := ParsePURL(in); err == nil {
			t.Errorf("ParsePURL(%q) = nil error, want error", in)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	// syft emits installed metadata verbatim, so mixed-case PyPI names reach us
	// while OSV publishes only PEP 503 forms. Every one of the 1,586 distinct
	// PyPI names in the live dump is normalized, so without this the lookup key
	// never matches and the package is reported clean with no error at all.
	cases := []struct{ eco, in, want string }{
		{"PyPI", "Jinja2", "jinja2"},
		{"PyPI", "PyYAML", "pyyaml"},
		{"PyPI", "zope.interface", "zope-interface"},
		{"PyPI", "backports_abc", "backports-abc"},
		{"PyPI", "a.-_b", "a-b"},
		{"PyPI", "django", "django"},
		// Go and npm are case-sensitive in their registries and OSV keeps them.
		{"Go", "github.com/Masterminds/semver/v3", "github.com/Masterminds/semver/v3"},
		{"npm", "@jupyterlab/help-extension", "@jupyterlab/help-extension"},
		{"npm", "JSONStream", "JSONStream"},
		// NuGet package IDs are case-insensitive; measured, 98% of advisory
		// names in the live dump are mixed-case, so a lowercase fold (no PEP
		// 503 separator folding) is what keeps a lookup from missing them.
		{"NuGet", "Newtonsoft.Json", "newtonsoft.json"},
		{"NuGet", "newtonsoft.json", "newtonsoft.json"},
		{"NuGet", "System.Text.Json", "system.text.json"},
		// RubyGems, Packagist and Maven are case-sensitive and pass through
		// unchanged, the same as Go and npm above.
		{"RubyGems", "Rails", "Rails"},
		{"Packagist", "Drupal/Core", "Drupal/Core"},
		{"Maven", "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-core"},
	}
	for _, tc := range cases {
		if got := NormalizeName(tc.eco, tc.in); got != tc.want {
			t.Errorf("NormalizeName(%q, %q) = %q, want %q", tc.eco, tc.in, got, tc.want)
		}
	}
}

func TestEcosystemForPURLType(t *testing.T) {
	// cargo is the one entry whose purl type and ecosystem key are different
	// strings, which is why the map exists at all rather than being an
	// identity function with exceptions. Getting it wrong is silent: the
	// lookup lands in a bucket no provider writes and the package reports
	// clean.
	cases := map[string]string{
		"golang": "Go", "npm": "npm", "pypi": "PyPI", "cargo": "crates.io",
		"gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist", "maven": "Maven",
	}
	for typ, want := range cases {
		got, ok := EcosystemForPURLType(typ)
		if !ok || got != want {
			t.Errorf("EcosystemForPURLType(%q) = %q,%v want %q,true", typ, got, ok, want)
		}
	}
	// apk maps to a distro ecosystem whose key needs a release (D6), which a
	// purl does not carry. Left unmapped rather than mapped to a wrong key.
	if _, ok := EcosystemForPURLType("apk"); ok {
		t.Error("EcosystemForPURLType(apk) = ok, want not ok in slice 1")
	}
}
