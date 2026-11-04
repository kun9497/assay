package cyclonedx

import (
	"strings"
	"testing"
)

// QA 2026-11-04: metadata.component. The caller's tests live in
// internal/scancmd/cyclonedx_subject_test.go; these hold the branches the
// caller cannot see through a summary -- which bucket a subject's skip lands
// in, and that the root shapes land in none.
func TestParse_SubjectShapes(t *testing.T) {
	const start = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,`
	for _, tc := range []struct {
		name     string
		subject  string
		wantPkgs []string // name@version
		want     Stats
	}{
		{
			name:     "real library is cataloged",
			subject:  `{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}`,
			wantPkgs: []string{"lodash@4.17.20"},
			want:     Stats{Components: 1, Cataloged: 1},
		},
		{
			name:    "child of a purl-less container is cataloged, the container is not counted",
			subject: `{"type":"container","name":"demo","components":[{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}`,
			wantPkgs: []string{
				"lodash@4.17.20",
			},
			want: Stats{Components: 1, Cataloged: 1},
		},
		{
			name:    "grandchild under the subject is reached",
			subject: `{"type":"container","name":"demo","components":[{"type":"application","name":"app","version":"1","purl":"pkg:npm/app@1","components":[{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}]}`,
			wantPkgs: []string{
				"app@1", "lodash@4.17.20",
			},
			want: Stats{Components: 2, Cataloged: 2},
		},
		{
			name:    "syft container, no purl: root, uncounted",
			subject: `{"type":"container","name":"mirror.gcr.io/library/alpine:3.19","version":"sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171"}`,
			want:    Stats{},
		},
		{
			name:    "pkg:oci subject: root, uncounted",
			subject: `{"type":"container","name":"demo","version":"1","purl":"pkg:oci/demo@sha256:0000000000000000000000000000000000000000000000000000000000000000"}`,
			want:    Stats{},
		},
		{
			name:    "purl without a version: root, uncounted",
			subject: `{"type":"application","name":"product","purl":"pkg:npm/product"}`,
			want:    Stats{},
		},
		{
			// Not a root shape: a top-level component with this purl lands
			// in SkippedNoPURL, and the subject gets the same counted skip
			// rather than vanishing.
			name:    "malformed purl: a counted skip",
			subject: `{"type":"library","name":"odd","version":"1","purl":"not-a-purl"}`,
			want:    Stats{Components: 1, SkippedNoPURL: 1},
		},
		{
			// Likewise an unsupported ecosystem is counted where a top-level
			// twin's would be, so --fail-on-incomplete can see it.
			name:    "unsupported purl type with a version: a counted skip",
			subject: `{"type":"library","name":"odd","version":"1","purl":"pkg:generic/odd@1"}`,
			want:    Stats{Components: 1, SkippedUnsupportedEcosystem: 1},
		},
		{
			// A child of the subject is inventory, not a root: its skip
			// counts even though it has no purl.
			name:    "purl-less child of the subject is a counted skip",
			subject: `{"type":"container","name":"demo","components":[{"type":"library","name":"bare","version":"1"}]}`,
			want:    Stats{Components: 1, SkippedNoPURL: 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, stats, err := Parse(strings.NewReader(start + `"metadata":{"component":` + tc.subject + `}}`))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			var got []string
			for _, p := range target.Packages {
				got = append(got, p.Name+"@"+p.Version)
			}
			if strings.Join(got, ",") != strings.Join(tc.wantPkgs, ",") {
				t.Errorf("packages = %v, want %v", got, tc.wantPkgs)
			}
			if stats != tc.want {
				t.Errorf("stats = %+v, want %+v", stats, tc.want)
			}
		})
	}
}

// A package listed both as the subject (or under it) and in bom.components
// is one package; a second top-level listing is left as it was, two.
func TestParse_SubjectDuplicateOfAComponentIsOnePackage(t *testing.T) {
	const start = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,`
	const lodash = `{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}`
	for _, tc := range []struct {
		name     string
		doc      string
		wantPkgs int
		want     Stats
	}{
		{
			name:     "subject repeats a component verbatim",
			doc:      start + `"metadata":{"component":` + lodash + `},"components":[` + lodash + `]}`,
			wantPkgs: 1,
			want:     Stats{Components: 1, Cataloged: 1},
		},
		{
			name: "subject repeats a component with a different qualifier",
			doc: start + `"metadata":{"component":{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20?package-id=1"}},` +
				`"components":[` + lodash + `]}`,
			wantPkgs: 1,
			want:     Stats{Components: 1, Cataloged: 1},
		},
		{
			name:     "child of the subject repeats a component",
			doc:      start + `"metadata":{"component":{"type":"container","name":"demo","components":[` + lodash + `]}},"components":[` + lodash + `]}`,
			wantPkgs: 1,
			want:     Stats{Components: 1, Cataloged: 1},
		},
		{
			// A different version is a different package.
			name:     "subject at another version is a second package",
			doc:      start + `"metadata":{"component":{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}},"components":[` + lodash + `]}`,
			wantPkgs: 2,
			want:     Stats{Components: 2, Cataloged: 2},
		},
		{
			// Unchanged behaviour: two top-level listings were never
			// deduped, and this change does not widen into them.
			name:     "two top-level listings stay two",
			doc:      start + `"components":[` + lodash + `,` + lodash + `]}`,
			wantPkgs: 2,
			want:     Stats{Components: 2, Cataloged: 2},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, stats, err := Parse(strings.NewReader(tc.doc))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(target.Packages) != tc.wantPkgs {
				t.Errorf("packages = %d (%+v), want %d", len(target.Packages), target.Packages, tc.wantPkgs)
			}
			if stats != tc.want {
				t.Errorf("stats = %+v, want %+v", stats, tc.want)
			}
		})
	}
}

// The dedupe is subject tree against bom.components, nothing else: two
// listings both nested under the subject stay two, as two top-level
// listings do, so where a generator put its inventory does not change how
// many packages it holds. A bare purl at two component versions is two
// packages: the version comes from the component, so an equal purl string
// does not say equal version.
func TestParse_SubjectDedupeIsAgainstComponentsOnly(t *testing.T) {
	const start = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,`
	const lodash = `{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}`
	for _, tc := range []struct {
		name     string
		doc      string
		wantPkgs int
	}{
		{
			name:     "two listings both nested under the subject stay two",
			doc:      start + `"metadata":{"component":{"type":"container","name":"demo","components":[` + lodash + `,` + lodash + `]}}}`,
			wantPkgs: 2,
		},
		{
			name: "bare purl at two component versions is two packages",
			doc: start + `"metadata":{"component":{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash"}},` +
				`"components":[{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash"}]}`,
			wantPkgs: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, stats, err := Parse(strings.NewReader(tc.doc))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(target.Packages) != tc.wantPkgs {
				t.Errorf("packages = %d (%+v), want %d", len(target.Packages), target.Packages, tc.wantPkgs)
			}
			if want := (Stats{Components: tc.wantPkgs, Cataloged: tc.wantPkgs}); stats != want {
				t.Errorf("stats = %+v, want %+v", stats, want)
			}
		})
	}
}

// A dropped second listing still leaves its evidence on the kept package:
// every location the document gave the package (D10), and a source identity
// only the dropped listing carried (D8) -- a deb purl whose upstream
// qualifier one listing wrote and the other did not.
func TestParse_SubjectDuplicateKeepsTheDroppedListingsEvidence(t *testing.T) {
	const start = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,`
	t.Run("locations", func(t *testing.T) {
		const a = `{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20?package-id=a","properties":[{"name":"syft:location:0:path","value":"/app/a/node_modules/lodash/package.json"}]}`
		const b = `{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20?package-id=b","properties":[{"name":"syft:location:0:path","value":"/app/b/node_modules/lodash/package.json"}]}`
		target, _, err := Parse(strings.NewReader(start + `"metadata":{"component":` + b + `},"components":[` + a + `]}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(target.Packages) != 1 {
			t.Fatalf("packages = %d, want 1", len(target.Packages))
		}
		var paths []string
		for _, l := range target.Packages[0].Locations {
			paths = append(paths, l.Path)
		}
		if want := "/app/a/node_modules/lodash/package.json,/app/b/node_modules/lodash/package.json"; strings.Join(paths, ",") != want {
			t.Errorf("locations = %v, want both listings' paths", paths)
		}
	})
	t.Run("source", func(t *testing.T) {
		const bare = `{"type":"library","name":"libssl3","version":"3.0.2-0ubuntu1.15","purl":"pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.15?distro=ubuntu-22.04"}`
		const withSource = `{"type":"library","name":"libssl3","version":"3.0.2-0ubuntu1.15","purl":"pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.15?distro=ubuntu-22.04&upstream=openssl"}`
		target, _, err := Parse(strings.NewReader(start + `"metadata":{"component":` + withSource + `},"components":[` + bare + `]}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(target.Packages) != 1 {
			t.Fatalf("packages = %d, want 1", len(target.Packages))
		}
		if src := target.Packages[0].Source; src == nil || src.Name != "openssl" {
			t.Errorf("source = %+v, want openssl from the dropped listing", src)
		}
	})
}

// A distro package as the subject, or under it, is keyed by the document's
// operating-system component as its top-level twin is: the scratch
// inventory the subject walk catalogs into carries the document's distro.
func TestParse_SubjectDistroPackageIsKeyedByTheDocumentDistro(t *testing.T) {
	const start = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,`
	const debian12 = `{"type":"operating-system","name":"debian","version":"12","properties":[{"name":"syft:distro:id","value":"debian"},{"name":"syft:distro:versionID","value":"12"}]}`
	const bsdutils = `{"type":"library","name":"bsdutils","version":"2.38.1-5","purl":"pkg:deb/debian/bsdutils@2.38.1-5?arch=amd64&distro=debian-11"}`
	for _, tc := range []struct{ name, subject string }{
		{"subject", bsdutils},
		{"subject-child", `{"type":"container","name":"demo","components":[` + bsdutils + `]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, _, err := Parse(strings.NewReader(start + `"metadata":{"component":` + tc.subject + `},"components":[` + debian12 + `]}`))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(target.Packages) != 1 || target.Packages[0].Ecosystem != "Debian:12" {
				t.Errorf("packages = %+v, want one keyed Debian:12 (the document's distro, not the qualifier's)", target.Packages)
			}
		})
	}
}
