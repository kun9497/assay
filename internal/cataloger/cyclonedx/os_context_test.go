package cyclonedx

import (
	"strings"
	"testing"
)

// D166: the Target's own distro -- what the report's EOL line and coverage
// read -- is the top-level context's, else the one distro every OS component
// in the document agrees on, else none.
func TestParse_D166_TargetDistro(t *testing.T) {
	const (
		start   = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,`
		alpine  = `{"type":"operating-system","name":"alpine","version":"3.19.9"}`
		debian  = `{"type":"operating-system","name":"debian","version":"11"}`
		busybox = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}`
	)
	for _, tc := range []struct{ name, body, want string }{
		{"top-level OS", start + `"components":[` + alpine + `,` + busybox + `]}`, "alpine 3.19.9"},
		{"only a nested OS", start + `"components":[],"metadata":{"component":{"type":"container","name":"d","components":[` + alpine + `,` + busybox + `]}}}`, "alpine 3.19.9"},
		{"top-level wins over a nested one", start + `"components":[` + debian + `],"metadata":{"component":{"type":"container","name":"d","components":[` + alpine + `]}}}`, "debian 11"},
		// An OS in an unrelated branch keys that branch only; the subject's
		// own OS names the target.
		{"OS only in a top-level branch", start + `"components":[{"type":"application","name":"a","components":[` + debian + `]}]}`, ""},
		{"a branch's OS and the subject's", start + `"components":[{"type":"application","name":"a","components":[` + debian + `]}],"metadata":{"component":{"type":"container","name":"d","components":[` + alpine + `]}}}`, "alpine 3.19.9"},
		{"the subject is the OS", start + `"components":[` + busybox + `],"metadata":{"component":` + alpine + `}}`, "alpine 3.19.9"},
		{"no OS", start + `"components":[` + busybox + `]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, _, err := Parse(strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if target.Distro != nil {
				got = target.Distro.ID + " " + target.Distro.VersionID
			}
			if got != tc.want {
				t.Errorf("Target.Distro = %q, want %q", got, tc.want)
			}
		})
	}
}

// Two OS components of one release are one declaration, by ecosystem key.
func TestParse_D166_SameReleaseIsOneDeclaration(t *testing.T) {
	const doc = `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` +
		`{"type":"operating-system","name":"alpine","version":"3.19.9"},{"type":"operating-system","name":"alpine","version":"3.19.1"},` +
		`{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}]}`
	target, _, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 || target.Packages[0].Ecosystem != "Alpine:v3.19" {
		t.Errorf("packages = %+v, want busybox keyed Alpine:v3.19", target.Packages)
	}
}

// A package at the top (no OS there, unkeyed) and again under a subject
// that keys it is one package, keyed by the subject's listing (PR #270
// review).
func TestParse_D166_UnkeyedTopTwinOfAKeyedSubjectListingIsOnePackage(t *testing.T) {
	const busybox = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}`
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[` + busybox + `],` +
		`"metadata":{"component":{"type":"container","name":"d","components":[{"type":"operating-system","name":"alpine","version":"3.19.9"},` + busybox + `]}}}`
	target, stats, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(target.Packages) != 1 || target.Packages[0].Ecosystem != "Alpine:v3.19" || stats.Components != 1 {
		t.Errorf("packages = %+v, components = %d, want one busybox keyed Alpine:v3.19", target.Packages, stats.Components)
	}
}
