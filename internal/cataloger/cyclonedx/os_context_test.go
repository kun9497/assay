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
		{"two nested, disagreeing", start + `"components":[{"type":"application","name":"a","components":[` + debian + `]}],"metadata":{"component":{"type":"container","name":"d","components":[` + alpine + `]}}}`, ""},
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
