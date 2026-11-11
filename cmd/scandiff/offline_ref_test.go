package main

import (
	"bytes"
	"strings"
	"testing"
)

// QA 2026-11-11: an offline capture is held to the floors file's pinned
// ref. A target whose digest was re-pinned, with the old capture still
// under its name, passed both modes as that capture. The capture records
// the argument assay scanned (provenance.target.argument, D120); when the
// ref pins a digest the argument must name it.
func TestRun_Offline_CaptureOfAnotherRefIsAnError(t *testing.T) {
	const (
		bci    = "registry.suse.com/bci/bci-base@sha256:c4bd6f1a43a3d80e9345e75a0e115e9a34daee55120ad4ba2f14d71bd29ba1eb"
		alpine = "mirror.gcr.io/library/alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
	)
	capture := func(arg string) []byte {
		prov := ""
		if arg != "" {
			prov = `,"provenance":{"target":{"argument":"` + arg + `","kind":"image"}}`
		}
		return []byte(`{"schemaVersion":22,"findings":[],"summary":{"components":5}` + prov + `}`)
	}
	for _, tc := range []struct {
		name    string
		ref     string
		capture []byte
		code    int
		want    string
	}{
		{"the capture is of the pinned ref", alpine, capture(alpine), exitOK, ""},
		{"the capture is of another digest", alpine, capture(bci), exitError, `error: target=t offline capture is a scan of "` + bci + `", not of the target's ref "` + alpine + `"`},
		{"the capture is of the tag, not the digest", alpine, capture("mirror.gcr.io/library/alpine:3.19"), exitError, "offline capture is a scan of"},
		{"a capture from before D120 records no target", alpine, capture(""), exitOK, ""},
		{"a ref without a digest must match whole", "alpine:3.19", capture("alpine:3.19"), exitOK, ""},
		{"a ref without a digest, another capture", "alpine:3.19", capture("alpine:3.20"), exitError, "offline capture is a scan of"},
	} {
		for _, mode := range []string{"", "-regressions-only"} {
			t.Run(tc.name+" "+mode, func(t *testing.T) {
				target := Target{Name: "t", Ref: tc.ref, MaxFindings: 50, MinComponents: 1}
				targetsPath := writeTargetsFile(t, []Target{target})
				dir := t.TempDir()
				writeOffline(t, dir, map[string][]byte{"t.assay.json": tc.capture, "t.grype.json": grypeDoc(nil)})
				args := []string{"-targets", targetsPath, "-offline", dir}
				if mode != "" {
					args = append(args, mode)
				}
				var stdout, stderr bytes.Buffer
				code := run(args, &stdout, &stderr, noExec(t))
				if code != tc.code || (tc.want != "" && !strings.Contains(stderr.String(), tc.want)) {
					t.Errorf("exit %d, want %d; stderr lacks %q:\n%s\n%s", code, tc.code, tc.want, stderr.String(), stdout.String())
				}
				if tc.code == exitError && !strings.Contains(stdout.String(), "ERROR") {
					t.Errorf("the table does not show the ERROR verdict:\n%s", stdout.String())
				}
			})
		}
	}
}
