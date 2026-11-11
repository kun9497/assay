package scancmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Release check 2026-11-11 (main 60c512c), the CycloneDX items, end to end
// through Run on qa1111DB.

const (
	rc4Armhf = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=armhf&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
	rc4BNone = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?distro=debian-11"}`
	// The install stating arch and the other release's spelling of distro.
	rc4Bare320 = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.20","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
	rc4OS319   = `{"type":"operating-system","name":"alpine","version":"3.19.9"}`
)

// P1: three bare listings -- two at different source versions, one stating
// none -- leave an install that states no source version unjudged with BOTH
// versions in the reason, wherever the sourceless listing sits: the pair
// named is the pair that contradicts, not the first two (60c512c had judged
// the install on its own version when the sourceless listing came second:
// 90 findings, exit 0, against 70 and exit 2 for the other placements). The
// installs stating a source version keep their findings. The controls: two
// bare listings at one version and a sourceless third lend that version;
// three at one version too.
func TestRun_RC4_ThreeSourceCandidatesAgreeInEveryPlacement(t *testing.T) {
	db := qa1111DB(t)
	opts := Options{FailOnIncomplete: true}
	subject := []string{rc3Amd, rc4Armhf, rc3Arm, rc3I386}
	var first string
	for _, top := range [][]string{{rc4BNone, rc3B13, rc3B14}, {rc3B13, rc4BNone, rc3B14}, {rc3B13, rc3B14, rc4BNone}} {
		r := qa1111Run(t, db, rc2Doc(top, subject), opts)
		var skips []string
		for _, s := range r.doc.Skipped {
			skips = append(skips, s.Package.PURL+" "+string(s.Cause)+" "+s.Reason)
		}
		joined := strings.Join(skips, ";")
		if r.code != 2 || len(r.findings) != 1 || r.doc.Summary.NotEvaluated != 1 || r.doc.Summary.TargetIncomplete != 1 || r.doc.Summary.Components != 4 ||
			!strings.Contains(joined, "arch=i386") || !strings.Contains(joined, "2.31-13+deb11u13 and 2.31-13+deb11u14") {
			t.Fatalf("placement %v: exit=%d findings=%v notEvaluated=%d incomplete=%d components=%d skipped=%v; want 2, the amd64/armhf finding, 1, 1, 4, i386 unjudged for deb11u13 and deb11u14",
				top, r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components, skips)
		}
		sig := joined
		for k, v := range r.findings {
			sig += "|" + k + "=" + v
		}
		if first == "" {
			first = sig
		} else if sig != first {
			t.Fatalf("placement %v differs:\n%s\n%s", top, first, sig)
		}
	}
	for _, tc := range []struct {
		name string
		top  []string
	}{
		{"two at one version and one stating none", []string{rc3B13, rc4BNone, rc3B13}},
		{"three at one version", []string{rc3B13, rc3B13, rc3B13}},
	} {
		r := qa1111Run(t, db, rc2Doc(tc.top, subject), opts)
		if r.code != 0 || r.doc.Summary.TargetIncomplete != 0 || r.doc.Summary.NotEvaluated != 0 || !strings.Contains(r.findings["DEBIAN-CVE-2026-4046"], "Debian:11") {
			t.Errorf("%s: exit=%d findings=%v incomplete=%d notEvaluated=%d; want 0, the finding (i386 lent deb11u13), 0, 0", tc.name, r.code, r.findings, r.doc.Summary.TargetIncomplete, r.doc.Summary.NotEvaluated)
		}
	}
}

// P1: a VEX statement scoped to another release does not reach the
// install. The document's OS is Alpine 3.19 and the install states
// `distro=alpine-3.19`; a second listing of it spells `distro=alpine-3.20`.
// A statement for 3.20 exonerates nothing (60c512c: the join had taken the
// second listing's distro onto the install's purl, and the 3.20 statement
// hid both findings, exit 0), whichever listing comes first and when the
// 3.20 listing is absent; a statement for 3.19, or for the architecture,
// still applies.
func TestRun_RC4_VEXScopedToAnotherReleaseDoesNotReachTheInstall(t *testing.T) {
	db := qa1111DB(t)
	dir := t.TempDir()
	vex := func(name, product string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/qa/`+name+`","author":"QA","timestamp":"2026-11-11T00:00:00Z","version":1,"statements":[`+
			`{"vulnerability":{"name":"CVE-2024-58251"},"products":[{"@id":"`+product+`"}],"status":"not_affected","justification":"inline_mitigations_already_exist"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	only320 := vex("alpine320.vex.json", "pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.20")
	only319 := vex("alpine319.vex.json", "pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19")
	onlyArch := vex("arch.vex.json", "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64")
	for _, tc := range []struct {
		name         string
		top, subject []string
	}{
		{"typed top, 3.20 listing under the subject", []string{rc4OS319, rc2X86Keyed}, []string{rc4Bare320}},
		{"3.20 listing top, typed under the subject", []string{rc4OS319, rc4Bare320}, []string{rc2X86Keyed}},
		{"no second listing (control)", []string{rc4OS319, rc2X86Keyed}, nil},
	} {
		for _, v := range []struct {
			path       string
			suppressed int
		}{{only320, 0}, {only319, 1}, {onlyArch, 1}} {
			t.Run(tc.name+" "+filepath.Base(v.path), func(t *testing.T) {
				r := qa1111Run(t, db, rc2Doc(tc.top, tc.subject), Options{FailOn: &bandLow, FailOnUnknown: true, VEXFiles: []string{v.path}})
				wantCode := 1
				if v.suppressed == 1 {
					wantCode = 0
				}
				if r.doc.Summary.Suppressed != v.suppressed || len(r.findings) != 1-v.suppressed || r.code != wantCode || r.doc.Summary.Components != 1 || r.doc.Summary.TargetIncomplete != 0 {
					t.Errorf("suppressed=%d findings=%v exit=%d components=%d incomplete=%d; want %d, %d finding(s), %d, 1, 0", r.doc.Summary.Suppressed, r.findings, r.code, r.doc.Summary.Components, r.doc.Summary.TargetIncomplete, v.suppressed, 1-v.suppressed, wantCode)
				}
				for _, f := range r.doc.Findings {
					if p := f.Package.PURL; strings.Contains(p, "alpine-3.20") || f.Package.Ecosystem != "Alpine:v3.19" {
						t.Errorf("finding purl %q ecosystem %q: the purl must spell the evaluated release", p, f.Package.Ecosystem)
					}
				}
			})
		}
	}
}

// P2: a top-level purl written without `@version` joined by a listing that
// carries it keeps the version, so a version-scoped statement reaches the
// install (60c512c: the join merged qualifiers only, and the statement for
// busybox@1.36.1-r20 no longer matched -- 2 findings back, exit 1).
func TestRun_RC4_JoinedPURLTakesTheVersionTheTopListingOmitted(t *testing.T) {
	db := qa1111DB(t)
	const noVersionTop = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox?arch=x86_64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
	p := filepath.Join(t.TempDir(), "version.vex.json")
	if err := os.WriteFile(p, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/qa/version","author":"QA","timestamp":"2026-11-11T00:00:00Z","version":1,"statements":[`+
		`{"vulnerability":{"name":"CVE-2024-58251"},"products":[{"@id":"pkg:apk/alpine/busybox@1.36.1-r20"}],"status":"not_affected","justification":"inline_mitigations_already_exist"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := qa1111Run(t, db, rc2Doc([]string{rc4OS319, noVersionTop}, []string{rc2Bare}), Options{FailOn: &bandLow, FailOnUnknown: true, VEXFiles: []string{p}})
	if r.doc.Summary.Suppressed != 1 || len(r.findings) != 0 || r.code != 0 || r.doc.Summary.Components != 1 {
		t.Errorf("suppressed=%d findings=%v exit=%d components=%d; want 1, none, 0, 1", r.doc.Summary.Suppressed, r.findings, r.code, r.doc.Summary.Components)
	}
	if len(r.doc.Suppressed) == 1 && !strings.Contains(r.doc.Suppressed[0].Package.PURL, "busybox@1.36.1-r20") {
		t.Errorf("suppressed purl %q lacks the version the subject listing stated", r.doc.Suppressed[0].Package.PURL)
	}
}
