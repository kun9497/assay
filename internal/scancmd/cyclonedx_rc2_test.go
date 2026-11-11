package scancmd

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Release check 2026-11-11 (main 5197df4), the CycloneDX items, end to end
// through Run on qa1111DB (Debian 11 glibc fixed in deb11u14; Alpine 3.19
// and 3.20 busybox).

const (
	rc2X86Top   = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64","properties":[{"name":"syft:location:0:path","value":"/x86/top"}]}`
	rc2X86Sub   = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64","properties":[{"name":"syft:location:0:path","value":"/x86/subject"}]}`
	rc2ArmKeyed = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/child/aarch64/lib/apk/db/installed"}]}`
	rc2X86Keyed = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
	rc2Bare     = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20","properties":[{"name":"syft:location:0:path","value":"/top-unknown"}]}`
	rc2BareKey  = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/bare/keyed"}]}`
)

func rc2Doc(top, subject []string) string {
	return qa1111Start + `"components":[` + strings.Join(top, ",") + `],"metadata":{"component":{"type":"container","name":"demo","components":[` + strings.Join(subject, ",") + `]}}}`
}

// P1: a release stated only for aarch64 does not key a separate x86_64
// install. The x86_64 listings (one top, one subject, no distro) stay one
// unkeyed package: 2 ARM findings, 1 not evaluated, exit 2 under
// --fail-on-incomplete=any, in either order. A release stated for the same
// architecture, or by a record stating none, keys it.
func TestRun_RC2_ReleaseFromAnotherArchitectureDoesNotKey(t *testing.T) {
	db := qa1111DB(t)
	any := Options{FailOnIncomplete: true}
	for _, tc := range []struct {
		name        string
		subject     []string
		findings    int
		notEval     int
		code, comps int
	}{
		{"other arch keyed first", []string{rc2ArmKeyed, rc2X86Sub}, 1, 1, 2, 2},
		{"other arch keyed last", []string{rc2X86Sub, rc2ArmKeyed}, 1, 1, 2, 2},
		{"same arch keyed first", []string{rc2X86Keyed, rc2X86Sub}, 1, 0, 0, 1},
		{"same arch keyed last", []string{rc2X86Sub, rc2X86Keyed}, 1, 0, 0, 1},
		{"bare record keyed first", []string{rc2BareKey, rc2X86Sub}, 1, 0, 0, 1},
		{"bare record keyed last", []string{rc2X86Sub, rc2BareKey}, 1, 0, 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qa1111Run(t, db, rc2Doc([]string{rc2X86Top}, tc.subject), any)
			if r.code != tc.code || len(r.findings) != tc.findings || r.doc.Summary.NotEvaluated != tc.notEval || r.doc.Summary.Components != tc.comps {
				t.Errorf("exit=%d findings=%v notEvaluated=%d components=%d; want %d, %d, %d, %d", r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Summary.Components, tc.code, tc.findings, tc.notEval, tc.comps)
			}
		})
	}
}

// P1: a bare source record beside two arch-stating installs of one release
// is evidence for the installs it agrees with, not the first one listed.
// amd64 states glibc deb11u13 (vulnerable), arm64 deb11u14 (fixed), the bare
// record deb11u13: one finding, nothing unevaluated, either order -- the
// arm-first order had joined the bare record to arm64 and called it a
// contradiction (25 findings, incomplete 1, exit 2 on the public DB).
func TestRun_RC2_BareSourceRecordLendsToTheInstallsItAgreesWith(t *testing.T) {
	db := qa1111DB(t)
	const (
		amd  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
		arm  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=arm64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u14"}`
		bare = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?upstream=glibc%402.31-13%2Bdeb11u13"}`
	)
	opts := Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true}
	for _, tc := range []struct {
		name    string
		top     []string
		subject []string
	}{
		{"with bare, amd first", []string{bare}, []string{amd, arm}},
		{"with bare, arm first", []string{bare}, []string{arm, amd}},
		{"without bare, amd first", nil, []string{amd, arm}},
		{"without bare, arm first", nil, []string{arm, amd}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qa1111Run(t, db, rc2Doc(tc.top, tc.subject), opts)
			if r.code != 1 || len(r.findings) != 1 || r.findings["DEBIAN-CVE-2026-4046"] == "" || r.doc.Summary.NotEvaluated != 0 || r.doc.Summary.TargetIncomplete != 0 || r.doc.Summary.Components != 2 {
				t.Errorf("exit=%d findings=%v notEvaluated=%d incomplete=%d components=%d; want 1, the amd64 finding, 0, 0, 2", r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components)
			}
		})
	}
	// A bare record that contradicts every install is none of them: it is
	// its own listing, marked with the contradiction (D165), and the
	// installs are judged on their own statements -- 3 components, the
	// amd64 finding, incomplete 1, exit 2, in either order.
	const bareOther = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?upstream=glibc%401%3A2.31-13%2Bdeb11u13"}`
	for _, subject := range [][]string{{amd, arm}, {arm, amd}} {
		r := qa1111Run(t, db, rc2Doc([]string{bareOther}, subject), opts)
		if r.code != 2 || len(r.findings) != 1 || r.doc.Summary.TargetIncomplete != 1 || r.doc.Summary.Components != 3 {
			t.Errorf("contradicting bare, order %v: exit=%d findings=%v incomplete=%d components=%d; want 2, the amd64 finding, 1, 3", subject, r.code, r.findings, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components)
		}
	}
}

// P2: a VEX statement scoped to x86_64 suppresses that install's CVE and no
// other, whatever the listing order and whether a bare record is listed:
// the install a bare listing joins takes the twin's purl, so the `arch=`
// qualifier the statement names is on the package VEX compares.
func TestRun_RC2_ArchScopedVEXReachesTheJoinedInstall(t *testing.T) {
	db := qa1111DB(t)
	vexPath := filepath.Join(t.TempDir(), "arch.vex.json")
	if err := os.WriteFile(vexPath, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/qa/arch","author":"QA","timestamp":"2026-11-11T00:00:00Z","version":1,`+
		`"statements":[{"vulnerability":{"name":"CVE-2024-58251"},"products":[{"@id":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64"}],"status":"not_affected","justification":"inline_mitigations_already_exist"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{FailOn: &bandLow, FailOnUnknown: true, VEXFiles: []string{vexPath}}
	for _, tc := range []struct {
		name          string
		top, subject  []string
		findings      int
		suppressed    int
		comps         int
		suppressedLoc string // the path the suppressed finding's package must carry
	}{
		{"with bare, x86 first", []string{rc2Bare}, []string{rc2X86Keyed, rc2ArmKeyed}, 1, 1, 2, "/image/x86/lib/apk/db/installed"},
		{"with bare, arm first", []string{rc2Bare}, []string{rc2ArmKeyed, rc2X86Keyed}, 1, 1, 2, "/image/x86/lib/apk/db/installed"},
		{"without bare, x86 first", nil, []string{rc2X86Keyed, rc2ArmKeyed}, 1, 1, 2, "/image/x86/lib/apk/db/installed"},
		{"without bare, arm first", nil, []string{rc2ArmKeyed, rc2X86Keyed}, 1, 1, 2, "/image/x86/lib/apk/db/installed"},
		{"unique: bare top, keyed x86 subject", []string{rc2Bare}, []string{rc2X86Keyed}, 0, 1, 1, "/image/x86/lib/apk/db/installed"},
		{"unique: keyed x86 top, bare subject", []string{rc2X86Keyed}, []string{rc2Bare}, 0, 1, 1, "/image/x86/lib/apk/db/installed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qa1111Run(t, db, rc2Doc(tc.top, tc.subject), opts)
			var supPaths []string
			for _, s := range r.doc.Suppressed {
				for _, l := range s.Package.Locations {
					supPaths = append(supPaths, l.Path)
				}
			}
			sort.Strings(supPaths)
			if len(r.findings) != tc.findings || r.doc.Summary.Suppressed != tc.suppressed || r.doc.Summary.Components != tc.comps || !strings.Contains(strings.Join(supPaths, ","), tc.suppressedLoc) {
				t.Errorf("findings=%v suppressed=%d (paths %v) components=%d; want %d, %d on %s, %d", r.findings, r.doc.Summary.Suppressed, supPaths, r.doc.Summary.Components, tc.findings, tc.suppressed, tc.suppressedLoc, tc.comps)
			}
			// The bare listing's own path lands on an install it agrees
			// with (every one, when it joins none), never on neither.
			if len(tc.top) == 1 && tc.top[0] == rc2Bare {
				all := strings.Join(supPaths, ",")
				for _, f := range r.findings {
					all += "," + f
				}
				if !strings.Contains(all, "/top-unknown") {
					t.Errorf("the bare listing's /top-unknown is on no install: suppressed %v, findings %v", supPaths, r.findings)
				}
			}
		})
	}
}
