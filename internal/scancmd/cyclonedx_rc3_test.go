package scancmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Release check 2026-11-11 (main b732cac), the CycloneDX items, end to end
// through Run on qa1111DB.

const (
	rc3Amd  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
	rc3Arm  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=arm64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u14"}`
	rc3I386 = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=i386&distro=debian-11&upstream=glibc"}`
	rc3B13  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
	rc3B14  = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u14"}`
	rc3Bare = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?upstream=glibc%402.31-13%2Bdeb11u13"}`
)

// P1: the same document read the same way every run. Two bare records
// state the source two ways; the i386 install states no source version,
// so it is unjudged with the reason, and amd64 (vulnerable) and arm64
// (fixed) stand -- 1 finding, incomplete 1, exit 2, identically across 32
// runs (a Go map walk had lent whichever record came first: 70 or 65
// findings by run on the public DB). One bare record lends; none leaves
// i386 judged on its own version.
func TestRun_RC3_ConflictingBareRecordsLeaveTheInstallUnjudgedEveryRun(t *testing.T) {
	db := qa1111DB(t)
	opts := Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true}
	var first string
	for i := 0; i < 32; i++ {
		r := qa1111Run(t, db, rc2Doc([]string{rc3B13, rc3B14}, []string{rc3Amd, rc3Arm, rc3I386}), opts)
		var skips []string
		for _, s := range r.doc.Skipped {
			skips = append(skips, s.Package.PURL+" "+string(s.Cause)+" "+s.Reason)
		}
		sig := strings.Join([]string{string(rune('0' + r.code)), strings.Join(skips, ";")}, "|")
		for k, v := range r.findings {
			sig += "|" + k + "=" + v
		}
		if i == 0 {
			first = sig
			if r.code != 2 || len(r.findings) != 1 || r.doc.Summary.TargetIncomplete != 1 || r.doc.Summary.Components != 3 || !strings.Contains(strings.Join(skips, ";"), "arch=i386") || !strings.Contains(strings.Join(skips, ";"), "two values") {
				t.Fatalf("exit=%d findings=%v incomplete=%d components=%d skipped=%v; want 2, the amd64 finding, 1, 3, i386 unjudged for the two source versions", r.code, r.findings, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components, skips)
			}
		} else if sig != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, sig)
		}
	}
	r := qa1111Run(t, db, rc2Doc([]string{rc3B13}, []string{rc3Amd, rc3Arm, rc3I386}), opts)
	if r.code != 1 || len(r.findings) != 1 || r.doc.Summary.TargetIncomplete != 0 || r.findings["DEBIAN-CVE-2026-4046"] == "" {
		t.Errorf("single bare record: exit=%d findings=%v incomplete=%d; want 1, the finding (i386 lent deb11u13), 0", r.code, r.findings, r.doc.Summary.TargetIncomplete)
	}
}

// P1: a bare top-level listing joined by an arch-stating twin lends what it
// STATED, not the key the join gave it: an aarch64 install the document
// keys to nothing stays not evaluated whether it is listed before or after
// the keyed x86_64 one (2 findings, 1 not evaluated, exit 2 under
// --fail-on-incomplete=any).
func TestRun_RC3_SnapshotLendsNoKeyOfItsOwn(t *testing.T) {
	db := qa1111DB(t)
	const armUnkeyed = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=aarch64","properties":[{"name":"syft:location:0:path","value":"/child/aarch64/lib/apk/db/installed"}]}`
	for _, subject := range [][]string{{rc2X86Keyed, armUnkeyed}, {armUnkeyed, rc2X86Keyed}} {
		r := qa1111Run(t, db, rc2Doc([]string{rc2Bare}, subject), Options{FailOnIncomplete: true})
		if r.code != 2 || len(r.findings) != 1 || r.doc.Summary.NotEvaluated != 1 || r.doc.Summary.Components != 2 || !strings.Contains(r.findings["ALPINE319-CVE-2024-58251"], "/image/x86/") {
			t.Errorf("order %v: exit=%d findings=%v notEvaluated=%d components=%d; want 2, the x86_64 finding, 1, 2", subject, r.code, r.findings, r.doc.Summary.NotEvaluated, r.doc.Summary.Components)
		}
	}
}

// P1: a bare listing that contradicts its ONE arch-stating twin is not that
// install: the install keeps its finding and the bare listing is its own,
// marked and keyed -- wherever the two are placed. Under --fail-on low the
// finding exits 1 (the typed-top placement had lost it: 0 findings, exit
// 0); under the target gate the contradiction exits 2.
func TestRun_RC3_OneTwinContradictionKeepsTheInstall(t *testing.T) {
	db := qa1111DB(t)
	const (
		typedOnly = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?arch=amd64&distro=debian-11&upstream=glibc%402.31-13%2Bdeb11u13"}`
		bare14    = `{"type":"library","name":"libc6","version":"2.31-13+deb11u14","purl":"pkg:deb/debian/libc6@2.31-13%2Bdeb11u14?upstream=glibc%402.31-13%2Bdeb11u14"}`
		ctrl      = `{"type":"library","name":"assay-qa-inventory-control","version":"1.0.0","purl":"pkg:npm/assay-qa-inventory-control@1.0.0"}`
	)
	low := Options{FailOn: &bandLow, FailOnUnknown: true}
	target := Options{FailOn: &bandLow, FailOnUnknown: true, FailOnIncomplete: true, FailOnIncompleteTarget: true}
	for _, tc := range []struct {
		name         string
		top, subject []string
		incomplete   int
		comps        int
	}{
		{"bare top, typed subject", []string{bare14, ctrl}, []string{typedOnly}, 1, 3},
		{"typed top, bare subject", []string{typedOnly, ctrl}, []string{bare14}, 1, 3},
		{"typed only", []string{typedOnly, ctrl}, nil, 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := qa1111Run(t, db, rc2Doc(tc.top, tc.subject), low)
			if r.code != 1 || r.findings["DEBIAN-CVE-2026-4046"] == "" || r.doc.Summary.TargetIncomplete != tc.incomplete || r.doc.Summary.Components != tc.comps {
				t.Errorf("--fail-on low: exit=%d findings=%v incomplete=%d components=%d; want 1, the finding, %d, %d", r.code, r.findings, r.doc.Summary.TargetIncomplete, r.doc.Summary.Components, tc.incomplete, tc.comps)
			}
			r = qa1111Run(t, db, rc2Doc(tc.top, tc.subject), target)
			wantCode := 1
			if tc.incomplete > 0 {
				wantCode = 2
			}
			if r.code != wantCode || r.findings["DEBIAN-CVE-2026-4046"] == "" {
				t.Errorf("target gate: exit=%d findings=%v; want %d with the finding", r.code, r.findings, wantCode)
			}
		})
	}
}

// P2: a join keeps every qualifier either listing stated, so a VEX
// statement scoped by `distro=` reaches the install whichever listing
// carried the distro and whichever carried the arch; an `arch=`-scoped one
// still does.
func TestRun_RC3_JoinedPURLKeepsBothQualifiers(t *testing.T) {
	db := qa1111DB(t)
	const (
		distroOnly = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
		archOnly   = `{"type":"library","name":"busybox","version":"1.36.1-r20","purl":"pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64","properties":[{"name":"syft:location:0:path","value":"/image/x86/lib/apk/db/installed"}]}`
	)
	dir := t.TempDir()
	vex := func(name, product string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(`{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/qa/`+name+`","author":"QA","timestamp":"2026-11-11T00:00:00Z","version":1,`+
			`"statements":[{"vulnerability":{"name":"CVE-2024-58251"},"products":[{"@id":"`+product+`"}],"status":"not_affected","justification":"inline_mitigations_already_exist"}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	distroVEX := vex("distro.vex.json", "pkg:apk/alpine/busybox@1.36.1-r20?distro=alpine-3.19")
	archVEX := vex("arch.vex.json", "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64")
	for _, tc := range []struct {
		name         string
		top, subject []string
	}{
		{"distro top, arch subject", []string{distroOnly}, []string{archOnly}},
		{"arch top, distro subject", []string{archOnly}, []string{distroOnly}},
		{"both on one listing", []string{rc2X86Keyed}, nil},
	} {
		for _, v := range []string{distroVEX, archVEX} {
			t.Run(tc.name+" "+filepath.Base(v), func(t *testing.T) {
				r := qa1111Run(t, db, rc2Doc(tc.top, tc.subject), Options{FailOn: &bandLow, FailOnUnknown: true, VEXFiles: []string{v}})
				if r.doc.Summary.Suppressed != 1 || len(r.findings) != 0 || r.doc.Summary.Components != 1 {
					t.Errorf("suppressed=%d findings=%v components=%d; want 1, none, 1", r.doc.Summary.Suppressed, r.findings, r.doc.Summary.Components)
				}
				if len(r.doc.Suppressed) == 1 {
					if p := r.doc.Suppressed[0].Package.PURL; !strings.Contains(p, "arch=x86_64") || !strings.Contains(p, "distro=alpine-3.19") {
						t.Errorf("suppressed purl %q lacks a qualifier a listing stated", p)
					}
				}
			})
		}
	}
}
