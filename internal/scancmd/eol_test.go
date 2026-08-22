package scancmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// testDBWithEOL is testDB plus a Meta.EOL bucket, for the D87 tests below.
// Coverage is the identical Alpine:v3.19/Go/npm/PyPI set testDB declares —
// every test in this file scans an Alpine 3.19 image, so the EOL question
// is never entangled with the D20 uncovered-ecosystem exit that would
// otherwise fire first and hide whatever the gate itself would have done.
func testDBWithEOL(t *testing.T, rows []store.EOLRelease) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19", "Go", "npm", "PyPI"}}},
		EOL:       rows,
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// pinClock is the t.Cleanup-guarded seam every other package variable in
// this codebase uses (dbcmd.replaceWaits, nvd.sleep): swaps clockNow for a
// fixed instant so a test can put "today" on either side of an EOLFrom
// boundary without waiting for a real date to pass, and restores the real
// clock unconditionally so no later test in the package inherits a frozen
// one.
func pinClock(t *testing.T, now time.Time) {
	t.Helper()
	orig := clockNow
	clockNow = func() time.Time { return now }
	t.Cleanup(func() { clockNow = orig })
}

// alpine319Image is the one-package Alpine 3.19 image every test in this
// file scans — built once as a helper so the EOL question is exercised
// against a real Run() call, through the real cataloger, not a hand-built
// pkgmeta.Target.
func alpine319Image(t *testing.T, dbPath string, opts Options) (stdout, stderr string, code int) {
	t.Helper()
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath: osReleaseAlpine319,
		apkDBPath:     apkOneRecord,
	})
	var out, errOut bytes.Buffer
	c := Run(context.Background(), dbPath, "docker-archive:"+tarPath, opts, &out, &errOut)
	return out.String(), errOut.String(), c
}

// TestRun_EOLGateFiresWhenTargetIsEOL is the caller-first test (CLAUDE.md's
// own rule): it proves Run actually calls lookupEOL and threads what comes
// back all the way to both the table renderer and verdict's exit code, not
// merely that the two exist side by side. Deleting either the lookupEOL
// call in Run or the FailOnEOL clause in verdict must turn this red — see
// the deletion check performed alongside this slice.
func TestRun_EOLGateFiresWhenTargetIsEOL(t *testing.T) {
	db := testDBWithEOL(t, []store.EOLRelease{
		{DistroID: "alpine", Release: "3.19", EOLFrom: "2026-01-01", EOLLabel: "Security Support"},
	})
	pinClock(t, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) // well after EOLFrom

	out, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true})
	if code != 1 {
		t.Fatalf("Run() = %d, want 1 (stdout: %s, stderr: %s)", code, out, errOut)
	}
	if !strings.Contains(out, "EOL: alpine 3.19 reached end of Security Support on 2026-01-01") {
		t.Errorf("stdout does not carry the EOL line:\n%s", out)
	}
}

// TestRun_EOLGateDoesNotFireBeforeEOLFrom is the other side of the same
// boundary: a release that has not yet reached its own EOLFrom must not
// trip the gate, and the table must print nothing about it (D87's own "one
// line only when EOL" rule, proven end to end here rather than only at the
// report-package layer).
func TestRun_EOLGateDoesNotFireBeforeEOLFrom(t *testing.T) {
	db := testDBWithEOL(t, []store.EOLRelease{
		{DistroID: "alpine", Release: "3.19", EOLFrom: "2026-01-01", EOLLabel: "Security Support"},
	})
	pinClock(t, time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)) // well before EOLFrom

	out, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true})
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stdout: %s, stderr: %s)", code, out, errOut)
	}
	if strings.Contains(out, "EOL:") {
		t.Errorf("stdout carries an EOL line for a release not yet EOL:\n%s", out)
	}
}

// TestRun_EOLBoundaryDayIsExclusive pins the exact edge Options.FailOnEOL's
// own doc comment and EOLStatus.EOL's promise: "strictly after", so the day
// EOLFrom itself names is NOT yet EOL — endoflife.date's own isEol
// semantics, and an off-by-one here would silently move a whole day of
// scans across the gate in the wrong direction.
func TestRun_EOLBoundaryDayIsExclusive(t *testing.T) {
	db := testDBWithEOL(t, []store.EOLRelease{
		{DistroID: "alpine", Release: "3.19", EOLFrom: "2026-01-01", EOLLabel: "Security Support"},
	})
	pinClock(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) // exactly EOLFrom, midnight UTC

	out, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true})
	if code != 0 {
		t.Fatalf("Run() on the EOLFrom day itself = %d, want 0 (exclusive boundary) "+
			"(stdout: %s, stderr: %s)", code, out, errOut)
	}
	if strings.Contains(out, "EOL:") {
		t.Errorf("stdout carries an EOL line on the boundary day itself:\n%s", out)
	}
}

// TestRun_EOLUnknownWithNoDistroWarnsButDoesNotTrip: an SBOM carries no
// distro identity at all (D84), so --fail-on-eol has nothing to gate on —
// it must warn on stderr naming why, and must NOT exit 1 for it (a false
// trip is exactly as wrong as a silent skip, D87's own rule).
func TestRun_EOLUnknownWithNoDistroWarnsButDoesNotTrip(t *testing.T) {
	db := testDB(t)
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{FailOnEOL: true}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stdout: %s, stderr: %s)", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "EOL unknown") || !strings.Contains(errOut.String(), "no distro identity") {
		t.Errorf("stderr does not disclose why --fail-on-eol could not answer:\n%s", errOut.String())
	}
}

// TestRun_EOLUnknownWithNoEOLDataWarnsButDoesNotTrip: the database has a
// distro identity to work with (the scan itself succeeds) but carries no
// EOL data at all — an old database, or one built with EOL_ENABLE=0 — and
// the warning must name THAT specific reason, not the no-distro one above.
func TestRun_EOLUnknownWithNoEOLDataWarnsButDoesNotTrip(t *testing.T) {
	db := testDB(t) // no EOL rows at all: store.Meta.EOL is nil

	out, errOut, code := alpine319Image(t, db, Options{FailOnEOL: true})
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stdout: %s, stderr: %s)", code, out, errOut)
	}
	if !strings.Contains(errOut, "EOL unknown") || !strings.Contains(errOut, "no end-of-life data") {
		t.Errorf("stderr does not disclose the no-EOL-data reason:\n%s", errOut)
	}
}

// TestRun_EOLWarningOnlyFiresWhenTheFlagIsSet: the disclosure is opt-in,
// the same shape the Red Hat mainline-errata note just above it in Run is
// NOT — an SBOM with no distro identity is the routine case (D84), and
// warning about it on every such scan would be exactly the noise nobody
// asked for.
func TestRun_EOLWarningOnlyFiresWhenTheFlagIsSet(t *testing.T) {
	db := testDB(t)
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, sbom, Options{}, &out, &errOut)
	if code != 0 {
		t.Fatalf("Run() = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "EOL unknown") {
		t.Errorf("stderr warned about EOL with no --fail-on-eol flag set:\n%s", errOut.String())
	}
}

// --- direct tests of the lookup helpers, for branches the Run-level tests
// above cannot reach through one Alpine fixture each (CLAUDE.md: caller
// first, then the helper directly for what the caller cannot reach) ---

func TestEOLCycle(t *testing.T) {
	for eco, want := range map[string]string{
		"Alpine:v3.19":       "3.19",
		"Debian:12":          "12",
		"Ubuntu:22.04:LTS":   "22.04",
		"Ubuntu:25.10":       "25.10",
		"Red Hat:9":          "9",
		"Rocky Linux:9":      "9",
		"AlmaLinux:9":        "9",
		"Amazon Linux:2":     "2",
		"Amazon Linux:2023":  "2023",
		"Oracle Linux:9":     "9",
		"Fedora:43":          "43",
		"SLES:15.SP6":        "15.6", // .SP reshaped to the dotted name endoflife.date uses
		"SLES:15":            "15.0", // GA fold: no dot means SP0, endoflife.date's "15.0"
		"SLES:16.0":          "16.0", // 16+ keys carry VersionID verbatim already
		"openSUSE Leap:15.6": "15.6",
	} {
		t.Run(eco, func(t *testing.T) {
			got, ok := eolCycle(eco)
			if !ok {
				t.Fatalf("eolCycle(%q) ok = false, want true", eco)
			}
			if got != want {
				t.Errorf("eolCycle(%q) = %q, want %q", eco, got, want)
			}
		})
	}
}

func TestEOLCycle_RefusesUnparseable(t *testing.T) {
	for _, eco := range []string{"", "NoColonAtAll", "Ubuntu:"} {
		if _, ok := eolCycle(eco); ok {
			t.Errorf("eolCycle(%q) ok = true, want false", eco)
		}
	}
}

// TestLookupEOL_DebianLTSShape is the Debian-bookworm shape D87 exists for,
// exercised directly (the report-package tests already prove the RENDER
// side of this with the identical fixture; this proves the DERIVATION):
// EOL is true (past EOLFrom) yet StillMaintained is true too, because the
// row's own IsMaintained says so.
func TestLookupEOL_DebianLTSShape(t *testing.T) {
	rows := []store.EOLRelease{{
		DistroID: "debian", Release: "12", EOLFrom: "2026-07-11", EOLLabel: "Debian Security Support",
		EOESFrom: "2028-06-30", EOESLabel: "Debian LTS", IsMaintained: true,
	}}
	distro := &pkgmeta.Distro{ID: "debian", VersionID: "12"}
	st := lookupEOL(distro, rows, time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC))
	if !st.Known || !st.EOL {
		t.Fatalf("lookupEOL = %+v, want Known and EOL", st)
	}
	if !st.StillMaintained {
		t.Errorf("lookupEOL = %+v, want StillMaintained (IsMaintained was true on the row)", st)
	}
	if st.EOESLabel != "Debian LTS" || st.EOESFrom != "2028-06-30" {
		t.Errorf("lookupEOL = %+v, missing the LTS phase detail", st)
	}
}

// TestLookupEOL_UnexpiredEOESAloneAlsoCountsAsMaintained: the OR half of
// StillMaintained's own doc comment — even a row whose IsMaintained is
// false still reads as maintained today if EOESFrom has not passed yet,
// which is possible when a database's IsMaintained is momentarily stale
// relative to a scan running the same day EOES data was regenerated.
func TestLookupEOL_UnexpiredEOESAloneAlsoCountsAsMaintained(t *testing.T) {
	rows := []store.EOLRelease{{
		DistroID: "alpine", Release: "3.18", EOLFrom: "2020-01-01",
		EOESFrom: "2099-01-01", IsMaintained: false,
	}}
	distro := &pkgmeta.Distro{ID: "alpine", VersionID: "3.18.0"}
	st := lookupEOL(distro, rows, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if !st.StillMaintained {
		t.Errorf("lookupEOL = %+v, want StillMaintained from the unexpired EOES date alone", st)
	}
}

// TestLookupEOL_DistroIDDisambiguatesSameRelease pins the OTHER half of the
// row-match guard: bare major release numbers collide across distro
// families ("9" is Release for rhel, almalinux, rocky and ol rows alike),
// so a row must match on DistroID as well as Release, not Release alone.
// TestLookupEOL_NoRowMatches above only ever exercises a mismatched
// Release; every fixture in this file otherwise builds Meta.EOL rows for a
// single scanned distro, so nothing before this test could tell a wrong
// DistroID from a right one. The wrong-distro row is placed FIRST here
// deliberately: a lookup keyed on Release alone would return it immediately
// and never reach the rhel row below it.
func TestLookupEOL_DistroIDDisambiguatesSameRelease(t *testing.T) {
	rows := []store.EOLRelease{
		{DistroID: "almalinux", Release: "9", EOLFrom: "2099-01-01"},
		{DistroID: "rhel", Release: "9", EOLFrom: "2032-05-31"},
	}
	distro := &pkgmeta.Distro{ID: "rhel", VersionID: "9.4"}
	st := lookupEOL(distro, rows, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if !st.Known {
		t.Fatalf("lookupEOL = %+v, want Known true (the rhel row matches)", st)
	}
	if st.DistroID != "rhel" || st.EOLFrom != "2032-05-31" {
		t.Errorf("lookupEOL = %+v, want the rhel row (EOLFrom 2032-05-31), not almalinux's "+
			"same-release row (EOLFrom 2099-01-01)", st)
	}
}

// TestLookupEOL_NoRowMatchesNames the reason, distro and cycle both, so a
// reader of the --fail-on-eol warning can tell which lookup failed.
func TestLookupEOL_NoRowMatches(t *testing.T) {
	rows := []store.EOLRelease{{DistroID: "alpine", Release: "3.18"}}
	distro := &pkgmeta.Distro{ID: "alpine", VersionID: "3.19.9"}
	st := lookupEOL(distro, rows, time.Now())
	if st.Known {
		t.Fatalf("lookupEOL = %+v, want Known false: no row for 3.19", st)
	}
	if !strings.Contains(st.Reason, "alpine") || !strings.Contains(st.Reason, "3.19") {
		t.Errorf("Reason = %q, want it to name both the distro and the cycle", st.Reason)
	}
}
