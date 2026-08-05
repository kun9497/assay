package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/scancmd"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/store"
)

func TestRun_ExitCodes(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitError},
		{"version", []string{"version"}, exitOK},
		{"help", []string{"help"}, exitOK},
		{"unknown command", []string{"bogus"}, exitError},
		{"scan without target", []string{"scan"}, exitError},
		// An explicit image reference that cannot be read must fail loudly
		// rather than be interpreted as a clean, empty scan (D11). This uses a
		// docker-archive: prefix pointing at a file that does not exist, rather
		// than a bare registry reference like "alpine:3.19": the prefix makes
		// classification unambiguous and the load fails locally, so the test
		// never reaches an actual registry over the network.
		{"scan of an image target that cannot be read", []string{"scan", "docker-archive:/does/not/exist.tar"}, exitError},
		{"db without subcommand", []string{"db"}, exitError},
		{"db unknown subcommand", []string{"db", "bogus"}, exitError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.want {
				t.Errorf("run(%v) = %d, want %d (stderr: %s)",
					tc.args, got, tc.want, stderr.String())
			}
		})
	}
}

func TestRun_VersionGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("version returned %d, want %d", code, exitOK)
	}
	if !strings.HasPrefix(stdout.String(), "assay ") {
		t.Errorf("version output not on stdout or malformed: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", stderr.String())
	}
}

// Errors belong on stderr so that `assay scan ... --output json | jq` stays clean.
func TestRun_ErrorsGoToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	run([]string{"bogus"}, &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("stderr missing diagnostic: %q", stderr.String())
	}
}

// TestParseScanArgs covers the CLI syntax for the three --fail-on* flags:
// recognized in any position relative to the target (grype-style tools are
// invoked as `scan <target> --fail-on <band>`, target first), both the
// "--fail-on value" and "--fail-on=value" spellings, and the error cases a
// typo produces. Bad input must be an error, never a silently-ignored flag
// (task 5 brief) — a threshold the user thought they set but did not is worse
// than no threshold at all.
func TestParseScanArgs(t *testing.T) {
	high, critical := severity.High, severity.Critical

	t.Run("target only, no flags", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts != (scancmd.Options{}) {
			t.Errorf("opts = %+v, want the zero value", opts)
		}
	})

	t.Run("--fail-on after the target, space form", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--fail-on", "high"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != high {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, high)
		}
	})

	t.Run("--fail-on before the target", func(t *testing.T) {
		// The stdlib flag package stops parsing at the first non-flag
		// argument, which would treat the target itself as ending flag
		// parsing. This CLI's flags must work in either position.
		target, opts, err := parseScanArgs([]string{"--fail-on", "critical", "alpine:3.19"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != critical {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, critical)
		}
	})

	t.Run("--fail-on=value form", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--fail-on=high"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != high {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, high)
		}
	})

	t.Run("--fail-on-unknown and --fail-on-incomplete together", func(t *testing.T) {
		target, opts, err := parseScanArgs(
			[]string{"alpine:3.19", "--fail-on-unknown", "--fail-on-incomplete"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if !opts.FailOnUnknown {
			t.Error("opts.FailOnUnknown = false, want true")
		}
		if !opts.FailOnIncomplete {
			t.Error("opts.FailOnIncomplete = false, want true")
		}
	})

	t.Run("all three flags plus the target, mixed order", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{
			"--fail-on-incomplete", "alpine:3.19", "--fail-on", "medium", "--fail-on-unknown",
		})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.FailOn == nil || *opts.FailOn != severity.Medium {
			t.Errorf("opts.FailOn = %v, want %v", opts.FailOn, severity.Medium)
		}
		if !opts.FailOnUnknown || !opts.FailOnIncomplete {
			t.Errorf("opts = %+v, want both bool gates true", opts)
		}
	})

	t.Run("no target at all", func(t *testing.T) {
		target, _, err := parseScanArgs([]string{"--fail-on", "high"})
		if err != nil {
			t.Fatalf("err = %v, want nil (the caller checks for an empty target)", err)
		}
		if target != "" {
			t.Errorf("target = %q, want empty", target)
		}
	})

	t.Run("--fail-on with no value is an error, not a silently-ignored flag", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--fail-on"})
		if err == nil {
			t.Fatal("err = nil, want an error naming the missing value")
		}
		if !strings.Contains(err.Error(), "--fail-on") {
			t.Errorf("err = %q, want it to name --fail-on", err)
		}
	})

	// `--fail-on critical --fail-on low` must not silently loosen the gate to
	// whichever value came last - the same "the user thought they set a
	// threshold but did not" shape an invalid value already guards against.
	t.Run("a repeated --fail-on is rejected, not silently last-wins", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--fail-on", "critical", "--fail-on", "low"})
		if err == nil {
			t.Fatal("err = nil, want an error: a repeated --fail-on must not silently loosen the gate")
		}
	})

	// The mixed-spelling case: "--fail-on=x" the second time must be caught
	// too, since the check is on whether FailOn is already set, not on which
	// spelling set it.
	t.Run("a repeated --fail-on is rejected even across the two spellings", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--fail-on", "critical", "--fail-on=low"})
		if err == nil {
			t.Fatal("err = nil, want an error for the second --fail-on")
		}
	})

	// D17/the brief: a threshold the user thought they set but did not is
	// worse than no threshold, so a typo must be an error, not "no gate".
	t.Run("an invalid --fail-on value is an error naming what is accepted", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--fail-on", "extreme"})
		if err == nil {
			t.Fatal("err = nil, want an error for an invalid band")
		}
		for _, want := range []string{"extreme", "none", "low", "medium", "high", "critical"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, missing %q", err, want)
			}
		}
	})

	t.Run("an unrecognized flag is an error, not silently ignored", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--bogus"})
		if err == nil {
			t.Fatal("err = nil, want an error naming the unknown flag")
		}
		if !strings.Contains(err.Error(), "--bogus") {
			t.Errorf("err = %q, want it to name --bogus", err)
		}
	})

	t.Run("a second positional argument is an error", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "alpine:3.20"})
		if err == nil {
			t.Fatal("err = nil, want an error: scan takes exactly one target")
		}
	})

	// --output: D18, the flag name follows grype's own --output.
	t.Run("--output json after the target", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--output", "json"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.Output != "json" {
			t.Errorf("opts.Output = %q, want %q", opts.Output, "json")
		}
	})

	t.Run("--output=json form", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--output=json"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.Output != "json" {
			t.Errorf("opts.Output = %q, want %q", opts.Output, "json")
		}
	})

	t.Run("--output table is accepted explicitly", func(t *testing.T) {
		_, opts, err := parseScanArgs([]string{"alpine:3.19", "--output", "table"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if opts.Output != "table" {
			t.Errorf("opts.Output = %q, want %q", opts.Output, "table")
		}
	})

	t.Run("an invalid --output value is an error naming what is accepted", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--output", "sarif"})
		if err == nil {
			t.Fatal("err = nil, want an error for an unsupported output format")
		}
		for _, want := range []string{"sarif", "table", "json"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, missing %q", err, want)
			}
		}
	})

	t.Run("a repeated --output is rejected, not silently last-wins", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--output", "json", "--output", "table"})
		if err == nil {
			t.Fatal("err = nil, want an error: a repeated --output must not silently change the renderer")
		}
	})

	// --explain: D10/D8 made visible. Chosen as a scan flag rather than a
	// grype-style separate `explain` subcommand — see task-6-report.md for
	// the reasoning — but the word itself still follows grype's own naming
	// for the same feature (D18).
	t.Run("--explain <id> after the target", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"alpine:3.19", "--explain", "CVE-2024-12345"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.Explain != "CVE-2024-12345" {
			t.Errorf("opts.Explain = %q, want %q", opts.Explain, "CVE-2024-12345")
		}
	})

	t.Run("--explain=<id> form", func(t *testing.T) {
		_, opts, err := parseScanArgs([]string{"alpine:3.19", "--explain=GHSA-abcd"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if opts.Explain != "GHSA-abcd" {
			t.Errorf("opts.Explain = %q, want %q", opts.Explain, "GHSA-abcd")
		}
	})

	t.Run("--explain before the target", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{"--explain", "GHSA-abcd", "alpine:3.19"})
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if target != "alpine:3.19" {
			t.Errorf("target = %q, want %q", target, "alpine:3.19")
		}
		if opts.Explain != "GHSA-abcd" {
			t.Errorf("opts.Explain = %q, want %q", opts.Explain, "GHSA-abcd")
		}
	})

	t.Run("--explain with no value is an error, not a silently-ignored flag", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--explain"})
		if err == nil {
			t.Fatal("err = nil, want an error naming the missing value")
		}
		if !strings.Contains(err.Error(), "--explain") {
			t.Errorf("err = %q, want it to name --explain", err)
		}
	})

	// F5: "--explain=" (the = form with nothing after it) must be rejected
	// the same way, not silently leave opts.Explain empty. An empty
	// opts.Explain is indistinguishable from the flag never having been
	// given at all (scancmd.Run's own dispatch is `case opts.Explain !=
	// "":`), so an unguarded empty value would make Run silently fall back
	// to the table and exit 0 — the "flag parsed, then inert" shape this
	// branch has already been burned by once for --fail-on-incomplete.
	t.Run("--explain= with an empty value is rejected, not silently disabled", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--explain="})
		if err == nil {
			t.Fatal("err = nil, want an error: an empty --explain value must not silently disable the flag")
		}
	})

	t.Run("a repeated --explain is rejected, not silently last-wins", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--explain", "GHSA-1", "--explain", "GHSA-2"})
		if err == nil {
			t.Fatal("err = nil, want an error: a repeated --explain must not silently change which advisory is explained")
		}
	})

	t.Run("--explain cannot be combined with --output json", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--explain", "GHSA-1", "--output", "json"})
		if err == nil {
			t.Fatal("err = nil, want an error: the two renderers cannot both be requested")
		}
		if !strings.Contains(err.Error(), "--explain") || !strings.Contains(err.Error(), "--output") {
			t.Errorf("err = %q, want it to name both conflicting flags", err)
		}
	})

	t.Run("--explain cannot be combined with --output=json (the other spelling)", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--output=json", "--explain", "GHSA-1"})
		if err == nil {
			t.Fatal("err = nil, want an error regardless of flag order or --output spelling")
		}
	})

	// The conflict is not specific to --output json. scancmd.Run's dispatch
	// says "Three renderers, exactly one chosen", and that has to hold for
	// BOTH values of --output, not just "json" — otherwise an explicitly
	// requested table silently loses to --explain instead of the two being
	// flagged as the contradictory request they are.
	t.Run("--explain cannot be combined with --output table either", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--explain", "GHSA-1", "--output", "table"})
		if err == nil {
			t.Fatal("err = nil, want an error: an explicit --output table must not silently " +
				"lose to --explain")
		}
		if !strings.Contains(err.Error(), "--explain") || !strings.Contains(err.Error(), "--output") {
			t.Errorf("err = %q, want it to name both conflicting flags", err)
		}
	})
}

// The CLI contract end to end: a bad --fail-on value reaches run() as exit 2
// with the accepted values on stderr, never a scan that silently ran with no
// gate at all.
func TestRun_ScanBadFailOnValueExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "docker-archive:/does/not/exist.tar", "--fail-on", "extreme"},
		&stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "want one of") {
		t.Errorf("stderr = %q, want it to name the accepted bands", stderr.String())
	}
}

// scan with flags but no target must still be treated as "no target", the
// same exit code and messaging as today's no-flags case.
func TestRun_ScanFlagsWithNoTargetExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--fail-on", "high"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)", code, exitError)
	}
	if !strings.Contains(stderr.String(), "requires a target") {
		t.Errorf("stderr = %q, want it to say a target is required", stderr.String())
	}
}

// buildRunSeamFixture writes a real database (at ASSAY_DB_DIR/vulnerability.db
// — the caller must have already pointed ASSAY_DB_DIR at dir) and a matching
// CycloneDX SBOM naming three packages, so that all three --fail-on* gates
// have something to fire on simultaneously:
//
//   - "critical": a critical-severity finding (for --fail-on).
//   - "unknownsev": a finding whose advisory carries no CVSS vector at all,
//     so severity.Highest reports it Unknown (for --fail-on-unknown).
//   - "somecrate": a cargo purl, an unsupported ecosystem type the cataloger
//     drops before the matcher ever sees it, so report.Summary.NotEvaluated
//     is > 0 (for --fail-on-incomplete).
//
// All three conditions are present unconditionally; only which flag is set
// decides whether any of them changes the exit code, which is exactly what
// TestRun_ScanFlagsReachRealExitCode needs to isolate one flag at a time
// against one shared fixture.
func buildRunSeamFixture(t *testing.T, dir string) string {
	t.Helper()

	dbPath := filepath.Join(dir, "vulnerability.db")
	w, err := store.Create(dbPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	advisories := []advisory.Advisory{
		{
			ID:   "GHSA-critical",
			Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{
				Ecosystem: "Go",
				Name:      "example.com/critical",
				Ranges: []advisory.Range{{
					Type:   advisory.RangeSemver,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
				}},
			}},
			Severity: []advisory.Severity{
				// critical, 9.8 - the same vector pinned against its exact
				// band and score in internal/matcher/matcher_test.go.
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
		},
		{
			ID:   "GHSA-unknownsev",
			Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{
				Ecosystem: "Go",
				Name:      "example.com/unknownsev",
				Ranges: []advisory.Range{{
					Type:   advisory.RangeSemver,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}},
				}},
			}},
			// No Severity entries at all -> severity.Highest returns Unknown.
		},
	}
	for _, a := range advisories {
		if err := w.Put(a); err != nil {
			t.Fatalf("Put(%s): %v", a.ID, err)
		}
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sbom := filepath.Join(dir, "s.cdx.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"critical","version":"1.0.0","purl":"pkg:golang/example.com/critical@1.0.0"},` +
		`{"type":"library","name":"unknownsev","version":"1.0.0","purl":"pkg:golang/example.com/unknownsev@1.0.0"},` +
		`{"type":"library","name":"somecrate","version":"1.0.0","purl":"pkg:cargo/somecrate@1.0.0"}` +
		`]}`
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return sbom
}

// TestRun_ScanFlagsReachRealExitCode is the run()-seam wiring check for all
// three --fail-on* flags, not just --fail-on. TestParseScanArgs proves each
// field is parsed correctly; scancmd's own TestRun_ExitCodeMatrix proves
// scancmd.Run honours a given Options value correctly. Neither one can catch
// main.go silently dropping a field on the way between them — e.g.
//
//	opts.FailOnUnknown = false
//	opts.FailOnIncomplete = false
//	return scancmd.Run(ctx, path, target, opts, stdout, stderr)
//
// type-checks and leaves both of those suites green, since each only ever
// exercises its own half in isolation. This drives run() itself against one
// fixture (buildRunSeamFixture) that has all three conditions present at
// once, so the shared "no flags" row proves none of them changes the exit
// code alone, and each flag's own row proves that flag — and only that flag
// — does. A single dropped field (or all three) must turn exactly its own
// row red; a table reads that contract in one place rather than three
// near-identical test functions.
//
// store.DefaultPath honours ASSAY_DB_DIR (internal/store/store.go), which is
// what lets this test point the real lookup path at a temp dir without a
// database-path parameter on run() itself — no network, no real registry.
func TestRun_ScanFlagsReachRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	sbom := buildRunSeamFixture(t, dir)

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no flags: a critical finding, an unrated finding, and an unevaluated " +
			"package are all present, and none of them changes the exit code alone",
			nil, exitOK},
		{"--fail-on critical reaches scancmd.Run through run()",
			[]string{"--fail-on", "critical"}, exitFindings},
		{"--fail-on-unknown reaches scancmd.Run through run()",
			[]string{"--fail-on-unknown"}, exitFindings},
		{"--fail-on-incomplete reaches scancmd.Run through run()",
			[]string{"--fail-on-incomplete"}, exitError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"scan", sbom}, tc.args...)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != tc.want {
				t.Errorf("run(%v) = %d, want %d\nstdout:\n%s\nstderr:\n%s",
					args, code, tc.want, stdout.String(), stderr.String())
			}
		})
	}
}

// The CLI contract end to end for the repeated-flag rejection: exit 2, the
// diagnostic on stderr, and stdout untouched. TestParseScanArgs already
// proves parseScanArgs returns a non-nil error for a repeat; this proves the
// error actually reaches run()'s exit code and stream discipline rather than
// being swallowed or misrouted between parseScanArgs and run()'s own error
// handling.
// The target is a real, scannable SBOM rather than a path that does not
// exist. Against a missing target the exit code is 2 whether or not the flag
// was rejected, so that assertion proved nothing — verified: deleting the
// repeat check left it green, and only the stderr line carried the test. This
// fixture exits 0 on its own, so exit 2 here can only come from the rejection.
func TestRun_ScanRepeatedFailOnExits2(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	sbom := buildRunSeamFixture(t, dir)

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", sbom,
		"--fail-on", "critical", "--fail-on", "low"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)\nstderr:\n%s", code, exitError, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "more than once") {
		t.Errorf("stderr = %q, want it to say --fail-on was given more than once", stderr.String())
	}
}

// TestRun_ScanOutputJSONReachesRealExitCode is the run()-seam wiring check
// for --output json: TestParseScanArgs proves the flag parses correctly, and
// scancmd's own TestRun_OutputJSON proves scancmd.Run honours a given
// Options.Output correctly. Neither catches main.go silently dropping the
// field on the way between them (the same class of bug
// TestRun_ScanFlagsReachRealExitCode exists to catch for the --fail-on*
// gates) — e.g. `return scancmd.Run(ctx, path, target, scancmd.Options{
// FailOn: opts.FailOn}, stdout, stderr)` type-checks and leaves both of
// those suites green.
func TestRun_ScanOutputJSONReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	sbom := buildRunSeamFixture(t, dir)

	var stdout, stderr bytes.Buffer
	args := []string{"scan", sbom, "--output", "json"}
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("run(%v) = %d, want %d\nstdout:\n%s\nstderr:\n%s",
			args, code, exitOK, stdout.String(), stderr.String())
	}
	var doc report.Document
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", doc.SchemaVersion)
	}
	// buildRunSeamFixture's critical + unrated findings; somecrate is
	// dropped by the cataloger and never reaches a Finding at all.
	if len(doc.Findings) != 2 {
		t.Errorf("Findings = %d, want 2\nstdout:\n%s", len(doc.Findings), stdout.String())
	}
	if strings.Contains(stdout.String(), "PACKAGE") {
		t.Errorf("stdout contains the table header; --output json must reach scancmd "+
			"and replace Table entirely, not silently fall back to it:\n%s", stdout.String())
	}

	// Composing with --fail-on proves Output was not the only field that
	// survived the trip through run() — a mutation dropping FailOn while
	// keeping Output would pass the case above and fail only this one.
	stdout.Reset()
	stderr.Reset()
	args = []string{"scan", sbom, "--output", "json", "--fail-on", "critical"}
	if code := run(args, &stdout, &stderr); code != exitFindings {
		t.Errorf("run(%v) = %d, want %d (exitFindings)\nstdout:\n%s\nstderr:\n%s",
			args, code, exitFindings, stdout.String(), stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Errorf("stdout is not valid JSON even with --fail-on tripped: %v\n%s", err, stdout.String())
	}
}

// TestRun_ScanExplainReachesRealExitCode is the equivalent run()-seam wiring
// check for --explain: proves the identifier parsed by parseScanArgs reaches
// scancmd.Run rather than being dropped on the way, that it composes with
// --fail-on (a different field surviving the same trip), and that an
// identifier matching nothing is a loud exit 2 with stdout untouched, not a
// silent empty success.
func TestRun_ScanExplainReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	sbom := buildRunSeamFixture(t, dir)

	t.Run("matching id reaches scancmd.Run and replaces the table", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"scan", sbom, "--explain", "GHSA-critical"}
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("run(%v) = %d, want %d\nstdout:\n%s\nstderr:\n%s",
				args, code, exitOK, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), "GHSA-critical") {
			t.Errorf("stdout does not contain the explanation:\n%s", stdout.String())
		}
		if strings.Contains(stdout.String(), "PACKAGE") {
			t.Errorf("stdout contains the table header; --explain must reach scancmd "+
				"and replace Table entirely:\n%s", stdout.String())
		}
	})

	t.Run("--explain composes with --fail-on (both fields survive the trip)", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"scan", sbom, "--explain", "GHSA-critical", "--fail-on", "critical"}
		if code := run(args, &stdout, &stderr); code != exitFindings {
			t.Errorf("run(%v) = %d, want %d (exitFindings)\nstdout:\n%s\nstderr:\n%s",
				args, code, exitFindings, stdout.String(), stderr.String())
		}
	})

	t.Run("an id matching nothing is exit 2 with stdout untouched", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"scan", sbom, "--explain", "GHSA-does-not-exist"}
		if code := run(args, &stdout, &stderr); code != exitError {
			t.Errorf("run(%v) = %d, want %d\nstdout:\n%s\nstderr:\n%s",
				args, code, exitError, stdout.String(), stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("error path polluted stdout: %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "GHSA-does-not-exist") {
			t.Errorf("stderr = %q, want it to name the identifier that matched nothing", stderr.String())
		}
	})
}

// buildGoBinaryRunSeamDB writes a real database (at
// ASSAY_DB_DIR/vulnerability.db) holding one advisory against
// go.etcd.io/bbolt - a real dependency this test binary genuinely links
// (through internal/store, D4), so a "file:"+os.Executable() target produces
// a real finding rather than a fixture-shaped one. Unlike
// internal/scancmd's own TestRun_GatesApplyToBinaryAndDirectoryTargets, this
// can scan os.Executable() directly: cmd/assay's own test binary IS built
// from `package main`, and only a `go test` binary for a package that is NOT
// itself package main was measured to omit its module dependency list on
// this toolchain (internal/scancmd's own test binary is not package main;
// this one is).
func buildGoBinaryRunSeamDB(t *testing.T, dir string) {
	t.Helper()
	dbPath := filepath.Join(dir, "vulnerability.db")
	w, err := store.Create(dbPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(advisory.Advisory{
		ID:   "GHSA-binary-seam",
		Kind: advisory.KindVulnerability,
		Affected: []advisory.Affected{{
			Ecosystem: "Go",
			Name:      "go.etcd.io/bbolt",
			Ranges: []advisory.Range{{
				Type:   advisory.RangeSemver,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "99.0.0"}},
			}},
		}},
		Severity: []advisory.Severity{
			// critical, 9.8 - the same vector pinned against its exact band
			// and score in internal/matcher/matcher_test.go.
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestRun_ScanGoBinaryTargetReachesRealExitCode is the run()-seam wiring
// check for a go-binary target - the counterpart of
// TestRun_ScanFlagsReachRealExitCode for the SBOM path. parseScanArgs proves
// --fail-on parses (TestParseScanArgs); scancmd's own
// TestRun_GatesApplyToBinaryAndDirectoryTargets proves scancmd.Run honours it
// for a go-binary target; neither one catches main.go silently dropping
// opts.FailOn, or routing the wrong string, on the way between them - e.g.
// `scancmd.Run(ctx, path, target, scancmd.Options{}, stdout, stderr)`,
// dropping opts entirely, type-checks and leaves both of those suites green.
// This drives run() itself, with a real "file:" target and a real finding, so
// a dropped field turns this exact case red rather than passing by
// coincidence.
func TestRun_ScanGoBinaryTargetReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)
	buildGoBinaryRunSeamDB(t, dir)

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	target := "file:" + self

	t.Run("no flags: a real finding is present but does not change the exit code alone", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"scan", target}
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Errorf("run(%v) = %d, want %d\nstdout:\n%s\nstderr:\n%s",
				args, code, exitOK, stdout.String(), stderr.String())
		}
	})

	t.Run("--fail-on critical reaches scancmd.Run through run() for a go-binary target", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		args := []string{"scan", target, "--fail-on", "critical"}
		if code := run(args, &stdout, &stderr); code != exitFindings {
			t.Errorf("run(%v) = %d, want %d (exitFindings)\nstdout:\n%s\nstderr:\n%s",
				args, code, exitFindings, stdout.String(), stderr.String())
		}
	})
}

// TestRun_ScanExplainConflictsWithOutputJSONExits2 is the run()-level
// version of TestParseScanArgs' "cannot be combined" case: the CLI contract
// end to end, exit 2 with stdout untouched, not just a non-nil error from
// parseScanArgs in isolation.
func TestRun_ScanExplainConflictsWithOutputJSONExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "docker-archive:/does/not/exist.tar",
		"--explain", "GHSA-1", "--output", "json"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)\nstderr:\n%s", code, exitError, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--explain") || !strings.Contains(stderr.String(), "--output") {
		t.Errorf("stderr = %q, want it to name both conflicting flags", stderr.String())
	}
}

// TestNVDOptionsFromEnv_PassesAPIKeyThrough: `db update` reads NVD_API_KEY
// from the environment and must actually forward it into the Options the
// annotator is built from, not just read it and drop it (D27: "the provider
// must never read the environment itself - that is why it takes an
// option"). This is the one seam that proves the forwarding without a real
// `db update` run, which would either make a live network call to NVD or
// need a second, test-only BaseURL override just to avoid one.
func TestNVDOptionsFromEnv_PassesAPIKeyThrough(t *testing.T) {
	t.Run("key set", func(t *testing.T) {
		t.Setenv("NVD_API_KEY", "test-key-123")
		if got := nvdOptionsFromEnv(io.Discard); got.APIKey != "test-key-123" {
			t.Errorf("nvdOptionsFromEnv().APIKey = %q, want %q", got.APIKey, "test-key-123")
		}
	})
	// No key is a normal, fully supported configuration (D27: "never
	// required"), so the zero value must round-trip too, not just a set one.
	t.Run("key unset", func(t *testing.T) {
		t.Setenv("NVD_API_KEY", "")
		if got := nvdOptionsFromEnv(io.Discard); got.APIKey != "" {
			t.Errorf("nvdOptionsFromEnv().APIKey = %q, want empty when NVD_API_KEY is unset", got.APIKey)
		}
	})
}

// A rejected NVD_SINCE_DAYS silently produced a seven-hour full sync, which
// is the opposite of what setting a window asks for and gave no clue why. It
// says so now. Both directions matter: a value that cannot be used at all,
// and one that is quietly reduced.
func TestNVDOptionsFromEnv_SaysWhyItIgnoredOrCappedTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		wantSince   bool   // did a window survive at all?
		wantWarn    string // a distinctive fragment of the warning
	}{
		{"unparseable", "30d", false, "not a positive number"},
		{"zero", "0", false, "not a positive number"},
		{"negative", "-5", false, "not a positive number"},
		{"over the API maximum", "365", true, "exceeds the API's 120-day maximum"},
		{"accepted", "30", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NVD_SINCE_DAYS", tc.value)
			var errOut bytes.Buffer
			got := nvdOptionsFromEnv(&errOut)

			if gotSince := !got.Since.IsZero(); gotSince != tc.wantSince {
				t.Errorf("Since set = %v, want %v", gotSince, tc.wantSince)
			}
			if tc.wantWarn == "" {
				if errOut.Len() != 0 {
					t.Errorf("stderr = %q, want nothing for an accepted value", errOut.String())
				}
				return
			}
			if !strings.Contains(errOut.String(), tc.wantWarn) {
				t.Errorf("stderr = %q, want it to contain %q", errOut.String(), tc.wantWarn)
			}
			// The value is echoed so the warning names what was actually
			// set, not just that something was wrong with it.
			if !strings.Contains(errOut.String(), tc.value) {
				t.Errorf("stderr = %q, want it to quote the offending value %q", errOut.String(), tc.value)
			}
		})
	}

	// 365 days must not merely warn -- it must actually clamp. Asserting the
	// warning alone would pass on code that printed it and sent 365 anyway,
	// which the API rejects outright.
	t.Run("the cap is applied, not just announced", func(t *testing.T) {
		t.Setenv("NVD_SINCE_DAYS", "365")
		got := nvdOptionsFromEnv(io.Discard)
		days := int(time.Since(got.Since).Hours() / 24)
		if days < 119 || days > 121 {
			t.Errorf("Since is %d days ago, want ~120 (the value was capped in the message but not in Options)", days)
		}
	})
}

// nvd.Options.Progress must actually be connected to stderr.
//
// It was not, and that is how a run that spent 5h52m, hit a 503, retried
// four times and gave up reported "retries fired: 0" -- the notices went to
// io.Discard, which is what an unset Progress defaults to. The option was
// written for exactly this situation and then never wired, so the sync that
// most needed the output was the one that produced none.
//
// Asserted on identity, not on any message: what failed here was a
// connection, and nothing this test can trigger would make the provider
// emit a retry notice without a live NVD misbehaving.
func TestNVDOptionsFromEnv_ConnectsProgressToStderr(t *testing.T) {
	var errOut bytes.Buffer
	got := nvdOptionsFromEnv(&errOut)
	if got.Progress == nil {
		t.Fatal("Options.Progress is nil, so every retry notice goes to io.Discard")
	}
	if got.Progress != io.Writer(&errOut) {
		t.Errorf("Options.Progress = %v, want the stderr passed in", got.Progress)
	}
}

// NVD is opt-in. It ran unconditionally at first, which made a routine NIST
// 503 fatal to building any database at all -- dbcmd.Update deletes the
// half-built file when a configured annotator fails, correctly, so with no
// way to unconfigure NVD a user could not even rebuild the OSV-only database
// that worked the day before. It also moved the default cost of `db update`
// from minutes to about seven hours.
func TestDBUpdateAnnotators_NVDIsOptIn(t *testing.T) {
	// A key alone must NOT enable it: someone who exported NVD_API_KEY once
	// would otherwise get the seven hours without asking for them.
	t.Setenv("NVD_API_KEY", "spy-key-1")
	t.Setenv("NVD_ENABLE", "")

	orig := newNVDAnnotator
	sawCall := false
	newNVDAnnotator = func(opts nvd.Options) *nvd.Provider { sawCall = true; return orig(opts) }
	defer func() { newNVDAnnotator = orig }()

	if got := dbUpdateAnnotators(io.Discard); len(got) != 0 {
		t.Errorf("dbUpdateAnnotators() = %+v, want none without NVD_ENABLE", got)
	}
	if sawCall {
		t.Error("nvd.New was constructed even though NVD_ENABLE was unset")
	}
}

// TestDBUpdateAnnotators_ConstructsNVDWithTheAPIKeyFromEnv closes the gap
// TestNVDOptionsFromEnv_PassesAPIKeyThrough cannot: that test only proves
// nvdOptionsFromEnv reads NVD_API_KEY correctly in isolation, never that the
// "db update" call site actually threads its result into the constructed
// annotator. Mutating the call site to `nvd.New(nvd.Options{})` — dropping
// the argument while keeping the import and the call — compiles, and left
// every other test in this package (and the whole suite) green. This
// substitutes newNVDAnnotator with a spy so the actual Options nvd.New would
// have received is observable directly, without dbUpdateAnnotators (or `db
// update` itself) ever calling Annotate and reaching the real network
// nvd.New's BaseURL defaults to.
func TestDBUpdateAnnotators_ConstructsNVDWithTheAPIKeyFromEnv(t *testing.T) {
	t.Setenv("NVD_API_KEY", "spy-key-1")
	t.Setenv("NVD_ENABLE", "1")

	var gotOpts nvd.Options
	sawCall := false
	orig := newNVDAnnotator
	newNVDAnnotator = func(opts nvd.Options) *nvd.Provider {
		gotOpts, sawCall = opts, true
		return orig(opts)
	}
	defer func() { newNVDAnnotator = orig }()

	annotators := dbUpdateAnnotators(io.Discard)

	if !sawCall {
		t.Fatal("dbUpdateAnnotators never constructed an NVD annotator")
	}
	if gotOpts.APIKey != "spy-key-1" {
		t.Errorf("nvd.New was called with APIKey %q, want %q (NVD_API_KEY was not threaded through)",
			gotOpts.APIKey, "spy-key-1")
	}
	if len(annotators) != 1 || annotators[0].Name() != nvd.SourceName {
		t.Errorf("dbUpdateAnnotators() = %+v, want exactly one NVD annotator", annotators)
	}
}

// `db build` is the source-building command; `db update` downloads the
// published database (D28) instead of building it. This proves `build` is
// still routed, and that `update` reaches Pull -- not a silent build, and
// not the Task 1 placeholder -- without ever making a live call to the
// default ghcr.io ref: `--from` points at an address nothing listens on,
// the same unreachable-registry fixture internal/dbcmd's own Push/Pull
// tests use, so the routing proof needs no network.
func TestRun_DBBuildReplacesUpdate(t *testing.T) {
	t.Run("build is a known subcommand", func(t *testing.T) {
		// Pointed at a directory that cannot be created: `blocker` is a
		// regular file, so MkdirAll on a path beneath it fails. Update
		// creates the database directory BEFORE it touches a provider, so
		// this returns immediately.
		//
		// That precaution is the whole reason this subtest is written this
		// way. The first version just called `db build` and asserted on the
		// error -- and with ASSAY_DB_DIR unset, store.DefaultPath resolves
		// to the user's real cache, so the test performed an actual build:
		// ~200 MB fetched from the live OSV endpoint, 183 seconds, and the
		// developer's real database overwritten by `go test ./...`. A
		// routing assertion must not be able to do that.
		blocker := filepath.Join(t.TempDir(), "blocker")
		if err := os.WriteFile(blocker, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ASSAY_DB_DIR", filepath.Join(blocker, "sub"))

		var stdout, stderr bytes.Buffer
		run([]string{"db", "build"}, &stdout, &stderr)
		if strings.Contains(stderr.String(), "unknown db subcommand") {
			t.Errorf("db build is not routed:\n%s", stderr.String())
		}
	})

	t.Run("update reaches Pull, not a silent build", func(t *testing.T) {
		// ASSAY_DB_DIR is set even though this path is never written to
		// (Pull's MkdirAll runs after the schema check, which this never
		// reaches): store.DefaultPath is still called unconditionally for
		// every db subcommand, and leaving it unset would resolve to the
		// developer's real cache.
		t.Setenv("ASSAY_DB_DIR", t.TempDir())

		var stdout, stderr bytes.Buffer
		code := run([]string{"db", "update", "--from", "127.0.0.1:1/assay-db:v6"}, &stdout, &stderr)
		if code != exitError {
			t.Errorf("db update against an unreachable registry = %d, want %d\nstderr:\n%s",
				code, exitError, stderr.String())
		}
		if strings.Contains(stderr.String(), "unknown db subcommand") {
			t.Errorf("db update is not routed:\n%s", stderr.String())
		}
		if strings.Contains(stderr.String(), "not wired up yet") {
			t.Errorf("db update is still the Task 1 placeholder:\n%s", stderr.String())
		}
		// Fix round 1: the three checks above are all negative -- replacing
		// this case's body with `case "build":`'s call to dbcmd.Update
		// (dropping the environment's real OSV/NVD network calls aside, which
		// nothing here would observe either) still exits 2 on a provider
		// failure and says neither forbidden string, so "not a silent build"
		// was not actually held. dbcmd.Pull is the only function in the
		// codebase that writes this exact "fetching <ref>…" line
		// (internal/dbcmd/pull.go) -- dbcmd.Update's own progress lines name
		// a provider or annotator instead -- so this is positive proof of
		// which function ran, not just an absence of the wrong strings.
		if !strings.Contains(stderr.String(), "fetching 127.0.0.1:1/assay-db:v6") {
			t.Errorf("stderr does not show Pull's own fetch line, so update may not be "+
				"reaching Pull at all:\n%s", stderr.String())
		}
	})
}

// `db build --seed <ref>` must reach Pull, and a Pull failure must fail the
// whole build rather than falling through to a from-empty build -- the
// scheduled builder passes --seed every night, so a registry outage has to
// be loud (Task 5's whole point). 127.0.0.1:1 is a loopback address nothing
// listens on, the same unreachable-registry fixture internal/dbcmd's own
// Push/Pull tests and TestRun_DBBuildReplacesUpdate use, so this needs no
// network.
//
// ASSAY_DB_DIR is pointed under a regular file so MkdirAll beneath it can
// never succeed -- not to make the assertion pass, but to make the negative
// assertion below SAFE: if a bug fell through to dbcmd.Update after a
// failed seed, Update's own first step (MkdirAll on this same path) would
// fail immediately instead of reaching a live OSV fetch, which is exactly
// the "a routing test must not be able to perform a real build"
// precaution TestRun_DBBuildReplacesUpdate's own comment explains.
func TestRun_DBBuildWithSeedFailsRatherThanBuildingFromEmpty(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASSAY_DB_DIR", filepath.Join(blocker, "sub"))

	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "build", "--seed", "127.0.0.1:1/assay-db:v6"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("db build --seed against an unreachable registry = %d, want %d\nstderr:\n%s",
			code, exitError, stderr.String())
	}
	// Positive proof Pull ran at all: dbcmd.Pull is the only function that
	// writes this exact "fetching <ref>…" line (dbcmd.Update's own progress
	// lines name a provider or annotator instead).
	if !strings.Contains(stderr.String(), "fetching 127.0.0.1:1/assay-db:v6") {
		t.Errorf("stderr does not show Pull's own fetch line, so --seed may not be reaching Pull at all:\n%s", stderr.String())
	}
	// If dbcmd.Update ran despite the failed seed, ITS OWN MkdirAll (against
	// the same blocked ASSAY_DB_DIR) would have printed this exact message
	// -- so its absence is positive proof Update was never reached, not
	// just that the build also failed for some unrelated reason.
	if strings.Contains(stderr.String(), "create database directory") {
		t.Errorf("dbcmd.Update ran even though the seed could not be read -- a seed "+
			"failure must fail the whole build, never fall back to building from empty:\n%s", stderr.String())
	}
}

// resolveBuildSeed mirrors resolveUpdateRef's own test shape and reasoning
// (see TestResolveUpdateRef's doc comment): driven directly, never through
// run(), so a validation bug here is provable without ever letting
// execution reach dbcmd.Pull with a ref this test does not control.
func TestResolveBuildSeed(t *testing.T) {
	t.Run("no --seed builds from empty, as today", func(t *testing.T) {
		var stderr bytes.Buffer
		ref, has, ok := resolveBuildSeed([]string{"db", "build"}, &stderr)
		if !ok {
			t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
		}
		if has {
			t.Error("has = true, want false: no --seed means build from empty")
		}
		if ref != "" {
			t.Errorf("ref = %q, want empty", ref)
		}
	})

	t.Run("--seed <ref> is carried through", func(t *testing.T) {
		var stderr bytes.Buffer
		ref, has, ok := resolveBuildSeed([]string{"db", "build", "--seed", "example.test/assay-db:v6"}, &stderr)
		if !ok {
			t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
		}
		if !has {
			t.Error("has = false, want true: --seed was given")
		}
		if ref != "example.test/assay-db:v6" {
			t.Errorf("ref = %q, want the explicit --seed value", ref)
		}
	})

	t.Run("--seed with no value is rejected, not a silent from-empty build", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _, ok := resolveBuildSeed([]string{"db", "build", "--seed"}, &stderr)
		if ok {
			t.Error("ok = true, want false: --seed with no value must not silently build from empty")
		}
		if !strings.Contains(stderr.String(), "--seed requires a reference") {
			t.Errorf("stderr does not say --seed needs a value:\n%s", stderr.String())
		}
	})

	t.Run("an unrecognized flag is rejected, not silently ignored", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _, ok := resolveBuildSeed([]string{"db", "build", "--seeed", "example.test/assay-db:v6"}, &stderr)
		if ok {
			t.Error("ok = true, want false: a typo'd flag must not silently build from empty")
		}
		if !strings.Contains(stderr.String(), `unknown db build flag "--seeed"`) {
			t.Errorf("stderr does not name the unrecognized flag:\n%s", stderr.String())
		}
	})
}

// Fix round 1, finding 2: `db update --from` with a missing value, or a
// typo'd flag name, silently fell back to the default ref -- exactly wrong
// for an air-gapped or mirror-pinned user, who set --from specifically to
// avoid the public default. Driven directly against resolveUpdateRef, not
// through run(), because a validation bug here would otherwise only be
// provable by a test that lets execution reach dbcmd.Pull with the real
// default ghcr.io ref -- an actual network call, which this environment can
// in fact make (the codebase's own history: an unguarded ASSAY_DB_DIR once
// let a routing test perform a live ~200 MB OSV fetch). resolveUpdateRef
// itself never touches the network, so every case below is safe regardless
// of what it returns.
func TestResolveUpdateRef(t *testing.T) {
	t.Run("no --from uses the default, schema-derived ref", func(t *testing.T) {
		var stderr bytes.Buffer
		ref, ok := resolveUpdateRef([]string{"db", "update"}, &stderr)
		if !ok {
			t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
		}
		want := dbcmd.Ref(dbcmd.DefaultRef)
		if ref != want {
			t.Errorf("ref = %q, want %q", ref, want)
		}
	})

	t.Run("--from <ref> overrides the default", func(t *testing.T) {
		var stderr bytes.Buffer
		ref, ok := resolveUpdateRef([]string{"db", "update", "--from", "example.test/mirror:v6"}, &stderr)
		if !ok {
			t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
		}
		if ref != "example.test/mirror:v6" {
			t.Errorf("ref = %q, want the explicit --from value", ref)
		}
	})

	t.Run("--from with no value is rejected, not a silent default", func(t *testing.T) {
		var stderr bytes.Buffer
		_, ok := resolveUpdateRef([]string{"db", "update", "--from"}, &stderr)
		if ok {
			t.Error("ok = true, want false: --from with no value must not silently resolve to the default ref")
		}
		if !strings.Contains(stderr.String(), "--from requires a reference") {
			t.Errorf("stderr does not say --from needs a value:\n%s", stderr.String())
		}
	})

	t.Run("an unrecognized third argument is rejected, not silently ignored", func(t *testing.T) {
		var stderr bytes.Buffer
		_, ok := resolveUpdateRef([]string{"db", "update", "--form", "example.test/mirror:v6"}, &stderr)
		if ok {
			t.Error("ok = true, want false: a typo'd flag must not silently fall back to the default ref")
		}
		if !strings.Contains(stderr.String(), `unknown db update flag "--form"`) {
			t.Errorf("stderr does not name the unrecognized flag:\n%s", stderr.String())
		}
	})
}

// Fix round 2, finding 3: TestResolveUpdateRef drives resolveUpdateRef
// directly and never calls run(), so it cannot catch a mutation in
// case "update":'s own dispatch -- e.g. `return exitOK` in place of
// `return exitError` when resolveUpdateRef reports !ok. This closes that
// gap end to end. Safe to run through the real dispatch (unlike a similar
// check for the SUCCESS path, see resolveUpdateRef's own doc comment):
// resolveUpdateRef returns ok=false before case "update": ever reaches
// dbcmd.Pull, so this never touches the network regardless of what
// case "update": does with the result.
func TestRun_DBUpdateFromRejectionReachesExitError(t *testing.T) {
	t.Setenv("ASSAY_DB_DIR", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "update", "--from"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("db update --from (no value) via run() = %d, want %d\nstderr:\n%s",
			code, exitError, stderr.String())
	}
}

// `db ref` is what a CI workflow reads to know which tag `db push` should
// publish to, so the artifact's tag comes from the binary rather than a
// literal duplicated in the workflow (which would keep publishing to the
// old tag after a schema bump). Asserted against store.SchemaVersion, not a
// hardcoded "v6": this test must keep passing across a schema bump with no
// edit here, the same way the workflow itself needs no edit.
//
// want is built from fmt.Sprintf directly, not by calling dbcmd.Ref: doing
// the latter would launder a mutation to Ref's own format string right back
// into this assertion (Ref(DefaultRef) as both the input and the oracle
// always agree with itself). And the comparison is exact equality on the
// trimmed line, not strings.Contains: "v6" is a substring of a mutated
// "v6-nope", so a Contains check here would still pass against the exact
// defect dbcmd's own TestRef_EndsInTheCurrentSchemaVersion exists to catch --
// confirmed by running this test against that mutation before switching to
// equality, which passed when it should not have.
func TestRun_DBRefPrintsTheCurrentSchemaTag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "ref"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("db ref = %d, want %d\nstderr:\n%s", code, exitOK, stderr.String())
	}
	want := fmt.Sprintf("%s:v%d", dbcmd.DefaultRef, store.SchemaVersion)
	got := strings.TrimSpace(stdout.String())
	if got != want {
		t.Errorf("stdout = %q, want exactly %q", got, want)
	}
	if stderr.Len() != 0 {
		t.Errorf("db ref wrote a diagnostic for a clean run: %q", stderr.String())
	}
}

// Finding 2 of the final review: `db push` had no routing test at all --
// `build`, `update` and `ref` each had one, and replacing
// `return dbcmd.Push(...)` with `return exitOK` in case "push" left the
// whole suite green. ASSAY_DB_DIR points at an empty temp directory holding
// no database file, so dbcmd.Push's own os.Stat fails before it ever
// touches the network (mirroring TestRun_DBBuildReplacesUpdate's precaution
// against a routing test performing a real network operation) with a
// message unique to Push -- positive proof push reached it, not just an
// absence of "unknown db subcommand".
func TestRun_DBPushRoutesToPush(t *testing.T) {
	t.Setenv("ASSAY_DB_DIR", t.TempDir())

	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "push", "example.test/assay-db:v6"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("db push with no local database = %d, want %d\nstderr:\n%s", code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no database at") {
		t.Errorf("stderr does not show Push's own missing-database message, so push may not be "+
			"reaching dbcmd.Push at all:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "unknown db subcommand") {
		t.Errorf("db push is not routed:\n%s", stderr.String())
	}
}

// resolvePushRef mirrors resolveUpdateRef's own test shape and reasoning:
// driven directly, never through run(), so validation is provable without
// ever letting execution reach dbcmd.Push.
func TestResolvePushRef(t *testing.T) {
	t.Run("a bare reference is accepted", func(t *testing.T) {
		var stderr bytes.Buffer
		ref, _, ok := resolvePushRef([]string{"db", "push", "example.test/assay-db:v6"}, &stderr)
		if !ok {
			t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
		}
		if ref != "example.test/assay-db:v6" {
			t.Errorf("ref = %q, want the given reference", ref)
		}
	})

	t.Run("no reference is rejected", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _, ok := resolvePushRef([]string{"db", "push"}, &stderr)
		if ok {
			t.Error("ok = true, want false: db push needs a reference")
		}
		if !strings.Contains(stderr.String(), "db push needs a reference") {
			t.Errorf("stderr does not say push needs a reference:\n%s", stderr.String())
		}
	})

	// db push accepting trailing junk while db update rejects it
	// (resolveUpdateRef) was the inconsistency the final review flagged --
	// a reference typo followed by a stray argument must not silently
	// publish to the first token while dropping the second.
	t.Run("a trailing argument is rejected, not silently ignored", func(t *testing.T) {
		var stderr bytes.Buffer
		_, _, ok := resolvePushRef([]string{"db", "push", "example.test/assay-db:v6", "extra"}, &stderr)
		if ok {
			t.Error("ok = true, want false: db push takes exactly one reference")
		}
		if !strings.Contains(stderr.String(), `unexpected argument "extra"`) {
			t.Errorf("stderr does not name the unexpected argument:\n%s", stderr.String())
		}
	})
}

// End-to-end version of the trailing-argument rejection above: proves the
// "push" case in run() actually calls resolvePushRef rather than some other
// validation (or none). Safe through the real dispatch because
// resolvePushRef rejects before dbcmd.Push is ever reached, so this never
// touches the network regardless of what case "push" does with the result.
func TestRun_DBPushRejectsTrailingArgument(t *testing.T) {
	t.Setenv("ASSAY_DB_DIR", t.TempDir())

	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "push", "example.test/assay-db:v6", "extra"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("db push with a trailing argument = %d, want %d\nstderr:\n%s", code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unexpected argument "extra"`) {
		t.Errorf("stderr does not name the unexpected argument:\n%s", stderr.String())
	}
}
