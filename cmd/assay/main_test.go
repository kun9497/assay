package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
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
		if got := nvdOptionsFromEnv(); got.APIKey != "test-key-123" {
			t.Errorf("nvdOptionsFromEnv().APIKey = %q, want %q", got.APIKey, "test-key-123")
		}
	})
	// No key is a normal, fully supported configuration (D27: "never
	// required"), so the zero value must round-trip too, not just a set one.
	t.Run("key unset", func(t *testing.T) {
		t.Setenv("NVD_API_KEY", "")
		if got := nvdOptionsFromEnv(); got.APIKey != "" {
			t.Errorf("nvdOptionsFromEnv().APIKey = %q, want empty when NVD_API_KEY is unset", got.APIKey)
		}
	})
}
