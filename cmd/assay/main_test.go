package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/provider/amazon"
	"github.com/kun9497/assay/internal/provider/fedora"
	"github.com/kun9497/assay/internal/provider/knvd"
	"github.com/kun9497/assay/internal/provider/nvd"
	"github.com/kun9497/assay/internal/provider/oracle"
	"github.com/kun9497/assay/internal/provider/redhat"
	"github.com/kun9497/assay/internal/provider/suse"
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
		// D48. Not part of the pair above but parsed in the same switch, and
		// without this a case arm that accepted the flag and dropped it on the
		// floor left the whole suite green.
		if opts.FailOnUnfixable {
			t.Error("opts.FailOnUnfixable = true, but --fail-on-unfixable was not given")
		}
	})

	t.Run("all three flags plus the target, mixed order", func(t *testing.T) {
		target, opts, err := parseScanArgs([]string{
			"--fail-on-incomplete", "alpine:3.19", "--fail-on", "medium", "--fail-on-unknown",
			"--fail-on-unfixable",
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
		if !opts.FailOnUnknown || !opts.FailOnIncomplete || !opts.FailOnUnfixable {
			t.Errorf("opts = %+v, want every bool gate true", opts)
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

	// The example used to be "sarif", which D55 then implemented — so this
	// guard failed the moment the format landed, which is exactly what it is
	// for. Replaced with a format nothing plans to add rather than deleted.
	t.Run("an invalid --output value is an error naming what is accepted", func(t *testing.T) {
		_, _, err := parseScanArgs([]string{"alpine:3.19", "--output", "cyclonedx"})
		if err == nil {
			t.Fatal("err = nil, want an error for an unsupported output format")
		}
		for _, want := range []string{"cyclonedx", "table", "json", "sarif"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, missing %q", err, want)
			}
		}
	})

	// D55. The accepted list is a switch, so a format missing from it is inert
	// rather than loud — the flag parses and the default renderer runs.
	t.Run("--output sarif selects the sarif renderer", func(t *testing.T) {
		for _, in := range []string{"sarif", "SARIF", "Sarif"} {
			_, opts, err := parseScanArgs([]string{"alpine:3.19", "--output", in})
			if err != nil {
				t.Fatalf("parseScanArgs(--output %s): %v", in, err)
			}
			if opts.Output != "sarif" {
				t.Errorf("--output %s gave Output = %q, want sarif", in, opts.Output)
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
// CycloneDX SBOM naming four packages, so that all four --fail-on* gates
// have something to fire on simultaneously:
//
//   - "critical": a critical-severity finding (for --fail-on).
//   - "unknownsev": a finding whose advisory carries no CVSS vector at all,
//     so severity.Highest reports it Unknown (for --fail-on-unknown).
//   - "somecrate": a cargo purl, an unsupported ecosystem type the cataloger
//     drops before the matcher ever sees it, so report.Summary.NotEvaluated
//     is > 0 (for --fail-on-incomplete).
//   - "nofix": a RATED finding whose range never closes, so no source names a
//     version to upgrade to (for --fail-on-unfixable, D48). Rated on purpose:
//     an unrated one would trip --fail-on-unknown too and the two gates could
//     not be isolated from each other.
//
// All four conditions are present unconditionally; only which flag is set
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
		{
			ID:   "GHSA-nofix",
			Kind: advisory.KindVulnerability,
			Affected: []advisory.Affected{{
				Ecosystem: "Go",
				Name:      "example.com/nofix",
				// An introduced event and NOTHING else: affected at every
				// version, with nothing to upgrade to (D48). This is the shape
				// Red Hat's CSAF VEX feed publishes 1,278,384 times, spelled
				// here against a Go package so the fixture stays one ecosystem.
				Ranges: []advisory.Range{{
					Type:   advisory.RangeSemver,
					Events: []advisory.Event{{Introduced: "0"}},
				}},
			}},
			// Rated, deliberately: an unrated one would also trip
			// --fail-on-unknown and the two gates could not be told apart.
			Severity: []advisory.Severity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
			},
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
		`{"type":"library","name":"nofix","version":"1.0.0","purl":"pkg:golang/example.com/nofix@1.0.0"},` +
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
		{"--fail-on-unfixable reaches scancmd.Run through run()",
			[]string{"--fail-on-unfixable"}, exitFindings},
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

// TestRun_ScanDBMaxAgeReachesRealExitCode is the run()-seam wiring check for
// --db-max-age, which had none: main_test.go never mentioned the flag, and
// scancmd's own dbage_test.go drives scancmd.Run with Options{DBMaxAge: ...}
// built by hand, holding checkDBAge and Run's own consultation of it but
// never the parseScanArgs assignment (opts.DBMaxAge = d) one hop earlier.
// Dropping that assignment lets `assay scan --db-max-age=48h` parse cleanly
// and silently perform no age check at all -- a stale database would read as
// trustworthy, exactly the D59 hazard this flag exists to catch.
//
// store.DefaultPath honours ASSAY_DB_DIR (internal/store/store.go), the same
// seam TestRun_ScanFlagsReachRealExitCode uses to point the real lookup path
// at a temp dir without a database-path parameter on run() itself.
func TestRun_ScanDBMaxAgeReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)

	dbPath := filepath.Join(dir, "vulnerability.db")
	w, err := store.Create(dbPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Ancient but with coverage declared, so a refusal can only be the age
	// check firing, never D20's separate "nothing covers this ecosystem" gate.
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Go"}, DataAsOf: time.Now().AddDate(0, 0, -400)},
	}}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	sbom := filepath.Join(dir, "s.cdx.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"x","version":"1.0.0","purl":"pkg:golang/example.com/x@1.0.0"}]}`
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"scan", sbom, "--db-max-age=1h"}
	if code := run(args, &stdout, &stderr); code != exitError {
		t.Fatalf("run(%v) = %d, want %d (exitError) -- the database is 400 days old\n"+
			"stdout:\n%s\nstderr:\n%s", args, code, exitError, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "db-max-age") {
		t.Errorf("stderr does not mention the flag that refused the scan:\n%s", stderr.String())
	}
	// A verdict printed before the refusal would be a result from data the
	// next line calls untrustworthy.
	if stdout.Len() != 0 {
		t.Errorf("a refused scan wrote a report to stdout:\n%s", stdout.String())
	}

	// The same ancient database, with no --db-max-age at all, still scans --
	// proving the exit above came from the flag reaching Options.DBMaxAge,
	// not from something else about this fixture.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", sbom}, &stdout, &stderr); code != exitOK {
		t.Errorf("run without --db-max-age = %d, want %d (exitOK)\nstderr:\n%s",
			code, exitOK, stderr.String())
	}
}

// TestRun_ScanFailOnIncompleteTargetReachesRealExitCode is the run()-seam
// wiring check for --fail-on-incomplete=target. TestParseScan_FailOnIncompleteScopes
// proves parseScanArgs sets Options.FailOnIncompleteTarget correctly, and
// scancmd's own TestVerdict_FailOnIncompleteTargetIgnoresAdvisoryDefects (plus
// dirscan_wiring's "an unpinned requirement is the caller's to fix" subtest)
// prove scancmd.Run honours it -- but both stop at hand-built Options, and
// scan() sits between them setting opts.Version right where it could as
// easily zero the field: `opts.Version = version; opts.FailOnIncompleteTarget
// = false` type-checks and leaves both suites green, exactly the class of bug
// TestRun_ScanFlagsReachRealExitCode exists to catch for the other three
// --fail-on* gates. An unpinned requirements.txt line is the caller's own
// file (D36), not a coverage gap, so it trips the narrow gate without the
// database needing to cover anything at all.
func TestRun_ScanFailOnIncompleteTargetReachesRealExitCode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ASSAY_DB_DIR", dir)

	dbPath := filepath.Join(dir, "vulnerability.db")
	w, err := store.Create(dbPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Coverage declared for Go, so the go.mod package below is evaluated
	// (zero findings) rather than itself becoming a whole-package coverage
	// skip -- otherwise sum.Trustworthy() would be false regardless of the
	// flag under test, and the exit code would prove nothing about it.
	if err := w.SetMeta(store.Meta{
		Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Go"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	scanDir := filepath.Join(dir, "target")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scanDir, "go.mod"),
		[]byte("module example.com/poly\n\ngo 1.22\n\nrequire example.com/critical v1.0.0\n"),
		0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// An unpinned requirement is the caller's own file (D36), not a coverage
	// gap, so it trips the narrow gate on its own -- but only alongside an
	// evaluated package, or sum.Trustworthy() being false would exit 2 on
	// every row regardless of --fail-on-incomplete=target.
	if err := os.WriteFile(filepath.Join(scanDir, "requirements.txt"),
		[]byte("flask>=2.0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"scan", "dir:" + scanDir, "--fail-on-incomplete=target"}
	if code := run(args, &stdout, &stderr); code != exitError {
		t.Fatalf("run(%v) = %d, want %d (exitError) -- an unpinned requirement "+
			"is exactly the target-scope incompleteness this flag exists to catch\n"+
			"stdout:\n%s\nstderr:\n%s", args, code, exitError, stdout.String(), stderr.String())
	}

	// The same directory, with no --fail-on-incomplete at all, still scans
	// clean -- proving the exit above came from the flag reaching
	// Options.FailOnIncompleteTarget, not from something else about this
	// fixture.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", "dir:" + scanDir}, &stdout, &stderr); code != exitOK {
		t.Errorf("run without the flag = %d, want %d (exitOK)\nstderr:\n%s",
			code, exitOK, stderr.String())
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
	// Pinned, not read from the package: a constant compared against itself
	// cannot notice that the shape changed under it. Bumping this is meant to
	// be the deliberate act that accompanies a schema change (D33 was the
	// third).
	if doc.SchemaVersion != 6 {
		t.Errorf("SchemaVersion = %d, want 6", doc.SchemaVersion)
	}
	// buildRunSeamFixture's critical, unrated and no-fix findings; somecrate
	// is dropped by the cataloger and never reaches a Finding at all.
	if len(doc.Findings) != 3 {
		t.Errorf("Findings = %d, want 3\nstdout:\n%s", len(doc.Findings), stdout.String())
	}
	// D48 reaches the document, and on exactly one of the three. A field that
	// was always false would satisfy every other assertion here.
	unfixable := 0
	for _, f := range doc.Findings {
		if f.Unfixable {
			unfixable++
		}
	}
	if unfixable != 1 {
		t.Errorf("findings with unfixable=true = %d, want 1\nstdout:\n%s", unfixable, stdout.String())
	}
	if doc.Summary.Unfixable != 1 {
		t.Errorf("summary.unfixable = %d, want 1", doc.Summary.Unfixable)
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

// NVD_UNTIL_DAYS (D65) sets the LATE end of a backfill window. Driven through
// nvdOptionsFromEnv, the caller, rather than nvdUntilFromEnv directly: the
// project rule is that a helper's own test proves nothing about whether
// anything calls it, and nvdOptionsFromEnv is the only thing that does
// (CLAUDE.md, "the helper is covered; nothing calls it").
//
// The "equal to since" case is the one that matters. nvdUntilFromEnv refuses
// an until that is not strictly after since with `if !until.After(since)`.
// Flip that guard to `if false && ...` and every other case here still
// passes -- unequal windows never exercise the boundary -- so it is the one
// case that must set since==until exactly and demand the refusal fires.
func TestNvdOptionsFromEnv_UntilDays(t *testing.T) {
	cases := []struct {
		name string
		// "" means the variable is left unset.
		since, until string
		wantZero     bool // opts.Until must be the zero time.Time
		wantAgoDays  int  // when !wantZero, opts.Until must land here, within a minute
		wantWarn     []string
		wantNoWarn   bool // stderr must be empty
	}{
		{
			name:        "until inside the window is accepted",
			since:       "30",
			until:       "7",
			wantZero:    false,
			wantAgoDays: 7,
			wantNoWarn:  true,
		},
		{
			// THE KEY CASE: since==until is not After, so this must be
			// refused. This is what catches `if !until.After(since)` being
			// mutated to `if false && ...`.
			name:     "until equal to since is refused",
			since:    "30",
			until:    "30",
			wantZero: true,
			wantWarn: []string{"NVD_UNTIL_DAYS", "not after NVD_SINCE_DAYS"},
		},
		{
			name:     "until before since is refused",
			since:    "30",
			until:    "60",
			wantZero: true,
			wantWarn: []string{"NVD_UNTIL_DAYS", "not after NVD_SINCE_DAYS"},
		},
		{
			name:     "unparseable until",
			since:    "30",
			until:    "abc",
			wantZero: true,
			// "not a number of days" alone also reads as a substring of
			// the SINCE warning's "not a positive number of days" in
			// spirit, so pin down which flag actually fired too.
			wantWarn: []string{"NVD_UNTIL_DAYS", "not a number of days"},
		},
		{
			// A negative count is days in the FUTURE: AddDate(0,0,-days)
			// flips its sign, the inverted-window check passes (a future
			// end IS after since), and CoversUntil then records a date
			// that has not happened — coverage claimed for time that does
			// not exist yet. Refused at parse, like the SINCE side.
			name:     "negative until is refused, not a future date",
			since:    "30",
			until:    "-5",
			wantZero: true,
			wantWarn: []string{"NVD_UNTIL_DAYS", "not a number of days"},
		},
		{
			// Doc comment on nvdUntilFromEnv: "Ignored when no Since was
			// given ... rather than the bounded slice the caller was
			// reaching for." nvdOptionsFromEnv returns before Since is even
			// computed, so NVD_UNTIL_DAYS is never read at all.
			name:       "until with no since is ignored",
			since:      "",
			until:      "7",
			wantZero:   true,
			wantNoWarn: true,
		},
		{
			name:       "since with no until leaves the window open",
			since:      "30",
			until:      "",
			wantZero:   true,
			wantNoWarn: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NVD_SINCE_DAYS", tc.since)
			t.Setenv("NVD_UNTIL_DAYS", tc.until)
			var errOut bytes.Buffer
			got := nvdOptionsFromEnv(&errOut)

			if gotZero := got.Until.IsZero(); gotZero != tc.wantZero {
				t.Errorf("Until.IsZero() = %v, want %v (Until = %v)", gotZero, tc.wantZero, got.Until)
			}
			if !tc.wantZero {
				wantApprox := time.Now().UTC().AddDate(0, 0, -tc.wantAgoDays)
				if diff := got.Until.Sub(wantApprox); diff < -time.Minute || diff > time.Minute {
					t.Errorf("Until = %v, want within a minute of %v (now minus %d days)", got.Until, wantApprox, tc.wantAgoDays)
				}
			}

			if tc.wantNoWarn && errOut.Len() != 0 {
				t.Errorf("stderr = %q, want nothing", errOut.String())
			}
			for _, frag := range tc.wantWarn {
				if !strings.Contains(errOut.String(), frag) {
					t.Errorf("stderr = %q, want it to contain %q", errOut.String(), frag)
				}
			}
		})
	}
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

// TestDBUpdateProviders_RedHatOnByDefault is the caller-first proof for
// D51's wiring: dbUpdateProviders must actually construct the Red Hat
// provider when REDHAT_ENABLE is unset, not merely have redhat.New sitting
// unused in the import list. Every other test in this file that sets
// REDHAT_ENABLE sets it to "0", to isolate Amazon/Oracle/Fedora/SUSE's own
// wiring from Red Hat's -- none of them observes Red Hat's OWN default-on
// behaviour, so nothing anywhere calls dbUpdateProviders with REDHAT_ENABLE
// left unset and checks Red Hat landed. Driven through a spy exactly as
// TestDBUpdateProviders_AmazonOnByDefault's own doc comment explains why:
// mutating the call site's default argument (or dropping the provider, or
// its Options) compiles and would leave every other test in this package
// green, since AMAZON_ENABLE=0/ORACLE_ENABLE=0/FEDORA_ENABLE=0/SUSE_ENABLE=0
// isolation in those tests leaves REDHAT_ENABLE at its own default either way.
func TestDBUpdateProviders_RedHatOnByDefault(t *testing.T) {
	t.Setenv("REDHAT_ENABLE", "")
	t.Setenv("AMAZON_ENABLE", "0") // isolate: only Red Hat's own wiring is under test here
	t.Setenv("ORACLE_ENABLE", "0")
	t.Setenv("FEDORA_ENABLE", "0")
	t.Setenv("SUSE_ENABLE", "0")

	orig := newRedHatProvider
	sawCall := false
	var gotOpts redhat.Options
	newRedHatProvider = func(opts redhat.Options) *redhat.Provider {
		sawCall, gotOpts = true, opts
		return orig(opts)
	}
	defer func() { newRedHatProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if !sawCall {
		t.Fatal("dbUpdateProviders never constructed the Red Hat provider -- REDHAT_ENABLE defaults ON (D51)")
	}
	if gotOpts.Progress == nil {
		t.Error("redhat.New was constructed with a nil Progress -- Fetch's own discard counts would go nowhere")
	}
	var found bool
	for _, p := range ps {
		if p.Name() == "Red Hat CSAF VEX" {
			found = true
		}
	}
	if !found {
		t.Errorf("dbUpdateProviders() = %+v, want it to include the Red Hat provider", ps)
	}
}

// TestDBUpdateProviders_RedHatDisabledViaEnv is the other half: REDHAT_ENABLE=0
// must actually turn the fetch off, not merely be read and ignored -- the
// silent-drop direction every OTHER provider's test in this file already
// pins for its own flag, with Red Hat's used only as the isolating value.
func TestDBUpdateProviders_RedHatDisabledViaEnv(t *testing.T) {
	t.Setenv("REDHAT_ENABLE", "0")

	orig := newRedHatProvider
	sawCall := false
	newRedHatProvider = func(opts redhat.Options) *redhat.Provider {
		sawCall = true
		return orig(opts)
	}
	defer func() { newRedHatProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if sawCall {
		t.Error("dbUpdateProviders constructed the Red Hat provider even with REDHAT_ENABLE=0")
	}
	for _, p := range ps {
		if p.Name() == "Red Hat CSAF VEX" {
			t.Errorf("dbUpdateProviders() = %+v, want no Red Hat provider with REDHAT_ENABLE=0", ps)
		}
	}
}

// TestDBUpdateProviders_AmazonOnByDefault is the caller-first proof for
// D73's wiring: dbUpdateProviders must actually construct the Amazon Linux
// provider when AMAZON_ENABLE is unset, not merely have amazon.New sitting
// unused in the import list. Driven through a spy exactly as
// TestDBUpdateAnnotators_ConstructsNVDWithTheAPIKeyFromEnv's own doc comment
// explains why: mutating the call site to drop the provider (or to drop its
// Options) compiles and would leave every other test in this package green.
func TestDBUpdateProviders_AmazonOnByDefault(t *testing.T) {
	t.Setenv("AMAZON_ENABLE", "")
	t.Setenv("REDHAT_ENABLE", "0") // isolate: only Amazon's own wiring is under test here
	t.Setenv("SUSE_ENABLE", "0")

	orig := newAmazonProvider
	sawCall := false
	var gotOpts amazon.Options
	newAmazonProvider = func(opts amazon.Options) *amazon.Provider {
		sawCall, gotOpts = true, opts
		return orig(opts)
	}
	defer func() { newAmazonProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if !sawCall {
		t.Fatal("dbUpdateProviders never constructed the Amazon Linux provider -- AMAZON_ENABLE defaults ON (D73)")
	}
	if gotOpts.Progress == nil {
		t.Error("amazon.New was constructed with a nil Progress -- Fetch's extras disclosure would go nowhere")
	}
	var found bool
	for _, p := range ps {
		if p.Name() == "Amazon Linux ALAS" {
			found = true
		}
	}
	if !found {
		t.Errorf("dbUpdateProviders() = %+v, want it to include the Amazon Linux provider", ps)
	}
}

// TestDBUpdateProviders_AmazonDisabledViaEnv is the other half: an operator
// who does not want to scan Amazon Linux must be able to turn the fetch off
// entirely, exactly as REDHAT_ENABLE=0 already lets them skip Red Hat's.
func TestDBUpdateProviders_AmazonDisabledViaEnv(t *testing.T) {
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("REDHAT_ENABLE", "0")
	t.Setenv("SUSE_ENABLE", "0")

	orig := newAmazonProvider
	sawCall := false
	newAmazonProvider = func(opts amazon.Options) *amazon.Provider { sawCall = true; return orig(opts) }
	defer func() { newAmazonProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if sawCall {
		t.Error("amazon.New was constructed even though AMAZON_ENABLE=0")
	}
	for _, p := range ps {
		if p.Name() == "Amazon Linux ALAS" {
			t.Errorf("dbUpdateProviders() = %+v, want no Amazon Linux provider with AMAZON_ENABLE=0", ps)
		}
	}
}

// TestDBUpdateProviders_OracleOnByDefault is the caller-first proof for
// D74's wiring: dbUpdateProviders must actually construct the Oracle Linux
// provider when ORACLE_ENABLE is unset, not merely have oracle.New sitting
// unused in the import list. Mirrors
// TestDBUpdateProviders_AmazonOnByDefault exactly, for the identical reason
// its own doc comment gives: mutating the call site to drop the provider (or
// its Options) compiles and would leave every other test in this package
// green.
func TestDBUpdateProviders_OracleOnByDefault(t *testing.T) {
	t.Setenv("ORACLE_ENABLE", "")
	t.Setenv("REDHAT_ENABLE", "0") // isolate: only Oracle's own wiring is under test here
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("SUSE_ENABLE", "0")

	orig := newOracleProvider
	sawCall := false
	var gotOpts oracle.Options
	newOracleProvider = func(opts oracle.Options) *oracle.Provider {
		sawCall, gotOpts = true, opts
		return orig(opts)
	}
	defer func() { newOracleProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if !sawCall {
		t.Fatal("dbUpdateProviders never constructed the Oracle Linux provider -- ORACLE_ENABLE defaults ON (D74)")
	}
	if gotOpts.Progress == nil {
		t.Error("oracle.New was constructed with a nil Progress -- the UEK/module-train guard's skip counts would go nowhere")
	}
	var found bool
	for _, p := range ps {
		if p.Name() == "Oracle Linux OVAL" {
			found = true
		}
	}
	if !found {
		t.Errorf("dbUpdateProviders() = %+v, want it to include the Oracle Linux provider", ps)
	}
}

// TestDBUpdateProviders_OracleDisabledViaEnv is the other half: an operator
// who does not want to scan Oracle Linux must be able to turn the fetch off
// entirely, exactly as REDHAT_ENABLE=0 and AMAZON_ENABLE=0 already let them.
func TestDBUpdateProviders_OracleDisabledViaEnv(t *testing.T) {
	t.Setenv("ORACLE_ENABLE", "0")
	t.Setenv("REDHAT_ENABLE", "0")
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("SUSE_ENABLE", "0")

	orig := newOracleProvider
	sawCall := false
	newOracleProvider = func(opts oracle.Options) *oracle.Provider { sawCall = true; return orig(opts) }
	defer func() { newOracleProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if sawCall {
		t.Error("oracle.New was constructed even though ORACLE_ENABLE=0")
	}
	for _, p := range ps {
		if p.Name() == "Oracle Linux OVAL" {
			t.Errorf("dbUpdateProviders() = %+v, want no Oracle Linux provider with ORACLE_ENABLE=0", ps)
		}
	}
}

// TestDBUpdateProviders_FedoraOnByDefault is the caller-first proof for
// D75's wiring: dbUpdateProviders must actually construct the Fedora
// provider when FEDORA_ENABLE is unset, not merely have fedora.New sitting
// unused in the import list. Mirrors TestDBUpdateProviders_OracleOnByDefault
// exactly, for the identical reason its own doc comment gives: mutating the
// call site to drop the provider (or its Options) compiles and would leave
// every other test in this package green.
func TestDBUpdateProviders_FedoraOnByDefault(t *testing.T) {
	t.Setenv("FEDORA_ENABLE", "")
	t.Setenv("REDHAT_ENABLE", "0") // isolate: only Fedora's own wiring is under test here
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("ORACLE_ENABLE", "0")
	t.Setenv("SUSE_ENABLE", "0")

	orig := newFedoraProvider
	sawCall := false
	var gotOpts fedora.Options
	newFedoraProvider = func(opts fedora.Options) *fedora.Provider {
		sawCall, gotOpts = true, opts
		return orig(opts)
	}
	defer func() { newFedoraProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if !sawCall {
		t.Fatal("dbUpdateProviders never constructed the Fedora provider -- FEDORA_ENABLE defaults ON (D75)")
	}
	if gotOpts.Progress == nil {
		t.Error("fedora.New was constructed with a nil Progress -- the EOL disclosure and " +
			"NoExtractableCVE count would go nowhere")
	}
	var found bool
	for _, p := range ps {
		if p.Name() == "Fedora Bodhi Updates" {
			found = true
		}
	}
	if !found {
		t.Errorf("dbUpdateProviders() = %+v, want it to include the Fedora provider", ps)
	}
}

// TestDBUpdateProviders_FedoraDisabledViaEnv is the other half: an operator
// who does not want to scan Fedora must be able to turn the fetch off
// entirely, exactly as REDHAT_ENABLE=0, AMAZON_ENABLE=0 and ORACLE_ENABLE=0
// already let them.
func TestDBUpdateProviders_FedoraDisabledViaEnv(t *testing.T) {
	t.Setenv("FEDORA_ENABLE", "0")
	t.Setenv("REDHAT_ENABLE", "0")
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("ORACLE_ENABLE", "0")
	t.Setenv("SUSE_ENABLE", "0")

	orig := newFedoraProvider
	sawCall := false
	newFedoraProvider = func(opts fedora.Options) *fedora.Provider { sawCall = true; return orig(opts) }
	defer func() { newFedoraProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if sawCall {
		t.Error("fedora.New was constructed even though FEDORA_ENABLE=0")
	}
	for _, p := range ps {
		if p.Name() == "Fedora Bodhi Updates" {
			t.Errorf("dbUpdateProviders() = %+v, want no Fedora provider with FEDORA_ENABLE=0", ps)
		}
	}
}

// TestDBUpdateProviders_SUSEOnByDefault is the caller-first proof for D77's
// wiring: dbUpdateProviders must actually construct the SUSE provider when
// SUSE_ENABLE is unset, not merely have suse.New sitting unused in the
// import list. Mirrors TestDBUpdateProviders_FedoraOnByDefault exactly, for
// the identical reason its own doc comment gives: mutating the call site to
// drop the provider (or its Options) compiles and would leave every other
// test in this package green.
func TestDBUpdateProviders_SUSEOnByDefault(t *testing.T) {
	t.Setenv("SUSE_ENABLE", "")
	t.Setenv("REDHAT_ENABLE", "0") // isolate: only SUSE's own wiring is under test here
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("ORACLE_ENABLE", "0")
	t.Setenv("FEDORA_ENABLE", "0")

	orig := newSUSEProvider
	sawCall := false
	var gotOpts suse.Options
	newSUSEProvider = func(opts suse.Options) *suse.Provider {
		sawCall, gotOpts = true, opts
		return orig(opts)
	}
	defer func() { newSUSEProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if !sawCall {
		t.Fatal("dbUpdateProviders never constructed the SUSE provider -- SUSE_ENABLE defaults ON (D77)")
	}
	if gotOpts.Progress == nil {
		t.Error("suse.New was constructed with a nil Progress -- the discard counts would go nowhere")
	}
	var found bool
	for _, p := range ps {
		if p.Name() == "SUSE CSAF VEX" {
			found = true
		}
	}
	if !found {
		t.Errorf("dbUpdateProviders() = %+v, want it to include the SUSE provider", ps)
	}
}

// TestDBUpdateProviders_SUSEDisabledViaEnv is the other half: an operator
// who does not want to scan SLES or openSUSE Leap must be able to turn the
// fetch off entirely, exactly as REDHAT_ENABLE=0, AMAZON_ENABLE=0,
// ORACLE_ENABLE=0 and FEDORA_ENABLE=0 already let them.
func TestDBUpdateProviders_SUSEDisabledViaEnv(t *testing.T) {
	t.Setenv("SUSE_ENABLE", "0")
	t.Setenv("REDHAT_ENABLE", "0")
	t.Setenv("AMAZON_ENABLE", "0")
	t.Setenv("ORACLE_ENABLE", "0")
	t.Setenv("FEDORA_ENABLE", "0")

	orig := newSUSEProvider
	sawCall := false
	newSUSEProvider = func(opts suse.Options) *suse.Provider { sawCall = true; return orig(opts) }
	defer func() { newSUSEProvider = orig }()

	ps := dbUpdateProviders(io.Discard)
	if sawCall {
		t.Error("suse.New was constructed even though SUSE_ENABLE=0")
	}
	for _, p := range ps {
		if p.Name() == "SUSE CSAF VEX" {
			t.Errorf("dbUpdateProviders() = %+v, want no SUSE provider with SUSE_ENABLE=0", ps)
		}
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

// `db build --seed <ref>` must reach PullSeed, and a PullSeed failure must
// fail the whole build rather than falling through to a from-empty build --
// the scheduled builder passes --seed every night, so a registry outage has
// to be loud (Task 5's whole point). 127.0.0.1:1 is a loopback address
// nothing listens on -- a connection failure, not a MANIFEST_UNKNOWN, so
// PullSeed's D-seed-bootstrap retry never fires and this exercises the same
// plain fetch-failure path Pull itself has, the same unreachable-registry
// fixture internal/dbcmd's own Push/Pull tests and TestRun_DBBuildReplacesUpdate
// use, so this needs no network.
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
	// Positive proof PullSeed ran at all: dbcmd.Pull and dbcmd.PullSeed are
	// the only functions that write this exact "fetching <ref>…" line
	// (dbcmd.Update's own progress lines name a provider or annotator
	// instead), and Pull is no longer what `db build --seed` calls.
	if !strings.Contains(stderr.String(), "fetching 127.0.0.1:1/assay-db:v6") {
		t.Errorf("stderr does not show PullSeed's own fetch line, so --seed may not be reaching PullSeed at all:\n%s", stderr.String())
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

// publishSeedArtifact packs a small, genuinely valid database and pushes it
// to ref under the given schema annotation. It exists so this package's own
// tests can populate an in-memory registry the way internal/dbcmd's own
// pull_test.go does (publishedFrom) -- reimplemented here because that
// helper is unexported across the package boundary.
func publishSeedArtifact(t *testing.T, ref string, schema int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.PutRating(advisory.Rating{CVE: "CVE-2026-BOOTSTRAP", Source: "NVD"}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{BuiltAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	img, err := dbartifact.Pack(path, dbartifact.Meta{SchemaVersion: schema, BuiltAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	target, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(target, img); err != nil {
		t.Fatal(err)
	}
}

// TestRun_DBBuildSeedReachesPullSeedsBootstrapFallback is the caller-side
// proof for the D-seed-bootstrap fix: `db build --seed` must reach
// dbcmd.PullSeed, not dbcmd.Pull (CLAUDE.md: "the helper is covered; nothing
// calls it"). The two differ on exactly this input -- Pull has no retry and
// refuses a MANIFEST_UNKNOWN outright -- so if main.go's build case ever
// reverted to dbcmd.Pull, this test goes red while every dbcmd-level test of
// PullSeed itself (internal/dbcmd/pullseed_test.go) stays green.
//
// This is the exact failure the first :v9 publish hit: the nightly seed
// points at `assay db ref`, this binary's own schema tag, which cannot exist
// before the schema's own first push.
//
// ASSAY_DB_DIR is pointed under a regular file, the same blocker trick
// TestRun_DBBuildWithSeedFailsRatherThanBuildingFromEmpty uses, so that once
// PullSeed succeeds and control reaches dbcmd.Update, Update's own first
// step (MkdirAll on this same blocked path) fails immediately -- before any
// provider runs and, critically, before the real OSV network fetch
// dbUpdateProviders wires in by default (TestRun_DBBuildReplacesUpdate's own
// comment explains why a routing test must never be able to perform that).
// The exit code this produces (exitError, from Update's own MkdirAll
// failure) is therefore identical whether PullSeed is wired correctly or
// not; what differs is the STDERR content asserted below, which is why both
// assertions matter and neither alone would prove the wiring.
func TestRun_DBBuildSeedReachesPullSeedsBootstrapFallback(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Host

	prevRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion-1)
	curRef := fmt.Sprintf("%s/assay-db:v%d", host, store.SchemaVersion)
	// Only the PREVIOUS schema's tag is published -- the registry state a
	// brand new schema's tag has on its own first day, before its own first
	// push.
	publishSeedArtifact(t, prevRef, store.SchemaVersion-1)

	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASSAY_DB_DIR", filepath.Join(blocker, "sub"))

	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "build", "--seed", curRef}, &stdout, &stderr)
	if code != exitError {
		t.Fatalf("db build --seed with only the previous schema published = %d, want %d "+
			"(dbcmd.Update's own MkdirAll must still fail against the blocked ASSAY_DB_DIR)\nstderr:\n%s",
			code, exitError, stderr.String())
	}
	// PullSeed's own fallback line: reached only if the build case calls
	// PullSeed, not Pull -- Pull would have failed outright on the
	// MANIFEST_UNKNOWN with no retry, and neither line below would appear.
	if !strings.Contains(stderr.String(), "the previous schema") {
		t.Errorf("stderr does not show PullSeed's D-seed-bootstrap fallback, so --seed may "+
			"still be reaching dbcmd.Pull instead of dbcmd.PullSeed:\n%s", stderr.String())
	}
	// Positive proof the fallback SUCCEEDED and control reached
	// dbcmd.Update, not merely that a "previous schema" line was printed
	// before a second, unrelated failure: Update's own first line, from its
	// own MkdirAll against the still-blocked ASSAY_DB_DIR.
	if !strings.Contains(stderr.String(), "create database directory") {
		t.Errorf("stderr does not show dbcmd.Update being reached after the seed fallback, "+
			"so PullSeed's bootstrap retry may not have actually succeeded:\n%s", stderr.String())
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

// `db build --ratings-only` without `--seed` must reach dbcmd.Update's own
// refusal (D66) -- proving --ratings-only is actually parsed off the command
// line and threaded through to Update, not silently dropped on the floor,
// the "drive the caller first" shape CLAUDE.md asks of every new flag.
//
// ASSAY_DB_DIR is still pointed at a scratch directory, matching every other
// `db build` test in this file, even though Update's own refusal fires
// before MkdirAll ever runs -- a future reordering inside Update must not
// turn this into a test that performs a real build against the developer's
// cache the way TestRun_DBBuildReplacesUpdate's own comment warns about.
func TestRun_DBBuildRatingsOnlyWithoutSeedRefuses(t *testing.T) {
	t.Setenv("ASSAY_DB_DIR", t.TempDir())

	var stdout, stderr bytes.Buffer
	code := run([]string{"db", "build", "--ratings-only"}, &stdout, &stderr)
	if code != exitError {
		t.Errorf("db build --ratings-only without --seed = %d, want %d\nstderr:\n%s",
			code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--ratings-only") {
		t.Errorf("stderr does not name --ratings-only:\n%s", stderr.String())
	}
}

// resolveRatingsOnly is order-independent with respect to --seed, which
// resolveBuildSeed's own position-locked parsing (args[2]/args[3]) cannot be
// taught without breaking readme_schema_test.go's direct call to it -- see
// resolveRatingsOnly's own doc comment for why the two are split apart.
func TestResolveRatingsOnly(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"absent", []string{"db", "build"}, false},
		{"absent with --seed", []string{"db", "build", "--seed", "example.test/assay-db:v6"}, false},
		{"present alone", []string{"db", "build", "--ratings-only"}, true},
		{"present after --seed", []string{"db", "build", "--seed", "example.test/assay-db:v6", "--ratings-only"}, true},
		{"present before --seed", []string{"db", "build", "--ratings-only", "--seed", "example.test/assay-db:v6"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveRatingsOnly(tt.args); got != tt.want {
				t.Errorf("resolveRatingsOnly(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

// withoutRatingsOnly is what makes resolveBuildSeed still work when
// --ratings-only comes BEFORE --seed on the command line -- without it,
// "--ratings-only" would land at args[2] itself and resolveBuildSeed would
// reject it as an unknown flag, even combined with a perfectly valid --seed
// right after it.
func TestWithoutRatingsOnly_LeavesSeedParsingIntact(t *testing.T) {
	var stderr bytes.Buffer
	args := []string{"db", "build", "--ratings-only", "--seed", "example.test/assay-db:v6"}
	ref, has, ok := resolveBuildSeed(withoutRatingsOnly(args), &stderr)
	if !ok {
		t.Fatalf("ok = false, want true (stderr: %s)", stderr.String())
	}
	if !has || ref != "example.test/assay-db:v6" {
		t.Errorf("ref = %q has = %v, want the seed ref carried through even with "+
			"--ratings-only ahead of it in the argument list", ref, has)
	}
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

// pushForceFixtureDB writes a local database carrying exactly n NVD ratings,
// the same shape internal/dbcmd/push_guard_test.go's own `bounded` helper
// uses to build artifacts that differ only in how much coverage they claim --
// small enough here that a push from the FEWER-ratings copy onto a
// MORE-ratings published artifact trips refuseCoverageRegression's
// RatingCount comparison deterministically.
func pushForceFixtureDB(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := w.PutRating(advisory.Rating{
			CVE: fmt.Sprintf("CVE-2026-%d", i), Source: "NVD",
		}); err != nil {
			t.Fatalf("PutRating: %v", err)
		}
	}
	if err := w.SetMeta(store.Meta{}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// TestRun_DBPushForceReachesRealExitCode is the run()-seam wiring check for
// `db push --force`. resolvePushRef's own tests (TestResolvePushRef) blank
// the returned force value on every subtest (`ref, _, ok :=`), and no test
// anywhere in this file passes --force through run() and observes what
// dbcmd.Push does with it -- so the CLI-to-dbcmd wiring of the flag that
// overrides the coverage-regression guard (internal/dbcmd/push_guard_test.go
// covers the guard itself thoroughly, always calling dbcmd.Push directly with
// a hand-built bool) is held by nothing. Hardcoding resolvePushRef's return to
// always report force=true -- so would silently dropping it and always
// reporting false -- leaves the whole suite green: `assay db push ref`
// (without --force) would either always bypass the guard that stops a
// narrower database silently replacing a wider published one, or the
// documented `--force` override would never actually work.
//
// A real in-memory registry (github.com/google/go-containerregistry's
// registry.New(), the same helper internal/dbcmd/push_guard_test.go uses) is
// seeded with a 5-rating artifact through dbcmd.Push itself, so the
// comparison below is the real guard rather than a fake standing in for it.
func TestRun_DBPushForceReachesRealExitCode(t *testing.T) {
	srv := httptest.NewServer(registry.New())
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ref := u.Host + "/assay-db-push-force-test:v1"

	// Seed the registry with a WIDER artifact (5 ratings) via the real Push
	// path, force=false -- the first push to a fresh tag always succeeds
	// (D60: nothing exists yet to compare against).
	var seedOut, seedErr bytes.Buffer
	if code := dbcmd.Push(context.Background(), pushForceFixtureDB(t, 5), ref, false,
		&seedOut, &seedErr); code != 0 {
		t.Fatalf("seeding the registry failed: %d (%s)", code, seedErr.String())
	}

	// The LOCAL database run() will publish from, narrower than what is
	// already published -- exactly the regression refuseCoverageRegression
	// exists to catch.
	t.Setenv("ASSAY_DB_DIR", t.TempDir())
	narrower := pushForceFixtureDB(t, 2)
	if err := os.Rename(narrower, filepath.Join(os.Getenv("ASSAY_DB_DIR"), "vulnerability.db")); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	args := []string{"db", "push", ref}
	if code := run(args, &stdout, &stderr); code != exitError {
		t.Fatalf("run(%v) = %d, want %d (exitError) -- publishing 2 ratings over "+
			"a published 5-rating artifact without --force must be refused\n"+
			"stderr:\n%s", args, code, exitError, stderr.String())
	}
	if !strings.Contains(stderr.String(), "pass --force") {
		t.Errorf("stderr does not show the coverage-regression refusal:\n%s", stderr.String())
	}

	// The identical push, with --force, reaches run() through the exact same
	// parseScanArgs-adjacent path (resolvePushRef) and must now succeed,
	// proving the flag reaches dbcmd.Push's force parameter rather than being
	// dropped in either direction.
	stdout.Reset()
	stderr.Reset()
	args = []string{"db", "push", ref, "--force"}
	if code := run(args, &stdout, &stderr); code != exitOK {
		t.Fatalf("run(%v) = %d, want %d (exitOK) -- --force must override the guard\n"+
			"stderr:\n%s", args, code, exitOK, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--force was given") {
		t.Errorf("stderr does not show --force's own override notice:\n%s", stderr.String())
	}
}

// KISA enrichment is opt-in, and nothing may construct the enricher without
// KISA_ENABLE, which D37 made default-ON.
//
// The gate is not about cost the way NVD's is (~41 requests, under a minute).
// D29 made it opt-in because the data may not be redistributed, and D37 flipped
// that: `db push` strips it either way, so the only person a default-off flag
// protected was the one who wanted the feature and forgot the variable.
//
// Both directions are asserted, and the falsy spellings especially: the shape
// this replaced was `os.Getenv(name) != ""`, under which KISA_ENABLE=0 meant ON.
// That was survivable while the flag was opt-in and nobody wrote a falsy value,
// and it is not survivable now that the publish workflow depends on "0" to
// avoid 41 requests for data it deletes.
func TestDBUpdateEnrichers_KISADefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"", true},     // unset: the D37 default
		{"1", true},    //
		{"true", true}, //
		{"on", true},   //
		{"0", false},   // the one the publish workflow sets
		{"false", false},
		{"no", false},
		{"OFF", false},  // case-insensitive
		{" 0 ", false},  // and whitespace-tolerant, because YAML quoting varies
		{"maybe", true}, // unrecognised: warn and take the default, never fail the build
	} {
		t.Run("KISA_ENABLE="+tc.value, func(t *testing.T) {
			t.Setenv("KISA_ENABLE", tc.value)

			orig := newKNVDEnricher
			sawCall := false
			newKNVDEnricher = func(opts knvd.Options) *knvd.Provider { sawCall = true; return orig(opts) }
			defer func() { newKNVDEnricher = orig }()

			got := dbUpdateEnrichers(io.Discard)
			if (len(got) > 0) != tc.want {
				t.Errorf("dbUpdateEnrichers() = %d enricher(s), want enabled=%v", len(got), tc.want)
			}
			// Constructing knvd.New is what reaches the live endpoint's default
			// BaseURL, so "returned nothing" and "built nothing" are different
			// claims and both matter.
			if sawCall != tc.want {
				t.Errorf("knvd.New constructed = %v, want %v", sawCall, tc.want)
			}
		})
	}
}

// The same reader guards NVD, which stays opt-in — a full pass costs hours, so
// starting one nobody asked for is a different kind of surprise. Asserted here
// because the two now share envFlag, and a change that flipped the shared
// default would turn every build into a seven-hour one.
func TestDBUpdateAnnotators_NVDStaysOptIn(t *testing.T) {
	for value, want := range map[string]bool{"": false, "0": false, "1": true, "true": true} {
		t.Setenv("NVD_ENABLE", value)
		if got := dbUpdateAnnotators(io.Discard); (len(got) > 0) != want {
			t.Errorf("NVD_ENABLE=%q: %d annotator(s), want enabled=%v", value, len(got), want)
		}
	}
}

// An unrecognised value says so rather than failing silently in either
// direction. This is a database build, not a scan: refusing to start over a
// malformed variable would trade a fetch nobody wanted for a build nobody got.
func TestEnvFlag_UnrecognisedValueWarns(t *testing.T) {
	t.Setenv("KISA_ENABLE", "yeah-ok")
	var buf bytes.Buffer
	if !envFlag(&buf, "KISA_ENABLE", true) {
		t.Error("envFlag returned the non-default for an unrecognised value")
	}
	if !strings.Contains(buf.String(), "KISA_ENABLE") || !strings.Contains(buf.String(), "yeah-ok") {
		t.Errorf("warning = %q, want it to name the variable and the value it could not read", buf.String())
	}
}

// With KISA_ENABLE set, exactly one enricher is constructed and its Progress
// is connected to the stderr passed in.
//
// The second half is the one that has already gone wrong here: nvd.Options
// carried the identical field, it shipped unwired, and a run that retried
// four times logged "retries fired: 0" because the notices went to
// io.Discard. Task 3 built knvd.Options.Progress and left it with no caller;
// this is that caller, and asserting on identity is what makes "the option
// exists" and "the option is connected" different statements.
//
// Driven through a spy on newKNVDEnricher rather than by inspecting the
// returned Provider, because Options is consumed by New and not readable
// back — and because knvd.New defaults BaseURL to the live KNVD endpoint,
// which no test may reach.
func TestDBUpdateEnrichers_ConstructsKNVDWithProgressOnStderr(t *testing.T) {
	t.Setenv("KISA_ENABLE", "1")

	var errOut bytes.Buffer
	var gotOpts knvd.Options
	sawCall := false
	orig := newKNVDEnricher
	newKNVDEnricher = func(opts knvd.Options) *knvd.Provider {
		gotOpts, sawCall = opts, true
		return orig(opts)
	}
	defer func() { newKNVDEnricher = orig }()

	enrichers := dbUpdateEnrichers(&errOut)

	if !sawCall {
		t.Fatal("dbUpdateEnrichers never constructed a KNVD enricher")
	}
	if gotOpts.Progress == nil {
		t.Fatal("Options.Progress is nil, so every page and retry notice goes to io.Discard")
	}
	if gotOpts.Progress != io.Writer(&errOut) {
		t.Errorf("Options.Progress = %v, want the stderr passed in", gotOpts.Progress)
	}
	if len(enrichers) != 1 || enrichers[0].Name() != knvd.SourceName {
		t.Errorf("dbUpdateEnrichers() = %+v, want exactly one KISA enricher", enrichers)
	}
}

// The `db build` CALL SITE must hand its own stderr to both source
// constructors.
//
// TestNVDOptionsFromEnv_ConnectsProgressToStderr and
// TestDBUpdateEnrichers_ConstructsKNVDWithProgressOnStderr each prove one
// builder function connects Progress correctly, and neither can see what
// run() passes INTO it: changing either call in the "build" case to
// io.Discard reproduces the nvd defect exactly — every page and retry notice
// to nowhere, a multi-hour sync that reports nothing about the four retries
// it fired — and left the whole suite green. This is the assertion that holds
// the argument rather than the parameter, for both sources at once.
//
// It never fetches anything. ASSAY_DB_DIR points beneath a regular file, so
// dbcmd.Update's own MkdirAll fails before it touches a provider — the same
// fixture TestRun_DBBuildReplacesUpdate uses, and for the same reason: with
// ASSAY_DB_DIR unset, store.DefaultPath resolves to the developer's real
// cache and a routing test performed a genuine 183-second, ~200 MB build
// over their database. The exit code AND the reason are both asserted, so a
// future change that made the build get further would fail here rather than
// quietly going to the network.
//
// The spies return what the real constructors would, so nothing downstream
// sees a nil provider; construction alone reaches no network for either.
func TestRun_DBBuildConnectsBothProgressWritersToItsStderr(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ASSAY_DB_DIR", filepath.Join(blocker, "sub"))
	t.Setenv("NVD_ENABLE", "1")
	t.Setenv("KISA_ENABLE", "1")

	var gotNVD nvd.Options
	var gotKNVD knvd.Options
	origNVD, origKNVD := newNVDAnnotator, newKNVDEnricher
	newNVDAnnotator = func(o nvd.Options) *nvd.Provider { gotNVD = o; return origNVD(o) }
	newKNVDEnricher = func(o knvd.Options) *knvd.Provider { gotKNVD = o; return origKNVD(o) }
	defer func() { newNVDAnnotator, newKNVDEnricher = origNVD, origKNVD }()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"db", "build"}, &stdout, &stderr); code != exitError {
		t.Fatalf("db build against an uncreatable database directory = %d, want %d", code, exitError)
	}
	if !strings.Contains(stderr.String(), "create database directory") {
		t.Fatalf("db build failed for the wrong reason, so this test may have reached a "+
			"provider and the network:\n%s", stderr.String())
	}

	if gotNVD.Progress != io.Writer(&stderr) {
		t.Errorf("nvd.Options.Progress = %v, want the stderr `db build` was given - every "+
			"retry notice from a seven-hour sync goes to io.Discard", gotNVD.Progress)
	}
	if gotKNVD.Progress != io.Writer(&stderr) {
		t.Errorf("knvd.Options.Progress = %v, want the stderr `db build` was given - every "+
			"page and retry notice goes to io.Discard", gotKNVD.Progress)
	}
}

// D36: the valued form of --fail-on-incomplete, and its rejection of anything
// else. A scope typo that silently left the gate off would be worse than the
// unusable gate it replaces.
func TestParseScan_FailOnIncompleteScopes(t *testing.T) {
	for _, tc := range []struct {
		arg          string
		wantAny      bool
		wantTarget   bool
		wantErrPiece string
	}{
		{arg: "--fail-on-incomplete", wantAny: true},
		{arg: "--fail-on-incomplete=any", wantAny: true},
		{arg: "--fail-on-incomplete=target", wantTarget: true},
		{arg: "--fail-on-incomplete=", wantErrPiece: `unknown scope ""`},
		{arg: "--fail-on-incomplete=advisory", wantErrPiece: `unknown scope "advisory"`},
		{arg: "--fail-on-incomplete=TARGET", wantErrPiece: "unknown scope"},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			_, opts, err := parseScanArgs([]string{"sbom.json", tc.arg})
			if tc.wantErrPiece != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrPiece) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErrPiece)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScan: %v", err)
			}
			if opts.FailOnIncomplete != tc.wantAny {
				t.Errorf("FailOnIncomplete = %v, want %v", opts.FailOnIncomplete, tc.wantAny)
			}
			// Asserted as well as the one above: the bare form must NOT set the
			// narrow flag, and "=target" must NOT set the broad one. A parser
			// that set both would satisfy either assertion on its own and turn
			// the narrow scope into a no-op.
			if opts.FailOnIncompleteTarget != tc.wantTarget {
				t.Errorf("FailOnIncompleteTarget = %v, want %v", opts.FailOnIncompleteTarget, tc.wantTarget)
			}
		})
	}
}

// D52: the valued form of --fail-on-unfixable, and its rejection of anything
// else. Same shape as TestParseScan_FailOnIncompleteScopes above, for the
// same reason: a scope typo that silently left the gate off (or, worse,
// silently widened it) would be worse than the unusable broad gate D52 exists
// to narrow.
func TestParseScan_FailOnUnfixableScopes(t *testing.T) {
	for _, tc := range []struct {
		arg          string
		wantAny      bool
		wantWontFix  bool
		wantErrPiece string
	}{
		{arg: "--fail-on-unfixable", wantAny: true},
		{arg: "--fail-on-unfixable=any", wantAny: true},
		{arg: "--fail-on-unfixable=wont-fix", wantWontFix: true},
		{arg: "--fail-on-unfixable=", wantErrPiece: `unknown scope ""`},
		{arg: "--fail-on-unfixable=nonsense", wantErrPiece: `unknown scope "nonsense"`},
		{arg: "--fail-on-unfixable=WONT-FIX", wantErrPiece: "unknown scope"},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			_, opts, err := parseScanArgs([]string{"sbom.json", tc.arg})
			if tc.wantErrPiece != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrPiece) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErrPiece)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseScan: %v", err)
			}
			if opts.FailOnUnfixable != tc.wantAny {
				t.Errorf("FailOnUnfixable = %v, want %v", opts.FailOnUnfixable, tc.wantAny)
			}
			// Asserted as well as the one above: the bare form (and "=any") must
			// NOT set the narrow flag, and "=wont-fix" must NOT set the broad
			// one. A parser that set both would satisfy either assertion on its
			// own and turn the narrow scope into a no-op, exactly the shape
			// TestParseScan_FailOnIncompleteScopes guards for its own pair.
			if opts.FailOnUnfixableWontFix != tc.wantWontFix {
				t.Errorf("FailOnUnfixableWontFix = %v, want %v", opts.FailOnUnfixableWontFix, tc.wantWontFix)
			}
		})
	}
}

// D52: an unknown scope names BOTH accepted spellings, not just one - a
// reader who typed "wontfix" or "all" needs the message to say "any" and
// "wont-fix" so they can fix the flag without going to the docs.
func TestParseScan_FailOnUnfixableUnknownScopeNamesBothAccepted(t *testing.T) {
	_, _, err := parseScanArgs([]string{"sbom.json", "--fail-on-unfixable=nonsense"})
	if err == nil {
		t.Fatal("err = nil, want an error for an unknown scope")
	}
	for _, want := range []string{"any", "wont-fix"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, missing accepted spelling %q", err, want)
		}
	}
}

// Unlike --fail-on and --output, --fail-on-unfixable has no repeat guard: the
// bare form and the "=wont-fix" form set two DIFFERENT fields (the doc
// comment on Options.FailOnUnfixableWontFix says passing both is "redundant
// but not contradictory"), so giving both on one command line must compose,
// not error.
func TestParseScan_FailOnUnfixableBothFormsTogether(t *testing.T) {
	_, opts, err := parseScanArgs(
		[]string{"sbom.json", "--fail-on-unfixable", "--fail-on-unfixable=wont-fix"})
	if err != nil {
		t.Fatalf("err = %v, want nil: both forms together is redundant, not contradictory", err)
	}
	if !opts.FailOnUnfixable {
		t.Error("opts.FailOnUnfixable = false, want true")
	}
	if !opts.FailOnUnfixableWontFix {
		t.Error("opts.FailOnUnfixableWontFix = false, want true")
	}
}

// The CLI contract end to end for D52's scope rejection, the same shape as
// TestRun_ScanBadFailOnValueExits2 above: an unrecognized
// --fail-on-unfixable scope must reach run() as exit 2 with the accepted
// spellings on stderr and stdout untouched, not a scan that silently ran
// with the gate off. The target does not exist, so a passing exit 2 here can
// only come from the scope rejection itself, never from the (unreached)
// scan.
func TestRun_ScanBadFailOnUnfixableScopeExits2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "docker-archive:/does/not/exist.tar", "--fail-on-unfixable=nonsense"},
		&stdout, &stderr)
	if code != exitError {
		t.Errorf("run() = %d, want exitError (%d)", code, exitError)
	}
	if stdout.Len() != 0 {
		t.Errorf("error path polluted stdout: %q", stdout.String())
	}
	for _, want := range []string{"any", "wont-fix"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, missing accepted spelling %q", stderr.String(), want)
		}
	}
}

// TestNvdOptionsFromEnv_OneClockReadingForBothEnds pins the fix CI caught on
// 2026-08-14: Since and Until computed from two separate time.Now() calls made
// an equal-days window inverted by microseconds — refused on Windows, whose
// coarse clock returns the same reading twice, accepted on Linux. The
// advancing clock makes the defect visible on every platform: with one shared
// reading the equal-days case is exactly equal and refused; with two calls the
// second lands later and slips through.
func TestNvdOptionsFromEnv_OneClockReadingForBothEnds(t *testing.T) {
	base := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	calls := 0
	orig := clockNow
	clockNow = func() time.Time {
		calls++
		return base.Add(time.Duration(calls) * time.Microsecond)
	}
	defer func() { clockNow = orig }()

	t.Setenv("NVD_SINCE_DAYS", "30")
	t.Setenv("NVD_UNTIL_DAYS", "30")

	var errOut bytes.Buffer
	opts := nvdOptionsFromEnv(&errOut)
	if !opts.Until.IsZero() {
		t.Errorf("Until = %v, want zero — equal days must refuse even when the clock advances between reads", opts.Until)
	}
	if !strings.Contains(errOut.String(), "not after NVD_SINCE_DAYS") {
		t.Errorf("stderr = %q, want the inverted-window warning", errOut.String())
	}
}

// TestNvdOptionsFromEnv_WindowSpanCap pins the fix for the 2026-08-14
// backfill accident. The API's 120-day maximum is on the window's WIDTH, but
// the cap predated D65 and applied to SINCE alone — so NVD_SINCE_DAYS=240 was
// capped to 120, which made NVD_UNTIL_DAYS=120 read as inverted, and the two
// warnings COMPOSED into a [120d, now] window nobody asked for. The runbook's
// own example was unrepresentable.
func TestNvdOptionsFromEnv_WindowSpanCap(t *testing.T) {
	base := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	orig := clockNow
	clockNow = func() time.Time { return base }
	defer func() { clockNow = orig }()

	cases := []struct {
		name         string
		since, until string
		wantSinceAgo int // days; 0 means Since must be zero
		wantUntilAgo int // days; 0 means Until must be zero
		wantWarn     string
	}{
		{
			// The runbook slice, verbatim. Before the fix this produced
			// [120, 0] with two warnings; it must now run as asked.
			name:  "the runbook slice [240,120] is representable",
			since: "240", until: "120",
			wantSinceAgo: 240, wantUntilAgo: 120,
		},
		{
			name:  "a deep slice [360,240] is representable",
			since: "360", until: "240",
			wantSinceAgo: 360, wantUntilAgo: 240,
		},
		{
			// Width 260 > 120: clamped to [until+120, until], disclosed.
			name:  "a too-wide slice is clamped to 120 days above its end",
			since: "380", until: "120",
			wantSinceAgo: 240, wantUntilAgo: 120,
			wantWarn: "spans more than the API's 120-day maximum window; using 240",
		},
		{
			// No until: the pre-D65 behaviour, byte for byte.
			name:         "no until keeps the old SINCE cap and its warning",
			since:        "365",
			wantSinceAgo: 120,
			wantWarn:     "exceeds the API's 120-day maximum window; using 120",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NVD_SINCE_DAYS", tc.since)
			if tc.until != "" {
				t.Setenv("NVD_UNTIL_DAYS", tc.until)
			}
			var errOut bytes.Buffer
			opts := nvdOptionsFromEnv(&errOut)

			if want := base.AddDate(0, 0, -tc.wantSinceAgo); !opts.Since.Equal(want) {
				t.Errorf("Since = %v, want %v (%d days ago)", opts.Since, want, tc.wantSinceAgo)
			}
			if tc.wantUntilAgo == 0 {
				if !opts.Until.IsZero() {
					t.Errorf("Until = %v, want zero", opts.Until)
				}
			} else if want := base.AddDate(0, 0, -tc.wantUntilAgo); !opts.Until.Equal(want) {
				t.Errorf("Until = %v, want %v (%d days ago)", opts.Until, want, tc.wantUntilAgo)
			}

			s := errOut.String()
			if tc.wantWarn == "" {
				if s != "" {
					t.Errorf("stderr = %q, want none — a representable slice must not warn", s)
				}
			} else if !strings.Contains(s, tc.wantWarn) {
				t.Errorf("stderr = %q, want it to contain %q", s, tc.wantWarn)
			}
		})
	}
}
