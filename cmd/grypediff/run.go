package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
)

// Exit codes, same 2 > 1 > 0 precedence as assay's own CLI contract
// (main.go's exitOK/exitFindings/exitError): an untrustworthy result
// outranks the content of the result.
const (
	exitOK       = 0 // every target held its floors
	exitFindings = 1 // a floor was breached -- a regression signal
	exitError    = 2 // a target could not be run or its result could not be trusted
)

const usage = `grypediff — deterministic assay/grype differential (D93)

Usage:
  grypediff -targets <file> -assay <bin> -grype <bin> -capture <dir>
      Live mode: scans every target in <file> with both binaries, judges the
      result against that target's committed floors, and writes every raw
      JSON document into <dir> as <name>.assay.json / <name>.grype.json.

  grypediff -targets <file> -offline <dir>
      Offline mode: reads <dir>/<name>.assay.json and <dir>/<name>.grype.json
      instead of running either scanner. Same judging path as live mode --
      this is how floors are seeded and how tests get integration-shaped
      coverage without a network call.

Exit codes:
  0  every target held its floors
  1  a floor was breached (regression signal)
  2  a target could not be run, or its result could not be trusted
     (an assay scan that exited 2, a grype hard failure, malformed JSON, or
     an unreadable/invalid targets file)
`

// execFunc is the seam that stands between run and the real scanners: a
// test supplies a fake so it never launches an actual assay or grype
// process. bin is the executable, args are its arguments; out is whatever
// the process wrote to STDOUT (never stderr -- see main's real
// implementation for why the two are kept apart), exitCode is its process
// exit code, and err is non-nil only when the process could not be started
// at all (binary missing, permission denied) -- a nonzero exit from a
// process that DID run is reported via exitCode, not err.
type execFunc func(bin string, args ...string) (out []byte, exitCode int, err error)

// row is one line of the summary table written to stdout.
type row struct {
	Target       string
	AssayTuples  int
	GrypeTuples  int
	Agree        int
	OnlyAssay    int
	OnlyGrype    int
	NotEvaluated int
	Verdict      string // "ok", "BREACH", or "ERROR"
}

// run is the testable seam (mirrors cmd/assay/main.go's own run(args,
// stdout, stderr) int pattern): main only translates the return value into
// os.Exit. execScan is the additional seam D93 asks for, so no test here
// ever launches a real scanner.
func run(args []string, stdout, stderr io.Writer, execScan execFunc) int {
	fs := flag.NewFlagSet("grypediff", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print our own usage, once, on our own terms
	targetsPath := fs.String("targets", "", "path to the floors JSON file (required)")
	assayBin := fs.String("assay", "", "path to the assay binary (live mode)")
	grypeBin := fs.String("grype", "", "path to the grype binary (live mode)")
	captureDir := fs.String("capture", "", "directory to write raw scan JSON into (live mode)")
	offlineDir := fs.String("offline", "", "directory of previously captured JSON to replay")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		fmt.Fprint(stderr, usage)
		return exitError
	}

	if *targetsPath == "" {
		fmt.Fprintln(stderr, "error: -targets is required")
		fmt.Fprint(stderr, usage)
		return exitError
	}
	targets, err := loadTargets(*targetsPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		fmt.Fprint(stderr, usage)
		return exitError
	}

	live := *offlineDir == ""
	if live {
		if *assayBin == "" || *grypeBin == "" || *captureDir == "" {
			fmt.Fprintln(stderr, "error: live mode requires -assay, -grype and -capture")
			fmt.Fprint(stderr, usage)
			return exitError
		}
		if err := os.MkdirAll(*captureDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "error: create capture dir %s: %v\n", *captureDir, err)
			return exitError
		}
	}

	rows := make([]row, 0, len(targets))
	worst := exitOK

	for _, t := range targets {
		var assayRaw, grypeRaw []byte
		var fatal string

		if live {
			assayRaw, grypeRaw, fatal = scanLive(execScan, *assayBin, *grypeBin, t)
			writeCapture(stderr, *captureDir, t.Name, "assay", assayRaw)
			writeCapture(stderr, *captureDir, t.Name, "grype", grypeRaw)
		} else {
			assayRaw, grypeRaw, fatal = readOffline(*offlineDir, t)
		}

		if fatal != "" {
			fmt.Fprintf(stderr, "error: target=%s %s\n", t.Name, fatal)
			rows = append(rows, row{Target: t.Name, Verdict: "ERROR"})
			worst = exitError
			continue
		}

		var adoc assayDocument
		if err := json.Unmarshal(assayRaw, &adoc); err != nil {
			fmt.Fprintf(stderr, "error: target=%s malformed assay JSON: %v\n", t.Name, err)
			rows = append(rows, row{Target: t.Name, Verdict: "ERROR"})
			worst = exitError
			continue
		}
		var gdoc grypeDocument
		if err := json.Unmarshal(grypeRaw, &gdoc); err != nil {
			fmt.Fprintf(stderr, "error: target=%s malformed grype JSON: %v\n", t.Name, err)
			rows = append(rows, row{Target: t.Name, Verdict: "ERROR"})
			worst = exitError
			continue
		}

		aSet := assayTuples(adoc)
		gSet := grypeTuples(gdoc)
		agree, onlyAssay, onlyGrype := compareSets(aSet, gSet)
		notEvaluated := adoc.Summary.NotEvaluated

		breaches := judge(t, agree, len(aSet), notEvaluated)
		r := row{
			Target:       t.Name,
			AssayTuples:  len(aSet),
			GrypeTuples:  len(gSet),
			Agree:        agree,
			OnlyAssay:    onlyAssay,
			OnlyGrype:    onlyGrype,
			NotEvaluated: notEvaluated,
			Verdict:      "ok",
		}
		if len(breaches) > 0 {
			r.Verdict = "BREACH"
			if worst < exitFindings {
				worst = exitFindings
			}
			for _, b := range breaches {
				fmt.Fprintln(stderr, b.String())
			}
		}
		rows = append(rows, r)
	}

	renderTable(stdout, rows)
	return worst
}

// scanLive runs both scanners for one target. Both are always attempted,
// even if the first already failed: D93's -capture directory exists so a
// human can re-judge a failed target locally, and that needs whatever
// either side produced, not just the one that failed first.
func scanLive(execScan execFunc, assayBin, grypeBin string, t Target) (assayRaw, grypeRaw []byte, fatal string) {
	assayRaw, assayFatal := runAssay(execScan, assayBin, t)
	grypeRaw, grypeFatal := runGrype(execScan, grypeBin, t)
	switch {
	case assayFatal != "" && grypeFatal != "":
		fatal = assayFatal + "; " + grypeFatal
	case assayFatal != "":
		fatal = assayFatal
	case grypeFatal != "":
		fatal = grypeFatal
	}
	return assayRaw, grypeRaw, fatal
}

// runAssay runs `assay scan <ref> --output json`. Exit 0 and 1 both mean the
// scan completed and its result can be trusted (D93's own framing of
// assay's exit contract); only exit 2 -- or a failure to even launch --
// makes this target's result untrustworthy.
func runAssay(execScan execFunc, bin string, t Target) (out []byte, fatal string) {
	out, code, err := execScan(bin, "scan", t.Ref, "--output", "json")
	if err != nil {
		return out, fmt.Sprintf("assay: could not run: %v", err)
	}
	if code == exitError {
		return out, "assay scan exited 2 (untrustworthy result)"
	}
	if code != exitOK && code != exitFindings {
		return out, fmt.Sprintf("assay scan exited unexpected code %d", code)
	}
	return out, ""
}

// runGrype runs `grype <ref> -o json`. Default grype has no -f/--fail-on
// configured here, so 0 is the expected exit; but parse success is
// authoritative over the exit code either way (grype can be configured
// elsewhere to exit nonzero on findings), which is why this checks whether
// the output parses as JSON before deciding a nonzero exit is a hard
// failure.
//
// Mutation note: deleting this probe still leaves the malformed-JSON case
// caught (run's own later json.Unmarshal(grypeRaw, &gdoc) reaches the same
// "malformed grype JSON" verdict for a target where grype exited 0) -- an
// equivalent, not a gap, confirmed by deleting this block and re-running
// TestRun_Live_MalformedGrypeJSON_ExitError, which still passes. What the
// probe alone holds accountable is the exit!=0 branch: without it, a grype
// crash (nonzero exit, unparseable output) gets reported as "malformed
// grype JSON" instead of "grype hard failure (exit N)", which is what
// TestRun_Live_GrypeHardFailure_ExitError catches going red.
func runGrype(execScan execFunc, bin string, t Target) (out []byte, fatal string) {
	out, code, err := execScan(bin, t.Ref, "-o", "json")
	if err != nil {
		return out, fmt.Sprintf("grype: could not run: %v", err)
	}
	var probe json.RawMessage
	if uerr := json.Unmarshal(out, &probe); uerr != nil {
		if code != 0 {
			return out, fmt.Sprintf("grype hard failure (exit %d)", code)
		}
		return out, "malformed grype JSON"
	}
	return out, ""
}

// readOffline replays a previous capture instead of scanning. This is the
// path floor-seeding and most of this package's own tests use.
func readOffline(dir string, t Target) (assayRaw, grypeRaw []byte, fatal string) {
	assayRaw, err := os.ReadFile(filepath.Join(dir, t.Name+".assay.json"))
	if err != nil {
		return nil, nil, fmt.Sprintf("read offline assay capture: %v", err)
	}
	grypeRaw, err = os.ReadFile(filepath.Join(dir, t.Name+".grype.json"))
	if err != nil {
		return nil, nil, fmt.Sprintf("read offline grype capture: %v", err)
	}
	return assayRaw, grypeRaw, ""
}

// writeCapture persists one raw scan document for later human review
// (uploaded as a CI artifact by the workflow). A write failure is reported
// on stderr but never fails the run -- a full disk should not turn a
// passing differential into an untrustworthy one, and the run's own
// judgment does not depend on this file existing.
func writeCapture(stderr io.Writer, dir, name, kind string, data []byte) {
	path := filepath.Join(dir, name+"."+kind+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(stderr, "warning: write capture %s: %v\n", path, err)
	}
}

// renderTable writes the one thing that goes to stdout: every target's row,
// so a breach on target 4 of 13 does not hide what targets 1-3 and 5-13
// measured (D93's "still runs the rest" requirement, made visible).
func renderTable(w io.Writer, rows []row) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tASSAY\tGRYPE\tAGREE\tONLY_ASSAY\tONLY_GRYPE\tNOTEVAL\tVERDICT")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			r.Target, r.AssayTuples, r.GrypeTuples, r.Agree, r.OnlyAssay, r.OnlyGrype, r.NotEvaluated, r.Verdict)
	}
	tw.Flush()
}
