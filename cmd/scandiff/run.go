package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

// Exit codes, same 2 > 1 > 0 precedence as assay's own CLI contract
// (main.go's exitOK/exitFindings/exitError): an untrustworthy result
// outranks the content of the result.
const (
	exitOK       = 0 // every target held its floors
	exitFindings = 1 // a floor was breached -- a regression signal
	exitError    = 2 // a target could not be run or its result could not be trusted
)

const usage = `scandiff — deterministic assay/grype/trivy differential (D93, D105)

Usage:
  scandiff -targets <file> -assay <bin> -grype <bin> -capture <dir> [-trivy <bin>] [-regressions-only]
      Live mode: scans every target in <file> with assay and grype, judges the
      result against that target's committed floors, and writes every raw
      JSON document into <dir> as <name>.assay.json / <name>.grype.json.
      -trivy is only needed for targets whose entry carries a "trivy" block
      (D105); a target with no such block never invokes it, and -trivy may
      be omitted entirely if no target in the file has one.

  scandiff -targets <file> -offline <dir> [-regressions-only]
      Offline mode: reads <dir>/<name>.assay.json and <dir>/<name>.grype.json
      (and <dir>/<name>.trivy.json for a target with a trivy block) instead
      of running any scanner. Same judging path as live mode -- this is how
      floors are seeded and how tests get integration-shaped coverage
      without a network call.

  -regressions-only (either mode) is the nightly publish gate's mode (D114):
      it skips the ceilings, maxFindings, trivy.maxFindings,
      maxGrypeOnlyApp (D117) and maxAssayOnlyFixed (D146), and prints any
      that would have breached as an "info:" line instead. A ceiling
      measures upstream growth, which must never stop a new database from
      shipping; every other floor, and every ERROR, is judged exactly as
      without it -- minApplicationPackages (D167) included, since losing
      a probe's packages is what a broken candidate does.

Exit codes:
  0  every target held its floors
  1  a floor was breached (regression signal)
  2  a target could not be run, or its result could not be trusted
     (an assay scan that still exited 2 after live mode's one retry, a
     grype or trivy hard failure, malformed JSON, or an unreadable/invalid
     targets file)

A target's trivy block with every floor at zero ("trivy": {}) is
INFORMATIONAL, not a committed floor: scandiff measures and prints the
numbers on stdout in ready-to-paste JSON form but never breaches on them.
Run with -trivy and workflow_dispatch to seed real floors before committing
them.
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

// retryPause is the wait between an assay scan that exited 2 and its one
// retry (D114, revised 2026-10-06), held in a variable for the same reason as
// dbcmd's carryNow: a test replaces it with a no-op, or with one that records
// when it ran, so the suite neither sleeps nor has to guess whether the pause
// sat between the two attempts. Five seconds is sized to the measured case,
// not tuned: enough to stop the retry landing on the very same momentary
// registry state, short against a gate that already spends minutes per
// target. If a transient outlasts it, that is new information for D114, not
// a reason to grow the number unasked.
var retryPause = func() { time.Sleep(5 * time.Second) }

// row is one line of the summary table written to stdout.
type row struct {
	Target      string
	AssayTuples int
	GrypeTuples int
	// BridgedIntoAssay and BridgedIntoGrype are the tuples bridgeBareIDs added
	// to each side, already inside AssayTuples and GrypeTuples. Printed, never
	// judged: they let a ceiling breach be read as native or bridged growth
	// (see bridgeBareIDs).
	BridgedIntoAssay int
	BridgedIntoGrype int
	Agree            int
	OnlyAssay        int
	OnlyGrype        int
	NotEvaluated     int
	Verdict          string // "ok", "BREACH", or "ERROR"
}

// run is the testable seam (mirrors cmd/assay/main.go's own run(args,
// stdout, stderr) int pattern): main only translates the return value into
// os.Exit. execScan is the additional seam D93 asks for, so no test here
// ever launches a real scanner.
func run(args []string, stdout, stderr io.Writer, execScan execFunc) int {
	fs := flag.NewFlagSet("scandiff", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print our own usage, once, on our own terms
	targetsPath := fs.String("targets", "", "path to the floors JSON file (required)")
	assayBin := fs.String("assay", "", "path to the assay binary (live mode)")
	grypeBin := fs.String("grype", "", "path to the grype binary (live mode)")
	// trivyBin is deliberately NOT part of the "live mode requires..." check
	// below: most targets carry no "trivy" block at all (D105), and the ones
	// that do are judged one target at a time -- see runTrivy, which reports
	// a missing binary as that target's own fatal reason rather than
	// refusing to run the whole tool.
	trivyBin := fs.String("trivy", "", "path to the trivy binary (live mode; only needed for targets with a trivy block)")
	captureDir := fs.String("capture", "", "directory to write raw scan JSON into (live mode)")
	offlineDir := fs.String("offline", "", "directory of previously captured JSON to replay")
	// regressionsOnly is D114's publish-gate mode, valid live or offline.
	// Off by default so the weekly differential keeps judging every floor;
	// see demoteCeilings for which floors it skips and why only those.
	regressionsOnly := fs.Bool("regressions-only", false, "judge every floor except the ceilings (maxFindings, trivy.maxFindings, maxGrypeOnlyApp, maxAssayOnlyFixed), which print as info")

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

		// The run record brackets the target (runRecord): written
		// incomplete before its first scan and complete after its last, on
		// every path out of this iteration, so a replay can tell one
		// finished run's captures from an interrupted run's or a run that
		// could not update them.
		var rec *runRecord
		if live {
			rec = newRunRecord()
			writeRunRecord(stderr, *captureDir, t.Name, rec)
		} else {
			r, err := readRunRecord(*offlineDir, t.Name)
			if err != nil {
				fmt.Fprintf(stderr, "error: target=%s read offline run record: %v\n", t.Name, err)
				rows = append(rows, row{Target: t.Name, Verdict: "ERROR"})
				worst = exitError
				continue
			}
			rec = r
		}
		finish := func() {
			if live {
				rec.Complete = true
				writeRunRecord(stderr, *captureDir, t.Name, rec)
			}
		}
		errorRow := func(msg string) {
			fmt.Fprintf(stderr, "error: target=%s %s\n", t.Name, msg)
			rows = append(rows, row{Target: t.Name, Verdict: "ERROR"})
			worst = exitError
			finish()
		}

		if live {
			var assayFatal, grypeFatal string
			assayRaw, grypeRaw, assayFatal, grypeFatal = scanLive(execScan, *assayBin, *grypeBin, t, stderr)
			fatal = joinFatal(assayFatal, grypeFatal)
			rec.Tools["assay"] = writeCapture(stderr, *captureDir, t.Name, "assay", assayRaw, assayFatal == "")
			rec.Tools["grype"] = writeCapture(stderr, *captureDir, t.Name, "grype", grypeRaw, grypeFatal == "")
		} else {
			assayRaw, grypeRaw, fatal = readOffline(*offlineDir, t, rec)
		}

		if fatal != "" {
			errorRow(fatal)
			continue
		}

		var adoc assayDocument
		if err := json.Unmarshal(assayRaw, &adoc); err != nil {
			errorRow(fmt.Sprintf("malformed assay JSON: %v", err))
			continue
		}
		if why := assayShape(assayRaw); why != "" {
			errorRow("malformed assay JSON: " + why)
			continue
		}
		// An offline capture is held to the floors file's pinned ref (QA
		// 2026-11-11): a target renamed or re-pinned in the file, with an old
		// capture still under its name, was judged as that capture -- a BCI
		// capture passed both modes for an Alpine digest. The capture
		// records the argument assay scanned (D120); a digest-pinned ref
		// must appear in it. A capture from before D120 records none and is
		// taken as it was, since nothing can be checked. A live scan is of
		// t.Ref by construction, so checking it too would change nothing:
		// the !live guard states the intent, and its mutation survives.
		if !live {
			if why := captureMismatch(t, adoc.Provenance.Target.Argument, adoc.digests(), "assay", stderr); why != "" {
				errorRow(why)
				continue
			}
		}
		var gdoc grypeDocument
		if err := json.Unmarshal(grypeRaw, &gdoc); err != nil {
			errorRow(fmt.Sprintf("malformed grype JSON: %v", err))
			continue
		}
		// A document that is JSON but not a grype report -- the diagnostic
		// object grype writes when a scan fails -- decodes to zero matches,
		// which read as 101 agreements collapsing to 0 and the gate passing
		// (release check 2026-11-11). Judged by shape, live or offline, so a
		// capture of such a run cannot pass offline either.
		if why := grypeShape(grypeRaw); why != "" {
			errorRow("malformed grype JSON: " + why)
			continue
		}
		// The grype capture too (PR #276 review): a target re-pinned with
		// only its assay capture regenerated would be compared against the
		// old image's grype tuples.
		if !live {
			if why := captureMismatch(t, gdoc.Source.Target.UserInput, gdoc.digests(), "grype", stderr); why != "" {
				errorRow(why)
				continue
			}
		}

		aSet := assayTuples(adoc)
		gSet := grypeTuples(gdoc)
		intoAssay, intoGrype := bridgeBareIDs(adoc, gdoc, aSet, gSet)
		agree, onlyAssay, onlyGrype := compareSets(aSet, gSet)
		notEvaluated := adoc.Summary.NotEvaluated

		// D117's ceiling joins judge's breaches BEFORE demoteCeilings, so the
		// one place that decides what -regressions-only skips decides it for
		// this ceiling too.
		measured := judge(t, agree, len(aSet), notEvaluated, adoc.Summary.Components)
		measured = append(measured, judgeGrypeOnlyApp(t, grypeOnlyAppCounts(gdoc, aSet, gSet))...)
		measured = append(measured, judgeIncomplete(t, adoc.Summary)...)
		measured = append(measured, judgeAssayOnlyFixed(t, assayOnlyFixed(adoc, gSet))...)
		measured = append(measured, judgeApplicationPackages(t, adoc.Coverage)...)
		breaches, info := demoteCeilings(measured, *regressionsOnly)
		printInfo(stderr, info)
		r := row{
			Target:           t.Name,
			AssayTuples:      len(aSet),
			GrypeTuples:      len(gSet),
			BridgedIntoAssay: intoAssay,
			BridgedIntoGrype: intoGrype,
			Agree:            agree,
			OnlyAssay:        onlyAssay,
			OnlyGrype:        onlyGrype,
			NotEvaluated:     notEvaluated,
			Verdict:          "ok",
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

		// D105: the optional second comparison against trivy. Nothing here
		// runs, and no <name>.trivy.json capture is ever written, for a
		// target whose entry carries no "trivy" key at all.
		if t.Trivy != nil {
			switch trivyPhase(execScan, *trivyBin, *captureDir, *offlineDir, live, *regressionsOnly, t, aSet, rec, stdout, stderr) {
			case trivyError:
				r.Verdict = "ERROR"
				worst = exitError
			case trivyBreached:
				if r.Verdict == "ok" {
					r.Verdict = "BREACH"
				}
				if worst < exitFindings {
					worst = exitFindings
				}
			}
		}

		rows = append(rows, r)
		finish()
	}

	renderTable(stdout, rows)
	return worst
}

// scanLive runs both scanners for one target. Both are always attempted,
// even if the first already failed: D93's -capture directory exists so a
// human can re-judge a failed target locally, and that needs whatever
// either side produced, not just the one that failed first.
//
// Each side's fatal reason is returned on its own, so the capture of a
// scan that failed can be filed apart from a good one (writeCapture).
func scanLive(execScan execFunc, assayBin, grypeBin string, t Target, stderr io.Writer) (assayRaw, grypeRaw []byte, assayFatal, grypeFatal string) {
	assayRaw, assayFatal = runAssay(execScan, assayBin, t, stderr)
	grypeRaw, grypeFatal = runGrype(execScan, grypeBin, t)
	return assayRaw, grypeRaw, assayFatal, grypeFatal
}

// joinFatal is the target's one fatal line from both scanners' reasons.
func joinFatal(assayFatal, grypeFatal string) string {
	switch {
	case assayFatal != "" && grypeFatal != "":
		return assayFatal + "; " + grypeFatal
	case assayFatal != "":
		return assayFatal
	}
	return grypeFatal
}

// runAssay runs `assay scan <ref> --output json`. Exit 0 and 1 both mean the
// scan completed and its result can be trusted (D93's own framing of
// assay's exit contract); only exit 2 -- or a failure to even launch --
// makes this target's result untrustworthy.
//
// An exit 2 is run once more before it is believed (D114, revised
// 2026-10-06). A target scan is read-only and idempotent against the same
// candidate database, so a second attempt cannot change what the gate
// measures; it can only produce a result the first attempt never finished.
// Exit 2 is the one code that means "could not finish" -- a launch failure,
// an unexpected code or malformed JSON is not a transient, and running it
// again would only repeat it, so none of those is retried. One retry, not a
// budget: the measured failure (2026-10-05, mirror.gcr.io answering
// BLOB_UNKNOWN for one layer) was a single blob on a single pull, so the
// second attempt is what tells a transient from a fault, and a third would
// only mean the first two were not transients. The second attempt's result
// is then used exactly as the first's would have been -- its output too,
// which is what run writes to the capture, so a human re-judging the target
// reads the bytes the verdict came from.
func runAssay(execScan execFunc, bin string, t Target, stderr io.Writer) (out []byte, fatal string) {
	args := []string{"scan", t.Ref, "--output", "json"}
	out, code, err := execScan(bin, args...)
	if err == nil && code == exitError {
		fmt.Fprintf(stderr, "retry: target=%s assay scan exited 2, retrying once\n", t.Name)
		retryPause()
		out, code, err = execScan(bin, args...)
	}
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
	// JSON that is not a grype report -- the `{"error": ...}` diagnostic
	// a failed scan writes -- with a nonzero exit is the hard failure the
	// exit code says it is, not a scan of zero matches (release check
	// 2026-11-11: exit 2 with a diagnostic object passed the gate at 0
	// agreements). With exit 0 the shape is judged by run, as offline.
	if code != 0 && grypeShape(out) != "" {
		return out, fmt.Sprintf("grype hard failure (exit %d)", code)
	}
	return out, ""
}

// grypeShape is "" when raw is a grype report -- a JSON object carrying a
// `matches` array, empty or not -- and otherwise says what is missing. The
// field is what every grype -o json document has and no diagnostic object
// does.
func grypeShape(raw []byte) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err.Error()
	}
	m, ok := probe["matches"]
	if !ok {
		return "no \"matches\" field: not a grype report"
	}
	// A report's matches is an array, empty or not; grype's diagnostic
	// object can carry `"matches": null`, which decoded to zero matches
	// and passed the gate (release check of main 5197df4). Every real
	// capture with nothing to report carries `[]`.
	if !strings.HasPrefix(strings.TrimSpace(string(m)), "[") {
		return "\"matches\" is not an array: not a grype report"
	}
	return ""
}

// trivyShape is grypeShape for a trivy report: `SchemaVersion` is what every
// `trivy image --format json` document has and its diagnostic object lacks.
func trivyShape(raw []byte) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err.Error()
	}
	v, ok := probe["SchemaVersion"]
	if !ok {
		return "no \"SchemaVersion\" field: not a trivy report"
	}
	// A report's SchemaVersion is a number; a diagnostic object may carry
	// the key with null (release check of main b732cac).
	if s := strings.TrimSpace(string(v)); s == "" || s[0] < '0' || s[0] > '9' {
		return "\"SchemaVersion\" is not a number: not a trivy report"
	}
	return ""
}

// assayShape is grypeShape for an assay report: `summary` is what every
// `assay scan --output json` document has.
func assayShape(raw []byte) string {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err.Error()
	}
	if _, ok := probe["summary"]; !ok {
		return "no \"summary\" field: not an assay report"
	}
	return ""
}

// readOffline replays a previous capture instead of scanning. This is the
// path floor-seeding and most of this package's own tests use.
func readOffline(dir string, t Target, rec *runRecord) (assayRaw, grypeRaw []byte, fatal string) {
	assayRaw, fatal = readCapture(dir, t.Name, "assay", rec)
	if fatal != "" {
		return nil, nil, fatal
	}
	grypeRaw, fatal = readCapture(dir, t.Name, "grype", rec)
	if fatal != "" {
		return nil, nil, fatal
	}
	return assayRaw, grypeRaw, ""
}

// readCapture reads <name>.<kind>.json for a replay. A <name>.<kind>.failed.json
// beside it that is not older is the later run: that run failed, and the
// success capture is an earlier run's that writeCapture could not remove
// (release check of main 5197df4: on Windows a reader holding the success
// capture open kept it in place through the failed run, and the replay
// read it as that run's result). The replay then fails as the run did; the
// next successful run removes the marker.
//
// With a run record (rec) the record is the authority: the run must have
// completed, must have recorded this tool, and that outcome must be ok with
// the bytes it describes; a failed-run marker beside such a capture is one
// the run could not remove, and the capture is not trusted until a reader
// has removed it (release check of main 60c512c: the grype state file held
// open through a failed run kept an earlier run's `ok` beside the new
// marker, and the replay took the earlier success for the run's). Without a
// record the per-tool state decides, as before the record.
func readCapture(dir, name, kind string, rec *runRecord) ([]byte, string) {
	good := filepath.Join(dir, name+"."+kind+".json")
	failed := filepath.Join(dir, name+"."+kind+".failed.json")
	if rec != nil {
		if !rec.Complete {
			return nil, fmt.Sprintf("offline %s capture %s is not a finished run's: run %s did not complete, and its captures may be from different runs", kind, filepath.Base(good), rec.ID)
		}
		st, ok := rec.Tools[kind]
		if !ok {
			return nil, fmt.Sprintf("offline %s capture %s is not run %s's: the run recorded no %s scan", kind, filepath.Base(good), rec.ID, kind)
		}
		if st.Result != captureOK {
			return nil, fmt.Sprintf("offline %s capture %s is not this run's: the last run %s (%s)", kind, filepath.Base(good), st.Result, st.Reason)
		}
		if _, ferr := os.Stat(failed); ferr == nil {
			return nil, fmt.Sprintf("offline %s capture %s sits beside a failed-run marker run %s could not remove; remove %s after reading it", kind, filepath.Base(good), rec.ID, filepath.Base(failed))
		}
		raw, err := os.ReadFile(good)
		if err != nil {
			return nil, fmt.Sprintf("read offline %s capture: %v", kind, err)
		}
		if st.SHA256 != sha256Hex(raw) {
			return nil, fmt.Sprintf("offline %s capture %s is not the one run %s describes (sha256 %s, recorded %s)", kind, filepath.Base(good), rec.ID, sha256Hex(raw), st.SHA256)
		}
		return raw, ""
	}
	st, serr := readState(dir, name, kind)
	if serr != nil {
		return nil, fmt.Sprintf("read offline %s capture state: %v", kind, serr)
	}
	if st != nil && st.Result != captureOK {
		// The last run's own word, whether or not a capture lies under
		// the good name.
		return nil, fmt.Sprintf("offline %s capture %s is not this run's: the last run %s (%s)", kind, filepath.Base(good), st.Result, st.Reason)
	}
	raw, err := os.ReadFile(good)
	if err != nil {
		return nil, fmt.Sprintf("read offline %s capture: %v", kind, err)
	}
	switch {
	case st == nil:
		// No state beside it: a capture from before the state file, or
		// one unpacked without it. A failed-run marker beside it then
		// cannot be placed in time, and the capture is not trusted.
		if _, ferr := os.Stat(failed); ferr == nil {
			return nil, fmt.Sprintf("offline %s capture %s sits beside a failed-run marker and no state file says which run is later", kind, filepath.Base(good))
		}
		return raw, ""
	case st.SHA256 != sha256Hex(raw):
		return nil, fmt.Sprintf("offline %s capture %s is not the one its state describes (sha256 %s, state %s)", kind, filepath.Base(good), sha256Hex(raw), st.SHA256)
	}
	return raw, ""
}

// writeCaptureFile writes a success capture; a variable so a test can make
// the write fail the way a reader holding the old file open on Windows does
// (release check of main b732cac), without a platform-specific lock.
var writeCaptureFile = func(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }

// captureState is what the last live run left of one tool's capture, in
// <name>.<tool>.state.json beside it. It is the replay's authority, not the
// files' modification times: a capture that moves through a ZIP keeps its
// bytes and loses its times (release check of main b732cac: a failed run's
// capture replayed as a success after unpacking), and a run that could not
// write its capture at all -- the good name held open on Windows -- must
// not leave the earlier success standing as its own. The SHA-256 ties the
// state to the bytes it describes, so a stale good capture a run could not
// replace is told from the one the state is about.
type captureState struct {
	Result string `json:"result"` // captureOK, captureFailed or captureUnsaved
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

const (
	captureOK      = "ok"
	captureFailed  = "failed"
	captureUnsaved = "unsaved"
)

func statePath(dir, name, kind string) string {
	return filepath.Join(dir, name+"."+kind+".state.json")
}

// runRecord is what one live run of one target left in <name>.run.json:
// written with Complete false before the target's first scan and rewritten
// with Complete true and every tool's outcome after its last (run), so a
// replay can tell a directory whose captures all come from one finished run
// from one a run was interrupted in, or could not update. Release check of
// main 60c512c: a second run in a reused directory, killed while trivy ran,
// left its new assay and grype captures beside the first run's trivy
// capture, each with a state of its own saying ok, and the replay judged the
// three together as a pass; and a failed grype run whose state file was held
// open on Windows left the earlier run's `ok` state beside its own failed-run
// marker, and the replay took the earlier success for the run's result. The
// per-tool state files remain for a reader; the record is the replay's
// authority when it exists (readCapture), and a directory with no record --
// a capture from before it, the weekly archive's shape -- is replayed by its
// state files as before. A record that could not be written is reported on
// stderr, and the directory is then not replayable as that run: an
// incomplete record refuses, and no record falls back to the state files.
type runRecord struct {
	ID       string                  `json:"id"`
	Started  string                  `json:"started"`
	Complete bool                    `json:"complete"`
	Tools    map[string]captureState `json:"tools,omitempty"`
}

func newRunRecord() *runRecord {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Time alone still tells two runs apart in practice; the id is
		// a label, never a secret.
		copy(b[:], []byte(time.Now().Format("150405.000")))
	}
	return &runRecord{ID: hex.EncodeToString(b[:]), Started: time.Now().UTC().Format(time.RFC3339), Tools: map[string]captureState{}}
}

func runRecordPath(dir, name string) string {
	return filepath.Join(dir, name+".run.json")
}

func readRunRecord(dir, name string) (*runRecord, error) {
	raw, err := os.ReadFile(runRecordPath(dir, name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec runRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if rec.Tools == nil {
		rec.Tools = map[string]captureState{}
	}
	return &rec, nil
}

// writeRunRecordFile writes the record; a variable so a test can make the
// write fail the way a held-open file on Windows does.
var writeRunRecordFile = func(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }

func writeRunRecord(stderr io.Writer, dir, name string, rec *runRecord) {
	raw, _ := json.Marshal(rec)
	if err := writeRunRecordFile(runRecordPath(dir, name), raw); err != nil {
		fmt.Fprintf(stderr, "warning: write run record %s: %v (the directory is not replayable as this run)\n", runRecordPath(dir, name), err)
	}
}

func readState(dir, name, kind string) (*captureState, error) {
	raw, err := os.ReadFile(statePath(dir, name, kind))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st captureState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// writeStateFile writes a state file; a variable so a test can make the
// write fail the way a reader holding the file open on Windows does.
var writeStateFile = func(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }

func writeState(stderr io.Writer, dir, name, kind string, st captureState) {
	raw, _ := json.Marshal(st)
	if err := writeStateFile(statePath(dir, name, kind), raw); err != nil {
		fmt.Fprintf(stderr, "warning: write capture state %s: %v\n", statePath(dir, name, kind), err)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// captureMismatch is "" when an offline capture records, as the target it
// scanned, the floors file's ref for t: by the argument the tool was given
// (arg -- it must name "@<digest>" when the ref pins one, the whole string
// otherwise) or, when the argument is absent, by a digest the tool
// recorded of the image it read (digests: assay's index and manifest
// digests, grype's manifest, repo and image digests, trivy's repo and image
// digests), which a digest-pinned ref must be among. A capture whose
// argument field was stripped but whose digests name another image passed
// as the pinned ref's (release check 2026-11-11); now the digests decide.
// A capture that records neither -- an assay capture from before D120, a
// tool run on a tag with its argument lost -- cannot be checked and is
// accepted as it was, with a warning saying so: the policy is that an
// unidentifiable capture is replayed, not refused, because nothing in it
// contradicts the ref. Otherwise it says what the capture was a scan of.
func captureMismatch(t Target, arg string, digests []string, tool string, stderr io.Writer) string {
	_, pinned, isPinned := strings.Cut(t.Ref, "@")
	if arg != "" {
		if isPinned {
			if strings.HasSuffix(arg, "@"+pinned) {
				return ""
			}
		} else if arg == t.Ref {
			return ""
		}
		return fmt.Sprintf("offline %s capture is a scan of %q, not of the target's ref %q", tool, arg, t.Ref)
	}
	var recorded []string
	for _, d := range digests {
		if d != "" {
			recorded = append(recorded, d)
		}
	}
	if !isPinned {
		// Nothing to hold a digest to: a ref with no digest is checked by
		// the argument alone, and with none recorded there is nothing to
		// check -- silently, since the fixtures of this package's own
		// tests are that shape and a warning on each would say nothing.
		return ""
	}
	if len(recorded) == 0 {
		fmt.Fprintf(stderr, "warning: target=%s offline %s capture records no target and no digest; accepted unchecked against the pinned ref\n", t.Name, tool)
		return ""
	}
	for _, d := range recorded {
		if d == pinned {
			return ""
		}
	}
	return fmt.Sprintf("offline %s capture records no target and its image digests %v are not the target's pinned %s", tool, recorded, pinned)
}

// trivyOutcome is trivyPhase's result: whether the target's verdict needs
// upgrading because of what the trivy comparison found (or failed to find).
type trivyOutcome int

const (
	trivyOK       trivyOutcome = iota // nothing to report -- held, or informational
	trivyBreached                     // a committed trivy floor tripped
	trivyError                        // trivy itself could not be trusted (committed-floor targets only)
)

// trivyPhase runs (live) or replays (offline) the trivy comparison for one
// target that carries a "trivy" block, judges it against that block, and
// reports on stderr/stdout the same way the primary assay/grype comparison
// does -- see run's own call site for how the returned outcome folds into
// that target's row and the tool's overall exit code.
//
// D105's informational/committed split is entirely inside this function: a
// trivy failure (could not launch, hard failure, malformed JSON) on an
// INFORMATIONAL target (every floor at zero) is reported as a warning and
// never escalates past trivyOK -- there is nothing committed to have
// broken. The identical failure on a target with a real floor is
// trivyError, the same "this target's result cannot be trusted" treatment
// runAssay/runGrype's own fatal paths get.
func trivyPhase(execScan execFunc, trivyBin, captureDir, offlineDir string, live, regressionsOnly bool, t Target, aSet map[tuple]struct{}, rec *runRecord, stdout, stderr io.Writer) trivyOutcome {
	informational := t.Trivy.isZero()

	var trivyRaw []byte
	var fatal string
	if live {
		trivyRaw, fatal = runTrivy(execScan, trivyBin, t)
		rec.Tools["trivy"] = writeCapture(stderr, captureDir, t.Name, "trivy", trivyRaw, fatal == "")
	} else {
		trivyRaw, fatal = readOfflineTrivy(offlineDir, t, rec)
	}

	if fatal != "" {
		if informational {
			fmt.Fprintf(stderr, "warning: target=%s trivy (informational): %s; measurement failed, nothing to paste\n", t.Name, fatal)
			return trivyOK
		}
		fmt.Fprintf(stderr, "error: target=%s trivy %s\n", t.Name, fatal)
		return trivyError
	}

	var tdoc trivyDocument
	if err := json.Unmarshal(trivyRaw, &tdoc); err != nil {
		msg := fmt.Sprintf("malformed trivy JSON: %v", err)
		if informational {
			fmt.Fprintf(stderr, "warning: target=%s trivy (informational): %s\n", t.Name, msg)
			return trivyOK
		}
		fmt.Fprintf(stderr, "error: target=%s %s\n", t.Name, msg)
		return trivyError
	}
	// Judged by shape live and offline (as grype's is in run): a
	// diagnostic object is no measurement, so an informational target
	// prints no numbers to paste and a committed one is an ERROR.
	if why := trivyShape(trivyRaw); why != "" {
		msg := "malformed trivy JSON: " + why
		if informational {
			fmt.Fprintf(stderr, "warning: target=%s trivy (informational): %s; measurement failed, nothing to paste\n", t.Name, msg)
			return trivyOK
		}
		fmt.Fprintf(stderr, "error: target=%s %s\n", t.Name, msg)
		return trivyError
	}

	if !live {
		if why := captureMismatch(t, tdoc.ArtifactName, tdoc.digests(), "trivy", stderr); why != "" {
			if informational {
				fmt.Fprintf(stderr, "warning: target=%s trivy (informational): %s\n", t.Name, why)
				return trivyOK
			}
			fmt.Fprintf(stderr, "error: target=%s %s\n", t.Name, why)
			return trivyError
		}
	}
	tSet := trivyTuples(tdoc)
	agree, _, _ := compareSets(aSet, tSet)
	findings := len(tSet)

	if informational {
		snippet, _ := json.Marshal(TrivyFloors{MinAgree: agree, MinFindings: findings, MaxFindings: findings})
		fmt.Fprintf(stderr, "info: target=%s trivy measured (informational; paste into scanner-diff-targets.json):\n", t.Name)
		fmt.Fprintf(stdout, "%s\n", snippet)
		return trivyOK
	}

	breaches, info := demoteCeilings(judgeTrivy(t, agree, findings), regressionsOnly)
	printInfo(stderr, info)
	if len(breaches) == 0 {
		return trivyOK
	}
	for _, b := range breaches {
		fmt.Fprintln(stderr, b.String())
	}
	return trivyBreached
}

// runTrivy runs `trivy image --format json --quiet <ref>`. Same
// probe-before-trusting-the-exit-code shape as runGrype (see its own
// comment): trivy is run with no --exit-code gate configured here, so 0 is
// the expected exit, but output that parses as JSON is trusted regardless
// of the exit code, and a nonzero exit is only a hard failure once parsing
// has already failed.
//
// An empty bin is a configuration fault, not a launch failure, and is
// reported without ever calling execScan: -trivy may legitimately be
// omitted when no target needs it, so this has to be a per-target fatal
// reason (checked here, where a target that DOES need it is known), not a
// blanket "live mode requires -trivy" refusal at the top of run.
func runTrivy(execScan execFunc, bin string, t Target) (out []byte, fatal string) {
	if bin == "" {
		return nil, "-trivy binary not configured"
	}
	out, code, err := execScan(bin, "image", "--format", "json", "--quiet", t.Ref)
	if err != nil {
		return out, fmt.Sprintf("trivy: could not run: %v", err)
	}
	var probe json.RawMessage
	if uerr := json.Unmarshal(out, &probe); uerr != nil {
		if code != 0 {
			return out, fmt.Sprintf("trivy hard failure (exit %d)", code)
		}
		return out, "malformed trivy JSON"
	}
	// JSON that is not a trivy report with a nonzero exit is the hard
	// failure the exit says (release check of main 5197df4: the diagnostic
	// object had been measured as 0 findings -- a BREACH on a committed
	// floor, a measurement on an informational one).
	if code != 0 && trivyShape(out) != "" {
		return out, fmt.Sprintf("trivy hard failure (exit %d)", code)
	}
	return out, ""
}

// readOfflineTrivy replays a previously captured trivy JSON document,
// mirroring readOffline. A target with a trivy block but no captured
// <name>.trivy.json is reported exactly like a missing assay/grype capture
// -- named by target, not silently treated as zero findings, which would
// let a committed-floor target quietly go unjudged.
func readOfflineTrivy(dir string, t Target, rec *runRecord) (out []byte, fatal string) {
	return readCapture(dir, t.Name, "trivy", rec)
}

// printInfo writes one line per ceiling -regressions-only did not judge. Both
// comparisons call it, so a demoted grype-side and trivy-side ceiling read the
// same in a nightly log. It prints before the target's breach lines so a
// reader scanning one target's block sees what was set aside first.
func printInfo(stderr io.Writer, info []breach) {
	for _, b := range info {
		fmt.Fprintln(stderr, b.infoString())
	}
}

// writeCapture persists one raw scan document for later human review
// (uploaded as a CI artifact by the workflow). A write failure is reported
// on stderr but never fails the run -- a full disk should not turn a
// passing differential into an untrustworthy one, and the run's own
// judgment does not depend on this file existing.
//
// A scan that failed (ok false: assay exited 2 after its retry, grype or
// trivy a hard failure) is filed as <name>.<kind>.failed.json: still there
// for a human to read, but not under the name -offline replays, so a
// document assay wrote beside its exit 2 cannot pass the gate offline when
// it failed it live (release check 2026-11-11). The good name is removed
// too, so a stale capture from an earlier run in the same directory does
// not stand in for the failed one.
//
// A successful run removes the failed marker of an earlier one, and a failed
// run's marker is what a replay trusts when the good name could not be
// removed (readCapture): each replay reflects the last run.
//
// The state file (captureState) is written LAST and describes what is on
// disk: a success whose capture could not be written leaves the state
// "unsaved", so the replay does not take an earlier success's bytes for this
// run's; a failed run leaves "failed" whether or not the good name could be
// removed; a success removes the failed-run marker and records the bytes'
// SHA-256.
func writeCapture(stderr io.Writer, dir, name, kind string, data []byte, ok bool) captureState {
	path := filepath.Join(dir, name+"."+kind+".json")
	failed := filepath.Join(dir, name+"."+kind+".failed.json")
	var st captureState
	switch {
	case !ok:
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "warning: remove stale capture %s: %v\n", path, err)
		}
		if err := os.WriteFile(failed, data, 0o644); err != nil {
			fmt.Fprintf(stderr, "warning: write capture %s: %v\n", failed, err)
		}
		st = captureState{Result: captureFailed, Reason: "the scan failed; its output is in " + filepath.Base(failed)}
	default:
		if err := writeCaptureFile(path, data); err != nil {
			fmt.Fprintf(stderr, "warning: write capture %s: %v\n", path, err)
			st = captureState{Result: captureUnsaved, Reason: "the scan succeeded but its capture could not be written: " + err.Error()}
			break
		}
		if err := os.Remove(failed); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "warning: remove failed-run marker %s: %v\n", failed, err)
		}
		st = captureState{Result: captureOK, SHA256: sha256Hex(data)}
	}
	// The state file is written whatever the outcome; the run record
	// (runRecord) carries the same state and is written by the caller.
	writeState(stderr, dir, name, kind, st)
	return st
}

// renderTable writes the one thing that goes to stdout: every target's row,
// so a breach on target 4 of 13 does not hide what targets 1-3 and 5-13
// measured (D93's "still runs the rest" requirement, made visible).
func renderTable(w io.Writer, rows []row) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tASSAY\tGRYPE\tA_BRIDGED\tG_BRIDGED\tAGREE\tONLY_ASSAY\tONLY_GRYPE\tNOTEVAL\tVERDICT")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n",
			r.Target, r.AssayTuples, r.GrypeTuples, r.BridgedIntoAssay, r.BridgedIntoGrype, r.Agree, r.OnlyAssay, r.OnlyGrype, r.NotEvaluated, r.Verdict)
	}
	tw.Flush()
}
