package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

// Exit codes, assay's own contract (D11): 0 every matcher-class label held,
// 1 at least one did not, 2 the run itself could not be trusted (a scan
// exited 2, the labels did not load, an output could not be written).
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

const usage = `usage: truthset [-labels FILE] [-assay BIN] [-out REPORT.json] [-keep DIR | -offline DIR]

Scans every labelled package (one one-component CycloneDX SBOM per case,
written to a temporary directory or -keep DIR) with assay, judges each
label against the finding assay reports for its CVE, and prints precision
and recall per family with a 95% Wilson interval. -offline DIR re-judges
the scan outputs a previous -keep run left (<case>.scan.json) without
running assay, so a failing run can be read again locally.

Exit 0: every matcher-class label held. 1: at least one did not (a false
positive, a miss, or a fixed version that differs). 2: the run itself
cannot be trusted -- labels did not load, a scan exited 2, or a file could
not be written. Data-class labels (known data gaps) are printed and kept
out of both the metrics and the exit code.
`

// execFunc is the seam between run and the real assay binary: a test
// supplies a fake. out is the child's stdout, exitCode its exit status, and
// err is non-nil only when it could not be started at all.
type execFunc func(bin string, args ...string) (out []byte, exitCode int, err error)

// Outcomes. TP/TN/FP/FN are the confusion matrix on matcher-class labels;
// MISMATCH is an affected label found with a different fixed version (a
// finding, but the wrong one -- a false positive about the fix and a false
// negative about the real one, counted as a failure and in neither cell);
// UNEVALUATED is a label whose package the scan could not judge at all
// (summary.evaluated 0), which is neither clean nor affected; ERROR is a
// scan that did not finish.
const (
	outTP          = "TP"
	outTN          = "TN"
	outFP          = "FP"
	outFN          = "FN"
	outMismatch    = "MISMATCH"
	outUnevaluated = "UNEVALUATED"
	outError       = "ERROR"
)

// result is one judged label.
type result struct {
	Label   Label  `json:"label"`
	Outcome string `json:"outcome"`
	// Got is what the scan said: the fixed version and fix state of the
	// finding for this CVE, or "" when there was none.
	GotFixed    string `json:"gotFixed,omitempty"`
	GotFixState string `json:"gotFixState,omitempty"`
	GotFrozen   string `json:"gotFrozenSince,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// familyMetrics is the confusion matrix and the two rates, with intervals,
// for the matcher-class labels of one family (or of all).
type familyMetrics struct {
	Family          string  `json:"family"`
	Labels          int     `json:"labels"`
	TP              int     `json:"tp"`
	TN              int     `json:"tn"`
	FP              int     `json:"fp"`
	FN              int     `json:"fn"`
	Mismatch        int     `json:"mismatch"`
	Unevaluated     int     `json:"unevaluated"`
	Errors          int     `json:"errors"`
	Precision       float64 `json:"precision"`
	PrecisionLow95  float64 `json:"precisionLow95"`
	PrecisionHigh95 float64 `json:"precisionHigh95"`
	Recall          float64 `json:"recall"`
	RecallLow95     float64 `json:"recallLow95"`
	RecallHigh95    float64 `json:"recallHigh95"`
}

// report is the JSON -out document: a tool artifact like scandiff's
// capture, versioned on its own so a reader can tell its shape; the
// `truthset report` row of docs/compatibility.md follows this constant.
type report struct {
	SchemaVersion int             `json:"schemaVersion"`
	Labels        string          `json:"labelsFile"`
	Database      string          `json:"databaseDigest,omitempty"`
	Tool          string          `json:"toolVersion,omitempty"`
	Families      []familyMetrics `json:"families"`
	Total         familyMetrics   `json:"total"`
	Results       []result        `json:"results"`
	DataClass     []result        `json:"dataClass"`
}

const reportSchemaVersion = 1

func run(args []string, stdout, stderr io.Writer, execScan execFunc) int {
	fs := flag.NewFlagSet("truthset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	labelsPath := fs.String("labels", "testdata/groundtruth/labels.json", "labels file")
	assayBin := fs.String("assay", "./bin/assay", "assay binary")
	outPath := fs.String("out", "", "write the JSON report here")
	keepDir := fs.String("keep", "", "keep each case's SBOM and scan output in this directory")
	offlineDir := fs.String("offline", "", "re-judge the scan outputs in this directory instead of running assay")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "error: unexpected argument %q\n", fs.Arg(0))
		fmt.Fprint(stderr, usage)
		return exitError
	}
	if *keepDir != "" && *offlineDir != "" {
		fmt.Fprintln(stderr, "error: -keep and -offline are exclusive")
		return exitError
	}

	labels, err := loadLabels(*labelsPath)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}

	// One scan per case: every label of a case shares its purl.
	workDir := *keepDir
	if workDir == "" && *offlineDir == "" {
		d, err := os.MkdirTemp("", "truthset-")
		if err != nil {
			fmt.Fprintf(stderr, "error: temp dir: %v\n", err)
			return exitError
		}
		defer os.RemoveAll(d)
		workDir = d
	}
	if workDir != "" {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
	}

	cases := casesOf(labels)
	scans := map[string]*scanDoc{}
	fatal := map[string]string{}
	var digest, tool string
	for _, c := range cases {
		var raw []byte
		if *offlineDir != "" {
			raw, err = os.ReadFile(filepath.Join(*offlineDir, c.name+".scan.json"))
			if err != nil {
				fatal[c.name] = fmt.Sprintf("offline: %v", err)
				continue
			}
		} else {
			sbomPath := filepath.Join(workDir, c.name+".cdx.json")
			if err := os.WriteFile(sbomPath, sbomFor(c.label), 0o644); err != nil {
				fmt.Fprintf(stderr, "error: write %s: %v\n", sbomPath, err)
				return exitError
			}
			var code int
			raw, code, err = execScan(*assayBin, "scan", sbomPath, "--output", "json")
			switch {
			case err != nil:
				fatal[c.name] = fmt.Sprintf("assay could not run: %v", err)
			case code == exitError:
				fatal[c.name] = "assay scan exited 2 (untrustworthy result)"
			case code != exitOK && code != exitFindings:
				fatal[c.name] = fmt.Sprintf("assay scan exited unexpected code %d", code)
			}
			if *keepDir != "" && len(raw) > 0 {
				if err := os.WriteFile(filepath.Join(workDir, c.name+".scan.json"), raw, 0o644); err != nil {
					fmt.Fprintf(stderr, "error: write scan output: %v\n", err)
					return exitError
				}
			}
			if fatal[c.name] != "" {
				fmt.Fprintf(stderr, "error: case=%s %s\n", c.name, fatal[c.name])
				continue
			}
		}
		var doc scanDoc
		if err := json.Unmarshal(raw, &doc); err != nil {
			fatal[c.name] = fmt.Sprintf("malformed assay JSON: %v", err)
			fmt.Fprintf(stderr, "error: case=%s %s\n", c.name, fatal[c.name])
			continue
		}
		scans[c.name] = &doc
		if digest == "" {
			digest, tool = doc.Provenance.Database.Artifact.Digest, doc.Provenance.Tool.Version
		}
	}

	var results, dataClass []result
	for _, l := range labels {
		r := judge(l, scans[l.Case], fatal[l.Case])
		if l.Class == "data" {
			dataClass = append(dataClass, r)
		} else {
			results = append(results, r)
		}
	}

	families := metricsByFamily(results)
	total := metricsOf("all", results)
	printTable(stdout, results, dataClass, families, total)

	if *outPath != "" {
		rep := report{SchemaVersion: reportSchemaVersion, Labels: *labelsPath, Database: digest, Tool: tool,
			Families: families, Total: total, Results: results, DataClass: dataClass}
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
		if err := os.WriteFile(*outPath, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintf(stderr, "error: write %s: %v\n", *outPath, err)
			return exitError
		}
	}

	if len(fatal) > 0 {
		return exitError
	}
	if total.FP+total.FN+total.Mismatch+total.Unevaluated > 0 {
		return exitFindings
	}
	return exitOK
}

// scanDoc is the slice of assay's JSON report this tool reads. A local type,
// not report.Document: a renamed field shows up here as a zero value and a
// failing label, not as a silent compile-through, and the tool stays
// stdlib-only.
type scanDoc struct {
	SchemaVersion int `json:"schemaVersion"`
	Summary       struct {
		Components int `json:"components"`
		Evaluated  int `json:"evaluated"`
	} `json:"summary"`
	Findings []struct {
		Package struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"package"`
		MatchedName string `json:"matchedName"`
		FrozenSince string `json:"frozenSince"`
		Advisory    struct {
			ID       string   `json:"id"`
			Aliases  []string `json:"aliases"`
			Upstream []string `json:"upstream"`
		} `json:"advisory"`
		Evidence struct {
			Fixed string `json:"fixed"`
		} `json:"evidence"`
		FixState string `json:"fixState"`
	} `json:"findings"`
	Provenance struct {
		Tool struct {
			Version string `json:"version"`
		} `json:"tool"`
		Database struct {
			Artifact struct {
				Digest string `json:"digest"`
			} `json:"artifact"`
		} `json:"database"`
	} `json:"provenance"`
}

type caseGroup struct {
	name  string
	label Label // any label of the case: they share purl, name and version
}

func casesOf(labels []Label) []caseGroup {
	seen := map[string]bool{}
	var out []caseGroup
	for _, l := range labels {
		if seen[l.Case] {
			continue
		}
		seen[l.Case] = true
		out = append(out, caseGroup{name: l.Case, label: l})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// sbomFor is the one-component CycloneDX document a label's package is
// scanned as: the shape the 2026-11-04 QA harness used, which keys the
// package through the purl's distro qualifier exactly as an image scan's
// own purl would (D121).
func sbomFor(l Label) []byte {
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"components": []map[string]any{{
			"type": "library", "name": l.Name, "version": l.Version, "purl": l.PURL,
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

// judge is one label against one scan. A finding "is this CVE" when the id,
// an alias or an upstream id equals it (D3: OSV puts the CVE in upstream),
// and it is this label's package when the package name or the matched name
// is the label's (a binary matched through its source keeps the installed
// name in package.name).
func judge(l Label, doc *scanDoc, fatal string) result {
	r := result{Label: l}
	if fatal != "" {
		r.Outcome, r.Detail = outError, fatal
		return r
	}
	if doc == nil {
		r.Outcome, r.Detail = outError, "no scan output for this case"
		return r
	}
	if doc.Summary.Evaluated == 0 {
		r.Outcome, r.Detail = outUnevaluated, fmt.Sprintf("the scan evaluated 0 of %d component(s)", doc.Summary.Components)
		return r
	}
	var found bool
	for _, f := range doc.Findings {
		if f.Package.Name != l.Name && f.MatchedName != l.Name {
			continue
		}
		if !namesCVE(f.Advisory.ID, f.Advisory.Aliases, f.Advisory.Upstream, l.CVE) {
			continue
		}
		found = true
		r.GotFixed, r.GotFixState, r.GotFrozen = f.Evidence.Fixed, f.FixState, f.FrozenSince
		break
	}
	switch {
	case l.Expect.State == "clean" && !found:
		r.Outcome = outTN
	case l.Expect.State == "clean" && found:
		r.Outcome, r.Detail = outFP, fmt.Sprintf("reported (fixed=%q, fixState=%s), label says clean", r.GotFixed, r.GotFixState)
	case !found:
		r.Outcome, r.Detail = outFN, "not reported, label says affected"
	case l.Expect.Fixed != "" && r.GotFixed != l.Expect.Fixed:
		r.Outcome, r.Detail = outMismatch, fmt.Sprintf("fixed=%q, label says %q", r.GotFixed, l.Expect.Fixed)
	default:
		r.Outcome = outTP
	}
	return r
}

func namesCVE(id string, aliases, upstream []string, cve string) bool {
	if strings.EqualFold(id, cve) {
		return true
	}
	for _, a := range aliases {
		if strings.EqualFold(a, cve) {
			return true
		}
	}
	for _, u := range upstream {
		if strings.EqualFold(u, cve) {
			return true
		}
	}
	return false
}

func metricsByFamily(rs []result) []familyMetrics {
	by := map[string][]result{}
	for _, r := range rs {
		by[r.Label.Family] = append(by[r.Label.Family], r)
	}
	fams := make([]string, 0, len(by))
	for f := range by {
		fams = append(fams, f)
	}
	sort.Strings(fams)
	out := make([]familyMetrics, 0, len(fams))
	for _, f := range fams {
		out = append(out, metricsOf(f, by[f]))
	}
	return out
}

// metricsOf folds outcomes into the confusion matrix. Precision is
// TP/(TP+FP), recall TP/(TP+FN); a MISMATCH is in neither numerator -- it is
// a wrong answer -- and is reported as its own count, as are UNEVALUATED
// and ERROR, so the two rates never hide a label that got no verdict.
func metricsOf(family string, rs []result) familyMetrics {
	m := familyMetrics{Family: family, Labels: len(rs)}
	for _, r := range rs {
		switch r.Outcome {
		case outTP:
			m.TP++
		case outTN:
			m.TN++
		case outFP:
			m.FP++
		case outFN:
			m.FN++
		case outMismatch:
			m.Mismatch++
		case outUnevaluated:
			m.Unevaluated++
		case outError:
			m.Errors++
		}
	}
	if m.TP+m.FP > 0 {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
		m.PrecisionLow95, m.PrecisionHigh95 = wilson(m.TP, m.TP+m.FP)
	}
	if m.TP+m.FN > 0 {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
		m.RecallLow95, m.RecallHigh95 = wilson(m.TP, m.TP+m.FN)
	}
	return m
}

// printTable writes the summary: one line per family and a total, the
// labels that did not hold (never the ones that did -- a 400-row table
// nobody reads is the failure scandiff's own design avoids), and the
// data-class rows with their outcome.
func printTable(w io.Writer, results, dataClass []result, families []familyMetrics, total familyMetrics) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "FAMILY\tLABELS\tTP\tTN\tFP\tFN\tMISMATCH\tUNEVAL\tERROR\tPRECISION (95% CI)\tRECALL (95% CI)")
	for _, m := range append(families, total) {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", m.Family, m.Labels, m.TP, m.TN, m.FP, m.FN, m.Mismatch, m.Unevaluated, m.Errors,
			rate(m.TP+m.FP, m.Precision, m.PrecisionLow95, m.PrecisionHigh95), rate(m.TP+m.FN, m.Recall, m.RecallLow95, m.RecallHigh95))
	}
	tw.Flush()

	var failed []result
	for _, r := range results {
		if r.Outcome != outTP && r.Outcome != outTN {
			failed = append(failed, r)
		}
	}
	if len(failed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "labels that did not hold:")
		for _, r := range failed {
			fmt.Fprintf(w, "  %-11s %s -- %s\n", r.Outcome, r.Label.ID, r.Detail)
		}
	}
	if len(dataClass) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "data-class labels (known data gaps, not in the metrics):")
		for _, r := range dataClass {
			d := r.Detail
			if d == "" {
				d = "holds"
				if r.Outcome == outTP || r.Outcome == outTN {
					d = "holds -- the data gap this label records may have closed; reclassify it"
				}
			}
			fmt.Fprintf(w, "  %-11s %s -- %s\n", r.Outcome, r.Label.ID, d)
		}
	}
}

func rate(n int, p, lo, hi float64) string {
	if n == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f (%.3f-%.3f)", p, lo, hi)
}
