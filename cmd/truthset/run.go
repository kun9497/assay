package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
out of both the metrics and the exit code, as is a label whose key the
database dates before the label's validFrom (listed as not judged).
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
	// outPredates is a label the database cannot judge: the data for the
	// label's key is as of a date before the label's validFrom, so neither
	// a finding nor its absence is evidence. Listed, counted in the report,
	// and in neither the metrics nor the exit code.
	outPredates = "PREDATES"
	// outFixUnknown is an affected label whose finding proves the package
	// is affected while a skipped comparison for the same CVE leaves the
	// fixed version undetermined (QA 2026-11-10): the verdict holds, the
	// fix the label demands cannot be confirmed. Counted with UNEVALUATED.
	outFixUnknown = "FIX-UNKNOWN"
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
	Family      string `json:"family"`
	Labels      int    `json:"labels"`
	TP          int    `json:"tp"`
	TN          int    `json:"tn"`
	FP          int    `json:"fp"`
	FN          int    `json:"fn"`
	Mismatch    int    `json:"mismatch"`
	Unevaluated int    `json:"unevaluated"`
	Errors      int    `json:"errors"`
	// Predates counts the labels the database's data predates (validFrom);
	// they are not in Labels, which counts the labels judged.
	Predates        int     `json:"predates"`
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

// 2: familyMetrics.predates and the PREDATES outcome (additive).
// 3: the FIX-UNKNOWN outcome, counted in unevaluated (QA 2026-11-10): a new
// value in results[].outcome, so a consumer switching on it must learn it.
const reportSchemaVersion = 3

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
			// A kept exit code of 2 is the fatal it was live; a capture from
			// before .exit files were written has none and is read as before.
			if b, err := os.ReadFile(filepath.Join(*offlineDir, c.name+".exit")); err == nil {
				code, err := strconv.Atoi(strings.TrimSpace(string(b)))
				if err != nil {
					fatal[c.name] = fmt.Sprintf("offline: %s.exit: %v", c.name, err)
					continue
				}
				if why := fatalExit(code); why != "" {
					fatal[c.name] = "kept " + why
					fmt.Fprintf(stderr, "error: case=%s %s\n", c.name, fatal[c.name])
					continue
				}
			}
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
			// --config none: a .assay.yaml in whatever directory this runs
			// from would move a labelled finding into suppressed[], which is
			// not read here, and a waiver would be judged as the matcher's
			// verdict. The labels are the only thing allowed to say "clean".
			var code int
			raw, code, err = execScan(*assayBin, "scan", sbomPath, "--output", "json", "--config", scancmdIgnoreNone)
			if err != nil {
				fatal[c.name] = fmt.Sprintf("assay could not run: %v", err)
			} else if why := fatalExit(code); why != "" {
				fatal[c.name] = why
			}
			if *keepDir != "" {
				// The exit code goes beside the output: assay renders its JSON
				// and THEN exits 2 on an untrustworthy result, so the document
				// alone would read as trustworthy to -offline.
				if err := os.WriteFile(filepath.Join(workDir, c.name+".exit"), []byte(fmt.Sprintf("%d\n", code)), 0o644); err != nil {
					fmt.Fprintf(stderr, "error: write scan exit: %v\n", err)
					return exitError
				}
				if len(raw) > 0 {
					if err := os.WriteFile(filepath.Join(workDir, c.name+".scan.json"), raw, 0o644); err != nil {
						fmt.Fprintf(stderr, "error: write scan output: %v\n", err)
						return exitError
					}
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
		// Every case must have been judged against one database: a `db
		// update` landing between two scans would attribute a label flip to
		// the matcher. The first document's digest is the run's.
		if d := doc.Provenance.Database.Artifact.Digest; digest != "" && d != digest {
			fatal[c.name] = fmt.Sprintf("database digest %s differs from the run's first, %s", d, digest)
			fmt.Fprintf(stderr, "error: case=%s %s\n", c.name, fatal[c.name])
			continue
		}
		// One component, one key: a document that maps it to several keys
		// is a shape this tool does not know how to date, so it is not
		// trusted rather than dated by whichever record came first.
		if len(doc.Coverage) > 1 {
			fatal[c.name] = fmt.Sprintf("%d coverage keys for a one-component SBOM", len(doc.Coverage))
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
	if total.Predates > 0 {
		fmt.Fprintf(stderr, "note: %d label(s) not judged: the database's data predates their validFrom\n", total.Predates)
	}

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
	// A run that judged nothing says nothing: every matcher label predates
	// the database. That is a stale database, not a clean one -- CI must
	// not read "found nothing" as "held" (D11).
	if total.Labels == 0 && len(results) > 0 {
		fmt.Fprintln(stderr, "error: no label could be judged: the database's data predates every label's validFrom")
		return exitError
	}
	if total.FP+total.FN+total.Mismatch+total.Unevaluated > 0 {
		return exitFindings
	}
	return exitOK
}

// scancmdIgnoreNone is scancmd.IgnoreNone, spelled here so this package
// stays stdlib-only and free of the scanner's own imports.
const scancmdIgnoreNone = "none"

// fatalExit says why an assay exit code makes the case's result untrustworthy,
// or "" for the two codes that carry a verdict (0 clean, 1 findings).
func fatalExit(code int) string {
	switch {
	case code == exitError:
		return "assay scan exited 2 (untrustworthy result)"
	case code != exitOK && code != exitFindings:
		return fmt.Sprintf("assay scan exited unexpected code %d", code)
	}
	return ""
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
			// Related (schema 20) is where Amazon ALAS, Fedora Bodhi and
			// Oracle OVAL records name their CVEs.
			Related []string `json:"related"`
		} `json:"advisory"`
		Evidence struct {
			Fixed string `json:"fixed"`
		} `json:"evidence"`
		FixState string `json:"fixState"`
		// Ratings carry each database's own advisory id; NVD's and EPSS's
		// is the CVE. The join of last resort (findingNamesCVE), so a
		// document from before schema 20 still reaches an ALAS finding's
		// CVE when an annotation source rated it.
		Ratings []rating `json:"ratings"`
	} `json:"findings"`
	// Coverage is the per-key data date (schema 17, D113 revised): the
	// scan's one component maps to one key, and its dataAsOf is what
	// validFrom is held against.
	// Skipped is the scan's own record of the comparisons it could not
	// make. A label whose CVE was among them cannot be judged clean or
	// missed from the findings alone (QA 2026-11-10).
	Skipped []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		AdvisoryID string `json:"advisoryId"`
		// CVEs (schema 21) are the CVEs the skipped advisory names.
		CVEs []string `json:"cves"`
	} `json:"skipped"`
	Coverage []struct {
		Ecosystem   string `json:"ecosystem"`
		DataAsOf    string `json:"dataAsOf"`
		FrozenSince string `json:"frozenSince"`
	} `json:"coverage"`
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
// name in package.name). Every such finding is read, not the first: two
// records for one CVE that share no id (a native Leap record beside a D108
// cross-mapped one) arrive as two findings, and which came first is not a
// verdict (D25). Their distinct fixed versions are joined, so a label that
// demands one is a MISMATCH naming both, and the detail says so.
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
	// validFrom: a database whose data for the key is older than the day
	// the expectation is known to hold at cannot confirm or refute it. Only
	// a dated key is compared; an undated one (a database from before
	// schema 17) is judged as before.
	// `== 1` is intent, not behaviour: run refuses a document with more
	// than one coverage record before it reaches judge, so `>= 1` reads
	// the same here (an equivalent mutation, verified 2026-11-09).
	if l.ValidFrom != "" && len(doc.Coverage) == 1 {
		c := doc.Coverage[0]
		// A D110-frozen key's data is as of its freeze, whatever the
		// provider's own date says (dbage.go's oldestProvider makes the
		// same correction): the earlier of the two is the key's date.
		asOf := c.DataAsOf
		if c.FrozenSince != "" && (asOf == "" || c.FrozenSince < asOf) {
			asOf = c.FrozenSince
		}
		if asOf != "" && asOf < l.ValidFrom {
			r.Outcome, r.Detail = outPredates, fmt.Sprintf("%s data is as of %s, before the label's validFrom %s", c.Ecosystem, asOf, l.ValidFrom)
			return r
		}
	}
	var found bool
	var fixes, states, frozen []string
	for _, f := range doc.Findings {
		if f.Package.Name != l.Name && f.MatchedName != l.Name {
			continue
		}
		if !findingNamesCVE(f.Advisory.ID, f.Advisory.Aliases, f.Advisory.Upstream, f.Advisory.Related, f.Ratings, l.CVE) {
			continue
		}
		found = true
		fixes = appendDistinct(fixes, f.Evidence.Fixed)
		states = appendDistinct(states, f.FixState)
		frozen = appendDistinct(frozen, f.FrozenSince)
	}
	r.GotFixed, r.GotFixState, r.GotFrozen = strings.Join(fixes, " | "), strings.Join(states, " | "), strings.Join(frozen, " | ")
	// A comparison the scan skipped for this package can leave the label's
	// CVE unjudged. It does when the skip names the CVE, or when it cannot
	// be told apart from one that does: a whole-package skip, or an
	// advisory id that is not a CVE with no cves list (a capture from
	// before schema 21, or an advisory naming no CVE). A skip that names
	// other CVEs only is about them, and changes nothing here.
	skip := skipFor(doc, l)
	switch {
	case skip != "" && found && l.Expect.State == "affected" && l.Expect.Fixed != "":
		// Affected is proven by the finding; which fix the skipped
		// comparison would have named is not.
		r.Outcome, r.Detail = outFixUnknown, fmt.Sprintf("affected (fixed=%q), but %s, so the fixed version is undetermined", r.GotFixed, skip)
		return r
	case skip != "" && !found:
		// Neither clean nor a miss: the comparison that would decide it
		// did not run.
		r.Outcome, r.Detail = outUnevaluated, fmt.Sprintf("not reported, but %s", skip)
		return r
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
		if len(fixes) > 1 {
			r.Detail += fmt.Sprintf(" (the findings for this CVE name %d different fixes)", len(fixes))
		}
	default:
		r.Outcome = outTP
	}
	return r
}

// skipFor describes the scan's skip that can leave l's CVE unjudged, or ""
// when no skip for l's package can.
func skipFor(doc *scanDoc, l Label) string {
	for _, s := range doc.Skipped {
		if s.Package.Name != l.Name {
			continue
		}
		switch {
		case s.AdvisoryID == "":
			return "the scan skipped the whole package"
		case strings.EqualFold(s.AdvisoryID, l.CVE):
			return fmt.Sprintf("the scan skipped %s", s.AdvisoryID)
		}
		for _, c := range s.CVEs {
			if strings.EqualFold(c, l.CVE) {
				return fmt.Sprintf("the scan skipped %s, which names %s", s.AdvisoryID, l.CVE)
			}
		}
		if len(s.CVEs) == 0 && !strings.HasPrefix(strings.ToUpper(s.AdvisoryID), "CVE-") {
			return fmt.Sprintf("the scan skipped %s and the report does not say which CVEs it names", s.AdvisoryID)
		}
	}
	return ""
}

// appendDistinct keeps the first occurrence of each value, in arrival order,
// so a joined field reads the way the report listed it.
func appendDistinct(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// findingNamesCVE reports whether a finding is about cve. The record's own
// identifiers decide when any of them is a CVE: its id, aliases, upstream
// (D3) and related (schema 20, D164). Only a finding whose own identifiers
// name no CVE at all -- an ALAS / ELSA / Bodhi finding in a document from
// before schema 20 -- falls back to the ratings' advisory ids, which the
// annotation sources key by CVE. A union would let an annotation carried
// for another CVE make this finding answer for it.
func findingNamesCVE(id string, aliases, upstream, related []string, ratings []rating, cve string) bool {
	own := false
	for _, l := range [][]string{{id}, aliases, upstream, related} {
		for _, s := range l {
			if strings.EqualFold(s, cve) {
				return true
			}
			if strings.HasPrefix(strings.ToUpper(s), "CVE-") {
				own = true
			}
		}
	}
	if own {
		return false
	}
	for _, r := range ratings {
		if strings.EqualFold(r.AdvisoryID, cve) {
			return true
		}
	}
	return false
}

// rating is the slice of a finding's rating the CVE join reads.
type rating struct {
	AdvisoryID string `json:"advisoryId"`
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
// TP/(TP+FP+MISMATCH), recall TP/(TP+FN+MISMATCH): a MISMATCH is a finding
// that was reported (so it counts against precision, as a wrong report) for
// a label that was affected (so it counts against recall, as the right
// verdict not produced), and in neither numerator -- a run that named every
// fix wrong must not print 1.000 on the boundary this tool exists to
// measure. UNEVALUATED and ERROR are reported as their own counts, outside
// both rates, so a label that got no verdict is never hidden in one.
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
		case outUnevaluated, outFixUnknown:
			m.Unevaluated++
		case outError:
			m.Errors++
		case outPredates:
			// Not judged: out of Labels, so the table's count is of labels
			// the database could speak to.
			m.Predates++
			m.Labels--
		}
	}
	if n := m.TP + m.FP + m.Mismatch; n > 0 {
		m.Precision = float64(m.TP) / float64(n)
		m.PrecisionLow95, m.PrecisionHigh95 = wilson(m.TP, n)
	}
	if n := m.TP + m.FN + m.Mismatch; n > 0 {
		m.Recall = float64(m.TP) / float64(n)
		m.RecallLow95, m.RecallHigh95 = wilson(m.TP, n)
	}
	return m
}

// printTable writes the summary: one line per family and a total, the
// labels that did not hold (never the ones that did -- a 400-row table
// nobody reads is the failure scandiff's own design avoids), and the
// data-class rows with their outcome.
func printTable(w io.Writer, results, dataClass []result, families []familyMetrics, total familyMetrics) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "FAMILY\tLABELS\tTP\tTN\tFP\tFN\tMISMATCH\tUNEVAL\tERROR\tPREDATES\tPRECISION (95% CI)\tRECALL (95% CI)")
	for _, m := range append(families, total) {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n", m.Family, m.Labels, m.TP, m.TN, m.FP, m.FN, m.Mismatch, m.Unevaluated, m.Errors, m.Predates,
			rate(m.TP+m.FP+m.Mismatch, m.Precision, m.PrecisionLow95, m.PrecisionHigh95), rate(m.TP+m.FN+m.Mismatch, m.Recall, m.RecallLow95, m.RecallHigh95))
	}
	tw.Flush()

	var failed []result
	for _, r := range results {
		if r.Outcome != outTP && r.Outcome != outTN && r.Outcome != outPredates {
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
	var predates []result
	for _, r := range results {
		if r.Outcome == outPredates {
			predates = append(predates, r)
		}
	}
	if len(predates) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "labels not judged (the database's data predates their validFrom):")
		for _, r := range predates {
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
