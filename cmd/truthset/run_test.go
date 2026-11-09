package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Caller first (CLAUDE.md): every test here drives run() with a fake assay,
// and asserts the table, the exit code and the JSON report -- never the
// judge or the metrics directly, except where a branch no scan can reach.

// fakeScan is what the fake assay returns for one case: the findings its
// report carries, keyed by the package's purl found in the SBOM run was
// handed. exit is the process exit code (0 or 1 complete, 2 untrustworthy).
type fakeScan struct {
	findings  []fakeFinding
	exit      int
	evaluated int
	raw       string // when set, returned verbatim (malformed JSON tests)
}

type fakeFinding struct {
	name, id, fixed, fixState string
	aliases, upstream         []string
}

// fakeAssay answers `assay scan <sbom> --output json` by reading the SBOM
// run wrote, finding its component's purl, and returning the canned report
// for it. Unknown purls get an empty, evaluated report (clean).
func fakeAssay(t *testing.T, scans map[string]fakeScan) (execFunc, *[]string) {
	t.Helper()
	var sboms []string
	return func(bin string, args ...string) ([]byte, int, error) {
		// --config none is part of the contract: a .assay.yaml in the
		// working directory must never reach the judged scan.
		if bin != "fake-assay" || len(args) != 6 || args[0] != "scan" || args[2] != "--output" || args[3] != "json" || args[4] != "--config" || args[5] != "none" {
			t.Fatalf("unexpected exec: %s %v", bin, args)
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			t.Fatalf("the SBOM run named does not exist: %v", err)
		}
		var sbom struct {
			BOMFormat  string `json:"bomFormat"`
			Components []struct {
				Type, Name, Version, PURL string
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &sbom); err != nil || sbom.BOMFormat != "CycloneDX" || len(sbom.Components) != 1 || sbom.Components[0].Type != "library" {
			t.Fatalf("run wrote an SBOM that is not a one-component CycloneDX document: %s (%v)", raw, err)
		}
		sboms = append(sboms, sbom.Components[0].PURL)
		sc := scans[sbom.Components[0].PURL]
		if sc.raw != "" {
			return []byte(sc.raw), sc.exit, nil
		}
		evaluated := sc.evaluated
		if evaluated == 0 && len(sc.findings) > 0 {
			evaluated = 1
		}
		if _, ok := scans[sbom.Components[0].PURL]; !ok {
			evaluated = 1
		}
		var fs []map[string]any
		for _, f := range sc.findings {
			fs = append(fs, map[string]any{
				"package":  map[string]any{"name": f.name, "version": sbom.Components[0].Version},
				"advisory": map[string]any{"id": f.id, "aliases": f.aliases, "upstream": f.upstream},
				"evidence": map[string]any{"fixed": f.fixed},
				"fixState": f.fixState,
			})
		}
		doc := map[string]any{
			"schemaVersion": 18,
			"summary":       map[string]any{"components": 1, "evaluated": evaluated, "findings": len(fs)},
			"findings":      fs,
			"coverage":      []map[string]any{{"ecosystem": "Alpine:v3.19", "dataAsOf": fakeDataAsOf, "state": "live"}},
			"provenance":    map[string]any{"tool": map[string]any{"version": "v0.0-test"}, "database": map[string]any{"artifact": map[string]any{"digest": "sha256:feed"}}},
		}
		b, _ := json.Marshal(doc)
		exit := sc.exit
		if exit == 0 && len(fs) > 0 {
			exit = 1
		}
		return b, exit, nil
	}, &sboms
}

// fakeDataAsOf is the key date every fake scan reports.
const fakeDataAsOf = "2026-11-09"

// A label whose validFrom is after the database's data date is not judged:
// listed under its own heading, out of the metrics and the exit code; one
// at or before it is judged as usual.
func TestRun_ValidFromAfterTheDataDate_IsNotJudged(t *testing.T) {
	labels := heldLabels()
	labels[3].ValidFrom = "2026-12-01" // the clean label: with no finding it would otherwise be TN
	labels[1].ValidFrom = fakeDataAsOf // same day: judged
	exec, _ := fakeAssay(t, heldScans())
	report := filepath.Join(t.TempDir(), "report.json")
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay", "-out", report}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errOut.String())
	}
	// Three judged (the TN is gone), TP 3 TN 0.
	if !strings.Contains(out.String(), "alpine  3       3   0   0   0   0         0       0      1         1.000 (0.439-1.000)  1.000 (0.439-1.000)") {
		t.Errorf("table:\n%s", out.String())
	}
	want := "labels not judged (the database's data predates their validFrom):\n  PREDATES    alpine-busybox-fixed/CVE-2024-58251 -- Alpine:v3.19 data is as of 2026-11-09, before the label's validFrom 2026-12-01"
	if !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	if strings.Contains(out.String(), "did not hold") {
		t.Errorf("a predating label was listed as a failure:\n%s", out.String())
	}
	var rep struct {
		Total familyMetrics `json:"total"`
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Total.Predates != 1 || rep.Total.Labels != 3 || rep.Total.TN != 0 {
		t.Errorf("total = %+v, want predates 1, labels 3, tn 0", rep.Total)
	}
}

// A frozen key is dated by its freeze, not the provider's day: a label
// whose validFrom is after the freeze is not judged even though the
// provider's date is after it.
func TestRun_ValidFrom_FrozenKeyIsDatedByItsFreeze(t *testing.T) {
	labels := heldLabels()
	labels[3].ValidFrom = "2026-10-28"
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: `{"schemaVersion":18,"summary":{"components":1,"evaluated":1},"findings":[],"coverage":[{"ecosystem":"Alpine:v3.19","dataAsOf":"2026-11-09","state":"frozen","frozenSince":"2026-08-19"}],"provenance":{"database":{"artifact":{"digest":"sha256:feed"}}}}`}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("exit = %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "PREDATES    alpine-busybox-fixed/CVE-2024-58251 -- Alpine:v3.19 data is as of 2026-08-19, before the label's validFrom 2026-10-28") {
		t.Errorf("stdout:\n%s", out.String())
	}
	if !strings.Contains(errOut.String(), "note: 1 label(s) not judged") {
		t.Errorf("stderr lacks the note:\n%s", errOut.String())
	}
}

// A coverage record with no date (a key the database does not hold) dates
// nothing: the label is judged as before.
func TestRun_ValidFrom_UndatedCoverageIsJudged(t *testing.T) {
	labels := heldLabels()
	labels[3].ValidFrom = "2026-12-01"
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: `{"schemaVersion":18,"summary":{"components":1,"evaluated":1},"findings":[],"coverage":[{"ecosystem":"Alpine:v3.19","dataAsOf":"","state":"not-in-database"}],"provenance":{"database":{"artifact":{"digest":"sha256:feed"}}}}`}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("exit = %d\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "labels not judged") || !strings.Contains(out.String(), "alpine  4       3   1   0   0") {
		t.Errorf("table:\n%s", out.String())
	}
}

// Every label predating the database is a stale database, not a clean run.
func TestRun_ValidFrom_NothingJudgedIsExitError(t *testing.T) {
	labels := heldLabels()
	for i := range labels {
		labels[i].ValidFrom = "2026-12-01"
	}
	exec, _ := fakeAssay(t, heldScans())
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitError {
		t.Fatalf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(errOut.String(), "error: no label could be judged") {
		t.Errorf("stderr:\n%s", errOut.String())
	}
}

// A one-component SBOM maps to one key; a document with two is not dated
// by whichever came first.
func TestRun_TwoCoverageKeys_ExitError(t *testing.T) {
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: `{"schemaVersion":18,"summary":{"components":1,"evaluated":1},"findings":[],"coverage":[{"ecosystem":"A","dataAsOf":"2026-11-09"},{"ecosystem":"B","dataAsOf":"2026-01-01"}],"provenance":{"database":{"artifact":{"digest":"sha256:feed"}}}}`}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitError {
		t.Fatalf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(errOut.String(), "2 coverage keys for a one-component SBOM") {
		t.Errorf("stderr:\n%s", errOut.String())
	}
}

// A scan document with no coverage (a database from before schema 17)
// judges every label as before, validFrom or not.
func TestRun_ValidFromWithoutCoverage_IsJudged(t *testing.T) {
	labels := heldLabels()
	labels[3].ValidFrom = "2026-12-01"
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: `{"schemaVersion":16,"summary":{"components":1,"evaluated":1},"findings":[],"provenance":{"database":{"artifact":{"digest":"sha256:feed"}}}}`}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("exit = %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "alpine  4       3   1   0   0") || strings.Contains(out.String(), "labels not judged") {
		t.Errorf("table:\n%s", out.String())
	}
}

func writeLabels(t *testing.T, labels []Label) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "labels.json")
	b, _ := json.MarshalIndent(labelsFile{SchemaVersion: labelsSchemaVersion, Labels: labels}, "", "  ")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func label(id, family, purl, name, version, cve, state, fixed string) Label {
	return Label{ID: id + "/" + cve, Case: id, Family: family, PURL: purl, Name: name, Version: version, CVE: cve,
		Expect: Expect{State: state, Fixed: fixed}, Class: "matcher",
		Source: Source{Statement: "test statement", URL: "https://example.test/" + cve, FetchedAt: "2026-11-09T00:00:00Z"}}
}

const busyboxPURL = "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64&distro=alpine-3.19.9"
const busyboxFixedPURL = "pkg:apk/alpine/busybox@1.36.1-r21?arch=x86_64&distro=alpine-3.19.9"

// heldLabels is deliberately out of order (the no-fix label first) so a
// run that stopped sorting would show in the report's row order.
func heldLabels() []Label {
	return []Label{
		// Affected with no fixed version demanded: held by presence alone,
		// whatever fix the finding names.
		label("alpine-busybox-below", "alpine", busyboxPURL, "busybox", "1.36.1-r20", "CVE-2025-60876", "affected", ""),
		label("alpine-busybox-below", "alpine", busyboxPURL, "busybox", "1.36.1-r20", "CVE-2024-58251", "affected", "1.36.1-r21"),
		label("alpine-busybox-below", "alpine", busyboxPURL, "busybox", "1.36.1-r20", "CVE-2025-46394", "affected", "1.36.1-r21"),
		label("alpine-busybox-fixed", "alpine", busyboxFixedPURL, "busybox", "1.36.1-r21", "CVE-2024-58251", "clean", ""),
	}
}

// The third finding names its CVE through `upstream` alone (D3), with a
// record id that shares no substring with it.
func heldScans() map[string]fakeScan {
	return map[string]fakeScan{
		busyboxPURL: {findings: []fakeFinding{
			{name: "busybox", id: "ALPINE-CVE-2024-58251", aliases: []string{"CVE-2024-58251"}, fixed: "1.36.1-r21", fixState: "fixed"},
			{name: "busybox", id: "ALPINE-CVE-2025-46394", aliases: []string{"CVE-2025-46394"}, fixed: "1.36.1-r21", fixState: "fixed"},
			{name: "busybox", id: "ALPINE-2025-0003", upstream: []string{"CVE-2025-60876"}, fixed: "1.36.1-r21", fixState: "fixed"},
		}},
		busyboxFixedPURL: {evaluated: 1},
	}
}

func TestRun_EveryLabelHeld_ExitOKAndOneScanPerCase(t *testing.T) {
	exec, sboms := fakeAssay(t, heldScans())
	var out, errOut bytes.Buffer
	code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	// Two cases, two scans -- the three labels of one case share one SBOM.
	if len(*sboms) != 2 || (*sboms)[0] != busyboxPURL || (*sboms)[1] != busyboxFixedPURL {
		t.Errorf("scanned purls = %v, want one scan per case in case order", *sboms)
	}
	want := "alpine  4       3   1   0   0   0         0       0      0         1.000 (0.439-1.000)  1.000 (0.439-1.000)"
	if !strings.Contains(out.String(), want) {
		t.Errorf("table lacks the alpine row %q:\n%s", want, out.String())
	}
	if strings.Contains(out.String(), "did not hold") {
		t.Errorf("a clean run lists failures:\n%s", out.String())
	}
}

func TestRun_FalsePositive_Exit1AndNamed(t *testing.T) {
	scans := heldScans()
	// The fixed build is reported anyway: a false positive against a clean label.
	scans[busyboxFixedPURL] = fakeScan{findings: []fakeFinding{{name: "busybox", id: "CVE-2024-58251", fixed: "", fixState: "unknown"}}}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec)
	if code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	for _, want := range []string{
		"FP          alpine-busybox-fixed/CVE-2024-58251 -- reported (fixed=\"\", fixState=unknown), label says clean",
		"0.750 (", // precision 3/4
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
}

func TestRun_FalseNegativeAndMismatch_Exit1(t *testing.T) {
	scans := heldScans()
	scans[busyboxPURL] = fakeScan{findings: []fakeFinding{
		// CVE-2024-58251 reported only against ANOTHER package (a decoy the
		// name filter must ignore, so the label stays FN); CVE-2025-46394
		// with the wrong fix; CVE-2025-60876 (no fix demanded) still held.
		{name: "busybox-extras", id: "ALPINE-CVE-2024-58251", aliases: []string{"CVE-2024-58251"}, fixed: "1.36.1-r21", fixState: "fixed"},
		{name: "busybox", id: "ALPINE-CVE-2025-46394", aliases: []string{"CVE-2025-46394"}, fixed: "1.36.1-r22", fixState: "fixed"},
		{name: "busybox", id: "ALPINE-2025-0003", upstream: []string{"CVE-2025-60876"}, fixed: "", fixState: "unknown"},
	}}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec)
	if code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	for _, want := range []string{
		"FN          alpine-busybox-below/CVE-2024-58251 -- not reported, label says affected",
		"MISMATCH    alpine-busybox-below/CVE-2025-46394 -- fixed=\"1.36.1-r22\", label says \"1.36.1-r21\"",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	// TP 1 (the no-fix label), FN 1, MISMATCH 1: recall 1/2, the mismatch in neither cell.
	// The mismatch is in both denominators: precision 1/2, recall 1/3.
	if !strings.Contains(out.String(), "alpine  4       1   1   0   1   1         0       0      0         0.500 (0.095-0.905)  0.333 (0.061-0.792)") {
		t.Errorf("table row does not carry TP 1, FN 1, MISMATCH 1:\n%s", out.String())
	}
}

// A data-class label is judged and printed and never moves the exit code or
// the metrics: a known data gap is disclosed, not failed on.
func TestRun_DataClassLabelIsReportedNotJudged(t *testing.T) {
	labels := heldLabels()
	gap := label("debian-libarchive13-after-freeze", "debian", "pkg:deb/debian/libarchive13@3.4.3-2+deb11u5?arch=amd64&distro=debian-11&upstream=libarchive",
		"libarchive13", "3.4.3-2+deb11u5", "CVE-2026-14164", "clean", "")
	gap.Class, gap.Note = "data", "Debian:11 frozen before DLA-4762-1"
	// A second data-class row that HOLDS: the gap it records may have
	// closed, and the table must say so rather than stay silent.
	closed := label("debian-libarchive13-after-freeze-below", "debian", "pkg:deb/debian/libarchive13@3.4.3-2+deb11u4?arch=amd64&distro=debian-11&upstream=libarchive",
		"libarchive13", "3.4.3-2+deb11u4", "CVE-2026-14164", "affected", "")
	closed.Class, closed.Note = "data", "Debian:11 frozen before DLA-4762-1"
	labels = append(labels, gap, closed)
	scans := heldScans()
	scans[gap.PURL] = fakeScan{findings: []fakeFinding{{name: "libarchive13", id: "DEBIAN-CVE-2026-14164", aliases: []string{"CVE-2026-14164"}, fixState: "unknown"}}}
	scans[closed.PURL] = fakeScan{findings: []fakeFinding{{name: "libarchive13", id: "DEBIAN-CVE-2026-14164", aliases: []string{"CVE-2026-14164"}, fixState: "unknown"}}}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay"}, &out, &errOut, exec)
	if code != exitOK {
		t.Fatalf("exit = %d, want 0: a data-class failure is not a matcher failure\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "data-class labels (known data gaps, not in the metrics):\n  FP          debian-libarchive13-after-freeze/CVE-2026-14164 -- reported (fixed=\"\", fixState=unknown), label says clean\n  TP          debian-libarchive13-after-freeze-below/CVE-2026-14164 -- holds -- the data gap this label records may have closed; reclassify it\n") {
		t.Errorf("the data-class rows are not listed under their own heading, the holding one flagged:\n%s", out.String())
	}
	if strings.Contains(out.String(), "debian  ") {
		t.Errorf("the data-class label leaked into the family metrics:\n%s", out.String())
	}
}

func TestRun_ScanExit2_ExitErrorAndRowERROR(t *testing.T) {
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{exit: 2, raw: ""}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec)
	if code != exitError {
		t.Fatalf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(errOut.String(), "error: case=alpine-busybox-fixed assay scan exited 2 (untrustworthy result)") {
		t.Errorf("stderr does not name the case and the exit:\n%s", errOut.String())
	}
	if !strings.Contains(out.String(), "ERROR       alpine-busybox-fixed/CVE-2024-58251 -- assay scan exited 2 (untrustworthy result)") {
		t.Errorf("the label of the failed scan is not listed as ERROR:\n%s", out.String())
	}
}

func TestRun_MalformedJSON_ExitError(t *testing.T) {
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: "{not json", exit: 0}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitError {
		t.Fatalf("exit = %d, want 2\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "malformed assay JSON") {
		t.Errorf("stderr: %s", errOut.String())
	}
}

// A package the scan could not evaluate is neither clean nor affected.
func TestRun_UnevaluatedPackageIsNeitherTNNorFN(t *testing.T) {
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: `{"schemaVersion":18,"summary":{"components":1,"evaluated":0},"findings":[],"provenance":{"database":{"artifact":{"digest":"sha256:feed"}}}}`}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "UNEVALUATED alpine-busybox-fixed/CVE-2024-58251 -- the scan evaluated 0 of 1 component(s)") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

// -keep writes the SBOM and the scan output per case; -offline re-judges
// from them without running assay, and -out writes the report.
func TestRun_KeepThenOfflineAndReport(t *testing.T) {
	exec, _ := fakeAssay(t, heldScans())
	keep := filepath.Join(t.TempDir(), "keep")
	report := filepath.Join(t.TempDir(), "report.json")
	labelsPath := writeLabels(t, heldLabels())
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", labelsPath, "-assay", "fake-assay", "-keep", keep, "-out", report}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("exit = %d\n%s", code, errOut.String())
	}
	for _, f := range []string{"alpine-busybox-below.cdx.json", "alpine-busybox-below.scan.json", "alpine-busybox-below.exit", "alpine-busybox-fixed.cdx.json", "alpine-busybox-fixed.scan.json", "alpine-busybox-fixed.exit"} {
		if _, err := os.Stat(filepath.Join(keep, f)); err != nil {
			t.Errorf("-keep did not write %s: %v", f, err)
		}
	}
	var rep struct {
		SchemaVersion int             `json:"schemaVersion"`
		Database      string          `json:"databaseDigest"`
		Tool          string          `json:"toolVersion"`
		Families      []familyMetrics `json:"families"`
		Total         familyMetrics   `json:"total"`
		Results       []result        `json:"results"`
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("report does not parse: %v", err)
	}
	if rep.SchemaVersion != reportSchemaVersion || rep.Database != "sha256:feed" || rep.Tool != "v0.0-test" || len(rep.Families) != 1 || rep.Total.TP != 3 || rep.Total.TN != 1 || len(rep.Results) != 4 {
		t.Errorf("report = %+v", rep)
	}
	// Rows are in (case, CVE) order whatever order the file had.
	if rep.Results[0].Label.CVE != "CVE-2024-58251" || rep.Results[2].Label.CVE != "CVE-2025-60876" {
		t.Errorf("results are not sorted by case then CVE: %s, %s, %s", rep.Results[0].Label.CVE, rep.Results[1].Label.CVE, rep.Results[2].Label.CVE)
	}
	if rep.Total.RecallLow95 < 0.438 || rep.Total.RecallLow95 > 0.44 {
		t.Errorf("recall lower bound = %.3f, want Wilson's 0.439 for 3 of 3", rep.Total.RecallLow95)
	}

	// Offline: the same table, byte for byte, from the kept outputs, no exec.
	live := out.String()
	out.Reset()
	errOut.Reset()
	noExec := func(bin string, args ...string) ([]byte, int, error) {
		t.Fatalf("offline run executed %s %v", bin, args)
		return nil, 0, nil
	}
	if code := run([]string{"-labels", labelsPath, "-offline", keep}, &out, &errOut, noExec); code != exitOK {
		t.Fatalf("offline exit = %d\n%s\n%s", code, out.String(), errOut.String())
	}
	if out.String() != live {
		t.Errorf("offline table differs from the live one:\n%s\n--- live:\n%s", out.String(), live)
	}
}

// A kept scan that exited 2 is still a fatal offline: assay renders its JSON
// and then exits 2, so the document alone would read as trustworthy.
func TestRun_OfflineKeepsAFatalFatal(t *testing.T) {
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{exit: 2, raw: `{"schemaVersion":18,"summary":{"components":1,"evaluated":1},"findings":[]}`}
	exec, _ := fakeAssay(t, scans)
	keep := filepath.Join(t.TempDir(), "keep")
	labelsPath := writeLabels(t, heldLabels())
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", labelsPath, "-assay", "fake-assay", "-keep", keep}, &out, &errOut, exec); code != exitError {
		t.Fatalf("live exit = %d, want 2", code)
	}
	out.Reset()
	errOut.Reset()
	noExec := func(bin string, args ...string) ([]byte, int, error) {
		t.Fatalf("offline run executed %s %v", bin, args)
		return nil, 0, nil
	}
	if code := run([]string{"-labels", labelsPath, "-offline", keep}, &out, &errOut, noExec); code != exitError {
		t.Fatalf("offline exit = %d, want 2: the kept exit code was 2\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "ERROR       alpine-busybox-fixed/CVE-2024-58251 -- kept assay scan exited 2 (untrustworthy result)") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

// Two findings for one CVE that disagree on the fix are not resolved by
// arrival order (D25): the row is a MISMATCH naming both.
func TestRun_TwoFindingsForOneCVEDisagree_Mismatch(t *testing.T) {
	scans := heldScans()
	// Three findings, two distinct fixes: the third repeats the second's, and
	// the joined field must not repeat it.
	scans[busyboxPURL] = fakeScan{findings: append(scans[busyboxPURL].findings,
		fakeFinding{name: "busybox", id: "OTHER-2024-58251", aliases: []string{"CVE-2024-58251"}, fixed: "1.36.1-r23", fixState: "fixed"},
		fakeFinding{name: "busybox", id: "THIRD-2024-58251", aliases: []string{"CVE-2024-58251"}, fixed: "1.36.1-r23", fixState: "fixed"})}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	want := `MISMATCH    alpine-busybox-below/CVE-2024-58251 -- fixed="1.36.1-r21 | 1.36.1-r23", label says "1.36.1-r21" (the findings for this CVE name 2 different fixes)`
	if !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
}

// Every case must be judged against one database.
func TestRun_DatabaseDigestChangesMidRun_ExitError(t *testing.T) {
	scans := heldScans()
	scans[busyboxFixedPURL] = fakeScan{raw: `{"schemaVersion":18,"summary":{"components":1,"evaluated":1},"findings":[],"provenance":{"database":{"artifact":{"digest":"sha256:other"}}}}`}
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitError {
		t.Fatalf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(errOut.String(), "database digest sha256:other differs from the run's first, sha256:feed") {
		t.Errorf("stderr:\n%s", errOut.String())
	}
}

// The purl is read as a purl: percent-decoded, name and version exactly.
func TestLoadLabels_PURLNameAndVersion(t *testing.T) {
	enc := label("debian-libxml2-below", "debian", "pkg:deb/debian/libxml2@2.9.10%2Bdfsg-6.7%2Bdeb11u4?arch=amd64&distro=debian-11", "libxml2", "2.9.10+dfsg-6.7+deb11u4", "CVE-2024-25062", "affected", "2.9.10+dfsg-6.7+deb11u5")
	if _, err := loadLabels(writeLabels(t, []Label{enc})); err != nil {
		t.Errorf("a percent-encoded version that decodes to the label's did not load: %v", err)
	}
	epoch := label("debian-bind9-below", "debian", "pkg:deb/debian/bind9@1%3A9.16.50-1%2Bdeb11u2?arch=amd64&distro=debian-11", "bind9", "1:9.16.50-1+deb11u2", "CVE-2024-1737", "affected", "1:9.16.50-1+deb11u3")
	if _, err := loadLabels(writeLabels(t, []Label{epoch})); err != nil {
		t.Errorf("an epoch version did not load: %v", err)
	}
	// A Go module's name is its whole path; an npm scope is part of the name.
	for _, ok := range []Label{
		label("go-x-net-below", "go", "pkg:golang/golang.org/x/net@v0.33.0", "golang.org/x/net", "v0.33.0", "CVE-2025-22870", "affected", "v0.36.0"),
		label("npm-scoped-below", "npm", "pkg:npm/%40babel/traverse@7.23.1", "@babel/traverse", "7.23.1", "CVE-2023-45133", "affected", "7.23.2"),
		// Maven joins group and artifact with ":" (the name OSV publishes),
		// every other namespaced type with "/", as the CycloneDX reader does.
		label("maven-log4j-below", "maven", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", "org.apache.logging.log4j:log4j-core", "2.14.0", "CVE-2021-44228", "affected", "2.15.0"),
		label("composer-monolog-below", "composer", "pkg:composer/monolog/monolog@1.0.0", "monolog/monolog", "1.0.0", "CVE-2024-0001", "affected", "1.0.1"),
	} {
		if _, err := loadLabels(writeLabels(t, []Label{ok})); err != nil {
			t.Errorf("%s did not load: %v", ok.ID, err)
		}
	}
	for _, tc := range []struct{ name, purl, version, pkg, want string }{
		{"substring version", "pkg:apk/alpine/busybox@1.36.1-r20?arch=x86_64", "1.36.1-r2", "busybox", `carrying the label's version "1.36.1-r2" (it carries "1.36.1-r20")`},
		{"go module named by its last segment", "pkg:golang/golang.org/x/net@v0.33.0", "v0.33.0", "net", `purl names "golang.org/x/net", label names "net"`},
		{"maven named with a slash", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", "2.14.0", "org.apache.logging.log4j/log4j-core", `purl names "org.apache.logging.log4j:log4j-core"`},
		{"no name after the type", "pkg:npm@1.0.0", "1.0.0", "npm", `no name after the type "npm"`},
		{"name differs", "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u5?arch=amd64", "1.1.1n-0+deb11u5", "openssl", `purl names "libssl1.1", label names "openssl"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := label("c", "alpine", tc.purl, tc.pkg, tc.version, "CVE-2024-0001", "clean", "")
			_, err := loadLabels(writeLabels(t, []Label{l}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// Each refusal is checked with labels that would otherwise load and a fake
// assay that would otherwise hold every label, so the refusal itself is what
// returns 2, and its message says which one.
func TestRun_BadArguments_ExitError(t *testing.T) {
	good := writeLabels(t, heldLabels())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-labels", filepath.Join(t.TempDir(), "missing.json"), "-assay", "fake-assay"}, "missing.json"},
		{[]string{"-labels", good, "-assay", "fake-assay", "-keep", t.TempDir(), "-offline", t.TempDir()}, "-keep and -offline are exclusive"},
		{[]string{"-labels", good, "-assay", "fake-assay", "extra-positional"}, `unexpected argument "extra-positional"`},
	} {
		exec, _ := fakeAssay(t, heldScans())
		var out, errOut bytes.Buffer
		if code := run(tc.args, &out, &errOut, exec); code != exitError {
			t.Errorf("run(%v) = %d, want 2", tc.args, code)
		}
		if !strings.Contains(errOut.String(), tc.want) {
			t.Errorf("run(%v) stderr lacks %q:\n%s", tc.args, tc.want, errOut.String())
		}
	}
}

// A miss alone -- one affected label with no finding, everything else held
// -- is a failed run on its own.
func TestRun_FalseNegativeAlone_Exit1(t *testing.T) {
	scans := heldScans()
	scans[busyboxPURL] = fakeScan{findings: scans[busyboxPURL].findings[1:]} // CVE-2024-58251 gone
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "alpine  4       2   1   0   1   0         0       0") {
		t.Errorf("table:\n%s", out.String())
	}
}

// A MISMATCH alone -- every finding present, one with the wrong fix -- is a
// failed run: the fix version is the point of the label.
func TestRun_MismatchAlone_Exit1(t *testing.T) {
	scans := heldScans()
	scans[busyboxPURL].findings[0].fixed = "1.36.1-r22"
	exec, _ := fakeAssay(t, scans)
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, heldLabels()), "-assay", "fake-assay"}, &out, &errOut, exec); code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "alpine  4       2   1   0   0   1         0       0") {
		t.Errorf("table:\n%s", out.String())
	}
}

// Nothing reported and nothing expected: both rates are n/a, and the report
// still writes (no NaN reaches the JSON encoder).
func TestRun_NoPositives_RatesAreNA(t *testing.T) {
	labels := []Label{label("alpine-busybox-fixed", "alpine", busyboxFixedPURL, "busybox", "1.36.1-r21", "CVE-2024-58251", "clean", "")}
	exec, _ := fakeAssay(t, map[string]fakeScan{busyboxFixedPURL: {evaluated: 1}})
	report := filepath.Join(t.TempDir(), "report.json")
	var out, errOut bytes.Buffer
	if code := run([]string{"-labels", writeLabels(t, labels), "-assay", "fake-assay", "-out", report}, &out, &errOut, exec); code != exitOK {
		t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "alpine  1       0   1   0   0   0         0       0      0         n/a") || !strings.Contains(out.String(), "n/a\nall ") {
		t.Errorf("table:\n%s", out.String())
	}
	if _, err := os.Stat(report); err != nil {
		t.Errorf("report not written: %v", err)
	}
}

func TestLoadLabels_RefusesAnotherSchemaVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "labels.json")
	b, _ := json.Marshal(labelsFile{SchemaVersion: labelsSchemaVersion + 1, Labels: heldLabels()})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLabels(p); err == nil || !strings.Contains(err.Error(), "this tool reads 1") {
		t.Errorf("err = %v", err)
	}
}

// The committed labels file loads, and holds the shape the metrics need:
// every family has positives and negatives, every id is unique, and the
// data-class rows carry their note.
func TestCommittedLabels_LoadAndShape(t *testing.T) {
	labels, err := loadLabels(filepath.Join("..", "..", "testdata", "groundtruth", "labels.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) < 140 {
		t.Errorf("labels = %d, want the 84 seeded from the 2026-11-04 harness plus the 56 of the 2026-11-09 expansion, or more", len(labels))
	}
	type counts struct{ pos, neg, data int }
	by := map[string]*counts{}
	for _, l := range labels {
		c := by[l.Family]
		if c == nil {
			c = &counts{}
			by[l.Family] = c
		}
		switch {
		case l.Class == "data":
			c.data++
		case l.Expect.State == "affected":
			c.pos++
		default:
			c.neg++
		}
	}
	// Every family is a boundary pair: at least one affected and one clean
	// matcher-class label, or its precision or recall has no denominator.
	fams := []string{"alpine", "debian", "leap", "rhel", "alma", "amzn", "wolfi", "npm", "go"}
	for _, fam := range fams {
		c := by[fam]
		if c == nil || c.pos == 0 || c.neg == 0 {
			t.Errorf("family %s: %+v, want at least one positive and one negative matcher-class label", fam, c)
		}
	}
	// A family this list does not name is one the loop did not check: add
	// it here, with its own boundary pair, rather than let it in unheld.
	if len(by) != len(fams) {
		t.Errorf("families = %d (%v), want the %d named ones", len(by), by, len(fams))
	}
	if by["debian"] == nil || by["debian"].data == 0 {
		t.Error("the Debian 11 after-freeze rows should be data-class")
	}
}

// loadLabels refuses the rows that would otherwise be judged as truths.
func TestLoadLabels_Refusals(t *testing.T) {
	good := heldLabels()
	for _, tc := range []struct {
		name string
		mut  func(ls []Label) []Label
		want string
	}{
		{"duplicate id", func(ls []Label) []Label { ls[1].ID = ls[0].ID; return ls }, "duplicate id"},
		{"bad cve", func(ls []Label) []Label { ls[0].CVE = "GHSA-xxxx"; return ls }, "is not CVE-YYYY-NNNN"},
		{"bad state", func(ls []Label) []Label { ls[0].Expect.State = "maybe"; return ls }, "want affected or clean"},
		{"clean with fixed", func(ls []Label) []Label { ls[3].Expect.Fixed = "1.0"; return ls }, "a clean label names a fixed version"},
		{"bad class", func(ls []Label) []Label { ls[0].Class = "guess"; return ls }, "want matcher or data"},
		{"data without note", func(ls []Label) []Label { ls[0].Class = "data"; return ls }, "needs a note"},
		{"purl without version", func(ls []Label) []Label { ls[0].PURL = "pkg:apk/alpine/busybox"; return ls }, "carrying the label's version"},
		{"no source", func(ls []Label) []Label { ls[0].Source.URL = ""; return ls }, "source.statement, source.url and source.fetchedAt"},
		{"two purls in one case", func(ls []Label) []Label { ls[1].PURL = busyboxFixedPURL; ls[1].Version = "1.36.1-r21"; return ls }, "names two purls"},
		{"validFrom not a date", func(ls []Label) []Label { ls[0].ValidFrom = "2026-11"; return ls }, "is not YYYY-MM-DD"},
		{"validFrom an impossible day", func(ls []Label) []Label { ls[0].ValidFrom = "2026-11-31"; return ls }, "is not YYYY-MM-DD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ls := tc.mut(append([]Label(nil), good...))
			_, err := loadLabels(writeLabels(t, ls))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

func TestWilson(t *testing.T) {
	for _, tc := range []struct {
		k, n   int
		lo, hi float64
	}{
		{35, 35, 0.901, 1.0},
		{0, 0, 0, 0},
		{0, 10, 0, 0.278},
		{5, 10, 0.237, 0.763},
	} {
		lo, hi := wilson(tc.k, tc.n)
		if fmt.Sprintf("%.3f %.3f", lo, hi) != fmt.Sprintf("%.3f %.3f", tc.lo, tc.hi) {
			t.Errorf("wilson(%d, %d) = %.3f-%.3f, want %.3f-%.3f", tc.k, tc.n, lo, hi, tc.lo, tc.hi)
		}
	}
}
