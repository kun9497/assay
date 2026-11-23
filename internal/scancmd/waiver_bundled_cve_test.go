package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/store"
)

// D171 (QA 2026-11-20). An errata record -- an ALAS, ELSA, RLSA, ALSA or
// Bodhi update -- lists the CVEs it fixes in `related` and is one finding. A
// waiver naming ONE of those CVEs matched the finding's whole identifier set
// and suppressed it, siblings included: an ignore rule or VEX statement for
// CVE-2031-1111 took CVE-2031-2222 out of the verdict with it, and nothing
// said so. A bundled CVE is now waived by itself, and the finding stands
// until none is left.

const (
	erratumID = "ALAS2023-2031-0001"
	cveA      = "CVE-2031-1111"
	cveB      = "CVE-2031-2222"
	bundledPU = "pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=alpine-3.19.9"
)

// erratumDB holds one errata record in the shape the Amazon provider emits:
// no aliases, no upstream, the CVEs in related alone.
func erratumDB(t *testing.T, aliases ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: erratumID, Kind: advisory.KindVulnerability, Database: "TEST",
		Aliases: aliases, Related: []string{cveA, cveB},
		Affected: []advisory.Affected{{
			Ecosystem: "Alpine:v3.19", Name: "openssl",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: "3.1.4-r99"}}}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.19"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func bundledSBOM(t *testing.T) string {
	t.Helper()
	return writeSBOM(t, "cyclonedx", `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[
 {"type":"library","name":"openssl","version":"3.1.4-r5","purl":"`+bundledPU+`"}]}`)
}

// ignoreRules writes a .assay.yaml waiving each id for its own reason.
func ignoreRules(t *testing.T, ids ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("ignore:\n")
	for _, id := range ids {
		b.WriteString("  - vulnerability: " + id + "\n    reason: reviewed " + id + "\n")
	}
	p := filepath.Join(t.TempDir(), ".assay.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// vexStatus is one statement about cve on the openssl package.
func vexStatus(cve, status, when string) string {
	s := `{"vulnerability":{"name":"` + cve + `"},"timestamp":"` + when + `","products":[{"@id":"pkg:apk/alpine/openssl"}],"status":"` + status + `"`
	if status == "not_affected" {
		s += `,"justification":"inline_mitigations_already_exist"`
	}
	return s + "}"
}

type bundledRun struct {
	code   int
	doc    report.Document
	stderr string
}

func runBundled(t *testing.T, db string, opts Options) bundledRun {
	t.Helper()
	opts.Output, opts.FailOnUnknown = "json", true
	if opts.IgnoreFile == "" {
		opts.IgnoreFile = IgnoreNone
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, bundledSBOM(t), opts, &out, &errOut)
	var doc report.Document
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v (stderr: %s)", err, errOut.String())
	}
	return bundledRun{code, doc, errOut.String()}
}

// reported asserts the finding is still reported, exit 1, with exactly the
// named CVEs waived by source.
func (r bundledRun) reported(t *testing.T, source string, waived ...string) {
	t.Helper()
	if r.code != 1 || len(r.doc.Findings) != 1 || len(r.doc.Suppressed) != 0 {
		t.Fatalf("exit=%d findings=%d suppressed=%d, want the errata still reported (1/1/0)\nstderr: %s",
			r.code, len(r.doc.Findings), len(r.doc.Suppressed), r.stderr)
	}
	var got []string
	for _, w := range r.doc.Findings[0].Waived {
		if w.Source != source || w.Reason == "" {
			t.Errorf("waived %+v, want source %s and a reason", w, source)
		}
		got = append(got, w.CVE)
	}
	if strings.Join(got, ",") != strings.Join(waived, ",") {
		t.Errorf("waived = %v, want %v", got, waived)
	}
}

func (r bundledRun) suppressed(t *testing.T, source string, reasonParts ...string) {
	t.Helper()
	if r.code != 0 || len(r.doc.Findings) != 0 || len(r.doc.Suppressed) != 1 {
		t.Fatalf("exit=%d findings=%d suppressed=%d, want the errata suppressed (0/0/1)\nstderr: %s",
			r.code, len(r.doc.Findings), len(r.doc.Suppressed), r.stderr)
	}
	s := r.doc.Suppressed[0]
	if s.Source != source {
		t.Errorf("suppressed by %q, want %q", s.Source, source)
	}
	for _, part := range reasonParts {
		if !strings.Contains(s.Reason, part) {
			t.Errorf("reason %q lacks %q", s.Reason, part)
		}
	}
}

func TestRun_IgnoreRuleForOneBundledCVELeavesTheErrataReported(t *testing.T) {
	db := erratumDB(t)

	r := runBundled(t, db, Options{IgnoreFile: ignoreRules(t, cveA)})
	r.reported(t, "ignore-file", cveA)
	if !strings.Contains(r.stderr, "1 CVE(s) waived by ") || !strings.Contains(r.stderr, "still reported for the other CVEs they bundle") {
		t.Errorf("stderr does not say a CVE was waived on a finding still reported:\n%s", r.stderr)
	}

	// Lower case, as a person types it.
	runBundled(t, db, Options{IgnoreFile: ignoreRules(t, strings.ToLower(cveB))}).reported(t, "ignore-file", cveB)

	// Every bundled CVE waived: nothing the finding stands for is left.
	runBundled(t, db, Options{IgnoreFile: ignoreRules(t, cveA, cveB)}).
		suppressed(t, "ignore-file", cveA+": reviewed "+cveA, cveB+": reviewed "+cveB)

	// The errata named itself is the errata, as before.
	runBundled(t, db, Options{IgnoreFile: ignoreRules(t, erratumID)}).suppressed(t, "ignore-file", "reviewed "+erratumID)
}

func TestRun_VEXForOneBundledCVELeavesTheErrataReported(t *testing.T) {
	db := erratumDB(t)
	const t1, t2 = "2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"

	r := runBundled(t, db, Options{VEXFiles: []string{writeVEX(t, vexStatus(cveA, "not_affected", t1))}})
	r.reported(t, "vex", cveA)
	if !strings.Contains(r.stderr, "1 CVE(s) waived by VEX") {
		t.Errorf("stderr does not say a CVE was waived:\n%s", r.stderr)
	}

	runBundled(t, db, Options{VEXFiles: []string{writeVEX(t,
		vexStatus(cveA, "not_affected", t1), vexStatus(cveB, "not_affected", t1))}}).suppressed(t, "vex", cveA+": ", cveB+": ")

	runBundled(t, db, Options{VEXFiles: []string{writeVEX(t, vexStatus(erratumID, "not_affected", t1))}}).suppressed(t, "vex")

	// "Latest statement wins" is a contest between statements about one
	// vulnerability. not_affected for one CVE and affected for its sibling
	// used to beat each other by document order and timestamp; each is now
	// judged on its own, so every arrangement gives the same answer.
	for name, statements := range map[string][]string{
		"waiver first, older":  {vexStatus(cveA, "not_affected", t1), vexStatus(cveB, "affected", t2)},
		"waiver first, newer":  {vexStatus(cveA, "not_affected", t2), vexStatus(cveB, "affected", t1)},
		"waiver second, older": {vexStatus(cveB, "affected", t2), vexStatus(cveA, "not_affected", t1)},
		"waiver second, newer": {vexStatus(cveB, "affected", t1), vexStatus(cveA, "not_affected", t2)},
	} {
		t.Run(name, func(t *testing.T) {
			runBundled(t, db, Options{VEXFiles: []string{writeVEX(t, statements...)}}).reported(t, "vex", cveA)
		})
	}

	// A later `affected` for the SAME CVE still retracts its waiver.
	runBundled(t, db, Options{VEXFiles: []string{writeVEX(t,
		vexStatus(cveA, "not_affected", t1), vexStatus(cveA, "affected", t2))}}).reported(t, "vex")
}

// The two mechanisms run one after the other and their waivers add up.
func TestRun_IgnoreAndVEXTogetherWaiveEveryBundledCVE(t *testing.T) {
	db := erratumDB(t)
	r := runBundled(t, db, Options{
		IgnoreFile: ignoreRules(t, cveA),
		VEXFiles:   []string{writeVEX(t, vexStatus(cveB, "not_affected", "2026-10-01T00:00:00Z"))},
	})
	r.suppressed(t, "vex", cveA+": reviewed "+cveA, cveB+": ")
}

// A record that carries a CVE as its own alias beside the bundle: the alias
// names the finding, so a waiver for it suppresses the finding, and waiving
// only the bundled ones does not.
func TestRun_ACVEThatNamesTheFindingIsNotABundledOne(t *testing.T) {
	const own = "CVE-2031-0001"
	db := erratumDB(t, own)
	runBundled(t, db, Options{IgnoreFile: ignoreRules(t, cveA, cveB)}).reported(t, "ignore-file", cveA, cveB)
	runBundled(t, db, Options{IgnoreFile: ignoreRules(t, own)}).suppressed(t, "ignore-file", "reviewed "+own)
}

// Every renderer says which CVEs were waived on a finding it still shows.
func TestRun_EveryRendererShowsAWaivedBundledCVE(t *testing.T) {
	db := erratumDB(t)
	for output, want := range map[string]string{
		"table": "waived: " + cveA + " on " + erratumID + " (openssl), by ignore-file: reviewed " + cveA,
		"sarif": "(waived: " + cveA + "; reported for the other CVEs it bundles)",
	} {
		var out, errOut bytes.Buffer
		Run(context.Background(), db, bundledSBOM(t), Options{Output: output, IgnoreFile: ignoreRules(t, cveA)}, &out, &errOut)
		if !strings.Contains(out.String(), want) {
			t.Errorf("--output %s lacks %q:\n%s", output, want, out.String())
		}
	}
	var out, errOut bytes.Buffer
	Run(context.Background(), db, bundledSBOM(t), Options{Explain: erratumID, IgnoreFile: ignoreRules(t, cveA)}, &out, &errOut)
	if want := "waived:   " + cveA + " by ignore-file: reviewed " + cveA; !strings.Contains(out.String(), want) {
		t.Errorf("--explain lacks %q:\n%s", want, out.String())
	}
}
