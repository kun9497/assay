package scancmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// D111's caller tests. Every one drives Run end to end against a real bolt
// database and a real docker-archive image or SBOM, because the defect D111
// closes lives between the pieces: a frozen key with no finding under it had
// no field to carry the fact, so a renderer-level test handed a hand-built
// coverage list would pass while Run never built one.
//
// The two dates are chosen so no other field in any document here carries
// either, and they differ from each other, so an assertion on one cannot pass
// from the other (the substring rule in CLAUDE.md).
var (
	d111FrozenSince = time.Date(2026, 5, 31, 0, 0, 0, 0, time.UTC)
	d111DataAsOf    = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
)

const (
	d111FrozenDate = "2026-05-31"
	d111AsOfDate   = "2026-09-27"
	// d111Footnote is the reworded D110 sentence (P1-5): true for an
	// entry-level freeze as well as a whole-key one.
	d111Footnote = "@ advisory data for Alpine:v3.19 includes entries carried forward since " +
		d111FrozenDate + ": the upstream stopped publishing some or all of it"
)

// d111Coverage mirrors report.CoverageRecord's JSON shape. Decoded into a
// local type rather than the report one, so a renamed or retagged field shows
// up here as a zero value rather than compiling straight through.
type d111Coverage struct {
	Ecosystem   string `json:"ecosystem"`
	Packages    int    `json:"packages"`
	Evaluated   int    `json:"evaluated"`
	State       string `json:"state"`
	Provider    string `json:"provider"`
	DataAsOf    string `json:"dataAsOf"`
	FrozenSince string `json:"frozenSince"`
}

type d111Doc struct {
	SchemaVersion int            `json:"schemaVersion"`
	Coverage      []d111Coverage `json:"coverage"`
	Distro        *struct {
		ID         string `json:"id"`
		VersionID  string `json:"versionId"`
		Ecosystem  string `json:"ecosystem"`
		Recognized bool   `json:"recognized"`
	} `json:"distro"`
	InventoryScope *struct {
		OSPackages          string `json:"osPackages"`
		Bitnami             string `json:"bitnami"`
		ApplicationPackages string `json:"applicationPackages"`
	} `json:"inventoryScope"`
	Summary struct {
		Findings   int  `json:"findings"`
		Evaluated  int  `json:"evaluated"`
		FrozenKeys *int `json:"frozenKeys"`
	} `json:"summary"`
}

// decodeD111 parses stdout as exactly one JSON document — json.Unmarshal
// refuses trailing non-whitespace, so a stray line after the document fails
// here (stream discipline) — and also returns it as a raw map, for the
// assertions that are about a key being ABSENT rather than null or empty.
func decodeD111(t *testing.T, out string) (d111Doc, map[string]json.RawMessage) {
	t.Helper()
	var doc d111Doc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not exactly one JSON document: %v\n%s", err, out)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("stdout is not a JSON object: %v", err)
	}
	return doc, raw
}

// d111DB builds a database with the given provider metadata and one Alpine
// 3.19 advisory for busybox (apkOneRecord's origin) FIXED at 1.36.1-r10, so
// the installed 1.36.1-r15 is evaluated and clean: a key with data, a package
// under it, and nothing found — the exact shape the 2026-09-30 review
// reproduced.
func d111DB(t *testing.T, providers map[string]store.Provenance) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-2024-0001", Kind: advisory.KindVulnerability, Database: "ALPINE",
		Upstream: []string{"CVE-2024-99001"},
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
		Affected: []advisory.Affected{{
			Ecosystem: "Alpine:v3.19", Name: "busybox",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r10"}}}},
		}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := w.SetMeta(store.Meta{Providers: providers}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

func d111FrozenProviders() map[string]store.Provenance {
	return map[string]store.Provenance{"osv": {
		Ecosystems: []string{"Alpine:v3.19"},
		DataAsOf:   d111DataAsOf,
		Frozen:     map[string]time.Time{"Alpine:v3.19": d111FrozenSince},
	}}
}

func d111LiveProviders() map[string]store.Provenance {
	return map[string]store.Provenance{"osv": {
		Ecosystems: []string{"Alpine:v3.19"},
		DataAsOf:   d111DataAsOf,
	}}
}

// scanImage runs one docker-archive image built from files through Run.
func scanImage(t *testing.T, dbPath string, files map[string]string, opts Options) (string, string, int) {
	t.Helper()
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, files)
	var out, errOut bytes.Buffer
	code := Run(context.Background(), dbPath, "docker-archive:"+tarPath, opts, &out, &errOut)
	return out.String(), errOut.String(), code
}

func alpine319Files() map[string]string {
	return map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkOneRecord}
}

// d111SARIF is the slice of the SARIF document the D111 assertions read.
type d111SARIF struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
		Invocations []struct {
			Properties struct {
				Coverage []d111Coverage `json:"coverage"`
			} `json:"properties"`
			ToolExecutionNotifications []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, out string) d111SARIF {
	t.Helper()
	var doc d111SARIF
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not one SARIF document: %v\n%s", err, out)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("want one run with one invocation:\n%s", out)
	}
	return doc
}

const frozenDataRule = "assay/frozen-data"

// (1) The review's reproduction: the only key is frozen and the one package
// under it is at a fixed version. Before D111 all three renderers called this
// a clean scan on current data.
func TestRun_D111_FrozenKeyWithNoFindingIsDisclosedEverywhere(t *testing.T) {
	db := d111DB(t, d111FrozenProviders())

	t.Run("json", func(t *testing.T) {
		out, errOut, code := scanImage(t, db, alpine319Files(), Options{Output: "json"})
		if code != 0 {
			t.Fatalf("Run = %d, want 0 (D111 discloses, it does not gate)\nstderr: %s", code, errOut)
		}
		doc, _ := decodeD111(t, out)
		if doc.SchemaVersion != 12 {
			t.Errorf("schemaVersion = %d, want 12", doc.SchemaVersion)
		}
		want := []d111Coverage{{
			Ecosystem: "Alpine:v3.19", Packages: 1, Evaluated: 1, State: "frozen",
			Provider: "osv", DataAsOf: d111AsOfDate, FrozenSince: d111FrozenDate,
		}}
		if !reflect.DeepEqual(doc.Coverage, want) {
			t.Errorf("coverage = %+v\nwant       %+v", doc.Coverage, want)
		}
		if doc.Summary.FrozenKeys == nil || *doc.Summary.FrozenKeys != 1 {
			t.Errorf("summary.frozenKeys = %v, want 1", doc.Summary.FrozenKeys)
		}
		if doc.Summary.Findings != 0 {
			t.Errorf("summary.findings = %d, want 0 — the fixture's package is at a fixed version", doc.Summary.Findings)
		}
	})

	t.Run("table", func(t *testing.T) {
		out, errOut, code := scanImage(t, db, alpine319Files(), Options{})
		if code != 0 {
			t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut)
		}
		// Both, on separate lines: the clean sentence is still true, and the
		// footnote is what qualifies it.
		if !strings.Contains(out, "No known vulnerabilities found in 1 package(s).\n") {
			t.Errorf("table lacks the clean sentence:\n%s", out)
		}
		if !strings.Contains(out, "\n"+d111Footnote+"\n") {
			t.Errorf("table lacks the frozen footnote %q though no finding sits under the key:\n%s", d111Footnote, out)
		}
		wantLine := "\ncoverage: Alpine:v3.19 frozen since " + d111FrozenDate + ", osv data as of " + d111AsOfDate + "\n"
		if !strings.Contains(out, wantLine) {
			t.Errorf("table lacks the coverage line %q:\n%s", wantLine, out)
		}
		// (8) The coverage lines carry no color: a terminal and a pipe get
		// the same bytes on a scan with nothing else to color.
		tty, _, _ := scanImage(t, db, alpine319Files(), Options{Colorize: true})
		if tty != out {
			t.Errorf("table differs between Colorize true and false:\n--- tty ---\n%s\n--- piped ---\n%s", tty, out)
		}
	})

	t.Run("sarif", func(t *testing.T) {
		out, errOut, code := scanImage(t, db, alpine319Files(), Options{Output: "sarif"})
		if code != 0 {
			t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut)
		}
		doc := decodeSARIF(t, out)
		run := doc.Runs[0]
		var rules int
		for _, r := range run.Tool.Driver.Rules {
			if r.ID == frozenDataRule {
				rules++
				if r.Name != "FrozenData" || r.ShortDescription.Text != "Advisory data for this ecosystem is frozen" {
					t.Errorf("frozen-data rule = %+v", r)
				}
			}
		}
		if rules != 1 {
			t.Errorf("driver.rules declares %s %d time(s), want exactly 1 (D55)", frozenDataRule, rules)
		}
		sentence := strings.TrimPrefix(d111Footnote, "@ ")
		var results int
		for _, r := range run.Results {
			if r.RuleID != frozenDataRule {
				continue
			}
			results++
			if r.Level != "note" {
				t.Errorf("frozen-data result level = %q, want note", r.Level)
			}
			if r.Message.Text != sentence {
				t.Errorf("frozen-data message = %q, want %q", r.Message.Text, sentence)
			}
			if len(r.PartialFingerprints) == 0 {
				t.Errorf("frozen-data result has no partialFingerprints (GitHub requires one)")
			}
		}
		if results != 1 {
			t.Errorf("%d %s result(s), want exactly 1", results, frozenDataRule)
		}
		inv := run.Invocations[0]
		if len(inv.Properties.Coverage) != 1 || inv.Properties.Coverage[0].Ecosystem != "Alpine:v3.19" ||
			inv.Properties.Coverage[0].State != "frozen" || inv.Properties.Coverage[0].FrozenSince != d111FrozenDate {
			t.Errorf("invocation properties.coverage = %+v, want the frozen Alpine:v3.19 record", inv.Properties.Coverage)
		}
		var notified bool
		for _, n := range inv.ToolExecutionNotifications {
			if n.Message.Text == sentence {
				notified = true
			}
		}
		if !notified {
			t.Errorf("no toolExecutionNotification carries %q: %+v", sentence, inv.ToolExecutionNotifications)
		}
	})
}

// (2) The same image against live data: nothing about freezing anywhere, and
// the table's one coverage line for the live keys.
func TestRun_D111_LiveKeyIsOneLineAndNoFrozenDisclosure(t *testing.T) {
	db := d111DB(t, d111LiveProviders())

	out, errOut, code := scanImage(t, db, alpine319Files(), Options{Output: "json"})
	if code != 0 {
		t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut)
	}
	doc, raw := decodeD111(t, out)
	want := []d111Coverage{{
		Ecosystem: "Alpine:v3.19", Packages: 1, Evaluated: 1, State: "live",
		Provider: "osv", DataAsOf: d111AsOfDate,
	}}
	if !reflect.DeepEqual(doc.Coverage, want) {
		t.Errorf("coverage = %+v\nwant       %+v", doc.Coverage, want)
	}
	var recs []map[string]json.RawMessage
	if err := json.Unmarshal(raw["coverage"], &recs); err != nil || len(recs) != 1 {
		t.Fatalf("coverage is not a one-element array: %v %s", err, raw["coverage"])
	}
	if _, present := recs[0]["frozenSince"]; present {
		t.Errorf("a live key carries frozenSince: %s", raw["coverage"])
	}
	if doc.Summary.FrozenKeys == nil || *doc.Summary.FrozenKeys != 0 {
		t.Errorf("summary.frozenKeys = %v, want present and 0", doc.Summary.FrozenKeys)
	}

	table, _, _ := scanImage(t, db, alpine319Files(), Options{})
	if strings.Contains(table, "carried forward") || strings.Contains(table, "\n@ ") {
		t.Errorf("table footnotes a live key:\n%s", table)
	}
	if !strings.Contains(table, "\ncoverage: 1 key(s) live, data as of "+d111AsOfDate+"\n") {
		t.Errorf("table lacks the live coverage line:\n%s", table)
	}

	sarif, _, _ := scanImage(t, db, alpine319Files(), Options{Output: "sarif"})
	s := decodeSARIF(t, sarif)
	for _, r := range s.Runs[0].Tool.Driver.Rules {
		if r.ID == frozenDataRule {
			t.Errorf("driver.rules declares %s for a live key", frozenDataRule)
		}
	}
	for _, r := range s.Runs[0].Results {
		if r.RuleID == frozenDataRule {
			t.Errorf("a %s result for a live key: %+v", frozenDataRule, r)
		}
	}
	if c := s.Runs[0].Invocations[0].Properties.Coverage; len(c) != 1 || c[0].State != "live" {
		t.Errorf("invocation properties.coverage = %+v, want the one live key", c)
	}
}

// (3) An SBOM where the frozen key (npm) is clean and the live one (Go) has
// a finding: the footnote is for npm, which no row carries; the Go row is
// exactly as before. frozenDB is D110's own fixture: npm frozen since
// 2026-06-30, Go live, no DataAsOf recorded.
func TestRun_D111_FrozenCleanKeyBesideALiveFinding(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"frozenpkg","version":"2.0.0","purl":"pkg:npm/frozenpkg@2.0.0"},` +
		`{"type":"library","name":"livepkg","version":"1.0.0","purl":"pkg:golang/example.com/livepkg@1.0.0"}]}`
	sbom := filepath.Join(t.TempDir(), "s.cdx.json")
	if err := os.WriteFile(sbom, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	db := frozenDB(t)
	run := func(opts Options) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, sbom, opts, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d, want 0\nstderr: %s", code, errOut.String())
		}
		return out.String()
	}

	table := run(Options{})
	footnote := "\n@ advisory data for npm includes entries carried forward since 2026-06-30: " +
		"the upstream stopped publishing some or all of it\n"
	if !strings.Contains(table, footnote) {
		t.Errorf("table lacks the npm footnote %q:\n%s", footnote, table)
	}
	var goRow string
	for _, line := range strings.Split(table, "\n") {
		if strings.Contains(line, liveID) {
			goRow = line
		}
	}
	if goRow == "" || !strings.Contains(goRow, "livepkg") || strings.Contains(goRow, "@") {
		t.Errorf("Go row = %q, want the live finding's row with no frozen marker", goRow)
	}
	if strings.Contains(table, "advisory data for Go") {
		t.Errorf("table footnotes the live Go key:\n%s", table)
	}
	if !strings.Contains(table, "\ncoverage: 1 key(s) live\ncoverage: npm frozen since 2026-06-30\n") {
		t.Errorf("table lacks the coverage block (one live line, then npm):\n%s", table)
	}

	got, _ := decodeD111(t, run(Options{Output: "json"}))
	want := []d111Coverage{
		{Ecosystem: "Go", Packages: 1, Evaluated: 1, State: "live", Provider: "osv"},
		{Ecosystem: "npm", Packages: 1, Evaluated: 1, State: "frozen", Provider: "osv", FrozenSince: "2026-06-30"},
	}
	if !reflect.DeepEqual(got.Coverage, want) {
		t.Errorf("coverage = %+v\nwant       %+v", got.Coverage, want)
	}
	// The per-key counts are Summarize's own definition, split by key.
	var sum int
	for _, c := range got.Coverage {
		sum += c.Evaluated
	}
	if sum != got.Summary.Evaluated {
		t.Errorf("coverage evaluated sums to %d, summary.evaluated = %d", sum, got.Summary.Evaluated)
	}
}

// (4) A release assay routes but the database lacks: not-in-database, and
// the distro is named as recognised — the half of the old `cause=coverage`
// collapse that is the database's gap, not the distro's.
func TestRun_D111_RoutedReleaseTheDatabaseLacks(t *testing.T) {
	db := d111DB(t, map[string]store.Provenance{"osv": {Ecosystems: []string{"Alpine:v3.18"}, DataAsOf: d111DataAsOf}})
	out, errOut, code := scanImage(t, db, alpine319Files(), Options{Output: "json"})
	if code != 2 {
		t.Fatalf("Run = %d, want 2 unchanged (nothing could be evaluated)\nstderr: %s", code, errOut)
	}
	doc, _ := decodeD111(t, out)
	want := []d111Coverage{{Ecosystem: "Alpine:v3.19", Packages: 1, Evaluated: 0, State: "not-in-database"}}
	if !reflect.DeepEqual(doc.Coverage, want) {
		t.Errorf("coverage = %+v\nwant       %+v", doc.Coverage, want)
	}
	if doc.Distro == nil || doc.Distro.ID != "alpine" || doc.Distro.VersionID != "3.19.9" ||
		doc.Distro.Ecosystem != "Alpine:v3.19" || !doc.Distro.Recognized {
		t.Errorf("distro = %+v, want alpine 3.19.9 Alpine:v3.19 recognized", doc.Distro)
	}

	table, _, _ := scanImage(t, db, alpine319Files(), Options{})
	if !strings.Contains(table, "\ncoverage: Alpine:v3.19 not-in-database\n") {
		t.Errorf("table lacks the not-in-database line:\n%s", table)
	}
	if strings.Contains(table, "key(s) live") {
		t.Errorf("table claims a live key when none is:\n%s", table)
	}
}

// (5) The review's probe: an os-release assay does not route, over an apk
// database. Before D111 the only trace was the reason text
// `no version comparer for ecosystem ""`, which D36 forbids a policy to match.
func TestRun_D111_UnrecognisedDistroIsNamed(t *testing.T) {
	files := map[string]string{
		osReleasePath: "ID=centos\nVERSION_ID=7\n",
		apkDBPath:     apkOneRecord,
	}
	out, errOut, code := scanImage(t, testDB(t), files, Options{Output: "json"})
	if code != 2 {
		t.Fatalf("Run = %d, want 2 unchanged\nstderr: %s", code, errOut)
	}
	doc, raw := decodeD111(t, out)
	if doc.Distro == nil {
		t.Fatalf("distro is absent:\n%s", out)
	}
	if doc.Distro.ID != "centos" || doc.Distro.VersionID != "7" || doc.Distro.Ecosystem != "" || doc.Distro.Recognized {
		t.Errorf("distro = %+v, want centos 7, ecosystem \"\", recognized false", *doc.Distro)
	}
	// recognized false must be a statement, not an omitted key.
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw["distro"], &d); err != nil {
		t.Fatal(err)
	}
	if string(d["recognized"]) != "false" || string(d["ecosystem"]) != `""` {
		t.Errorf("distro = %s, want recognized:false and ecosystem:\"\" present", raw["distro"])
	}
	if len(doc.Coverage) != 1 || doc.Coverage[0].Ecosystem != "" || doc.Coverage[0].State != "no-comparer" ||
		doc.Coverage[0].Packages != 1 || doc.Coverage[0].Evaluated != 0 {
		t.Errorf("coverage = %+v, want one no-comparer record for key \"\"", doc.Coverage)
	}
}

// (6) inventoryScope is an image fact: present on an image, ABSENT — not
// null — on a directory and on an SBOM.
func TestRun_D111_InventoryScopeOnlyForImages(t *testing.T) {
	db := testDB(t)

	t.Run("image", func(t *testing.T) {
		out, errOut, code := scanImage(t, db, alpine319Files(), Options{Output: "json"})
		if code != 0 {
			t.Fatalf("Run = %d\nstderr: %s", code, errOut)
		}
		doc, _ := decodeD111(t, out)
		s := doc.InventoryScope
		if s == nil || s.OSPackages != "read" || s.Bitnami != "none" || s.ApplicationPackages != "not-read" {
			t.Errorf("inventoryScope = %+v, want read/none/not-read", s)
		}
	})

	t.Run("bitnami image", func(t *testing.T) {
		bdb := d111DB(t, map[string]store.Provenance{
			"osv":     {Ecosystems: []string{"Alpine:v3.19"}},
			"bitnami": {Ecosystems: []string{"Bitnami"}},
		})
		files := alpine319Files()
		files["opt/bitnami/postgresql/.spdx-postgresql.spdx"] = bitnamiSPDXDoc("postgresql", "18.6.0-3", "photon-5")
		out, errOut, code := scanImage(t, bdb, files, Options{Output: "json"})
		if code != 0 {
			t.Fatalf("Run = %d\nstderr: %s", code, errOut)
		}
		doc, _ := decodeD111(t, out)
		s := doc.InventoryScope
		if s == nil || s.OSPackages != "read" || s.Bitnami != "read" || s.ApplicationPackages != "not-read" {
			t.Errorf("inventoryScope = %+v, want read/read/not-read", s)
		}
	})

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		writeManifest(t, dir, "go.mod", "module example.com/d111\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n")
		var out, errOut bytes.Buffer
		if code := Run(context.Background(), db, "dir:"+dir, Options{Output: "json"}, &out, &errOut); code != 0 {
			t.Fatalf("Run = %d\nstderr: %s", code, errOut.String())
		}
		_, raw := decodeD111(t, out.String())
		if v, present := raw["inventoryScope"]; present {
			t.Errorf("a directory scan carries inventoryScope: %s", v)
		}
		if v, present := raw["distro"]; present {
			t.Errorf("a directory scan carries distro: %s", v)
		}
		if _, present := raw["coverage"]; !present {
			t.Errorf("coverage is absent from a directory scan; it is always present")
		}
	})

	t.Run("sbom", func(t *testing.T) {
		out, _ := runFrozen(t, Options{Output: "json"})
		_, raw := decodeD111(t, out)
		if v, present := raw["inventoryScope"]; present {
			t.Errorf("an SBOM scan carries inventoryScope: %s", v)
		}
	})
}

// (7) A suppressed finding under a frozen key keeps the marker the active
// row would have had, and the footnote that explains it still prints.
func TestRun_D111_SuppressedFrozenFindingCarriesTheMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: "ALPINE-2024-0002", Kind: advisory.KindVulnerability, Database: "ALPINE",
		Upstream: []string{"CVE-2024-99002"},
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
		Affected: []advisory.Affected{{
			Ecosystem: "Alpine:v3.19", Name: "busybox",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "1.36.1-r99"}}}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{Providers: d111FrozenProviders()}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), ".assay.yaml")
	if err := os.WriteFile(cfg, []byte("ignore:\n  - vulnerability: CVE-2024-99002\n    reason: d111 waiver\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := scanImage(t, path, alpine319Files(), Options{IgnoreFile: cfg})
	if code != 0 {
		t.Fatalf("Run = %d\nstderr: %s", code, errOut)
	}
	// The rendered pair, not the glyph alone: '@' also opens the footnote.
	wantRow := "  busybox-binsh  Alpine:v3.19 @  ALPINE-2024-0002  (ignore-file: d111 waiver)\n"
	if !strings.Contains(out, wantRow) {
		t.Errorf("suppressed line lacks the frozen marker; want %q in:\n%s", wantRow, out)
	}
	if !strings.Contains(out, "\n"+d111Footnote+"\n") {
		t.Errorf("table lacks the footnote for the suppressed row's marker:\n%s", out)
	}
}

// (8) No color reaches a piped table, on a scan that has a finding to color.
func TestRun_D111_PipedTableHasNoEscapes(t *testing.T) {
	out, _ := runFrozen(t, Options{})
	if esc := string(rune(27)); strings.Contains(out, esc) {
		t.Errorf("piped table carries an escape sequence:\n%q", out)
	}
	if !strings.Contains(out, "\ncoverage: ") {
		t.Errorf("table lacks any coverage line:\n%s", out)
	}
}

// inventoryScope.bitnami's third value: markers present, none of them read.
// A symlinked marker is counted (D99, QA round 5) but never followed, so an
// image whose only markers are symlinks had Bitnami content that reached no
// part of the inventory — "none" would deny it was there and "read" would
// claim it was read. Driven through catalogFromImage because the fixture needs
// a symlink entry, which writeImageTar's map cannot express.
func TestCatalogFromImage_D111_SymlinkOnlyBitnamiMarkersAreNotRead(t *testing.T) {
	img := &source.Image{Layers: []source.Layer{layerWithSymlinks(t, "sha256:bitlink",
		map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkOneRecord},
		map[string]string{"opt/bitnami/common/.spdx-wait-for-port.spdx": "/nowhere/.spdx-x.spdx"},
	)}}
	_, _, scope, err := catalogFromImage(context.Background(), "test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v", err)
	}
	want := report.InventoryScopeRecord{OSPackages: "read", Bitnami: "not-read", ApplicationPackages: "not-read"}
	if scope != want {
		t.Errorf("scope = %+v, want %+v", scope, want)
	}
}

// The legacy components file alone is a read Bitnami inventory too. D99 says
// it ships beside SPDX markers, so the existing legacy fixture carries both and
// the marker branch answers first; this one holds the legacy branch on its own.
func TestCatalogFromImage_D111_LegacyOnlyBitnamiIsRead(t *testing.T) {
	img := rpmImage(t, map[string]string{
		osReleasePath:     osReleaseAlpine319,
		apkDBPath:         apkOneRecord,
		bitnamiLegacyPath: `{"postgresql":{"arch":"amd64","distro":"debian-12","type":"NAMI","version":"17.5.0-14"}}`,
	})
	_, _, scope, err := catalogFromImage(context.Background(), "test-image", img)
	if err != nil {
		t.Fatalf("catalogFromImage: %v", err)
	}
	if scope.Bitnami != "read" {
		t.Errorf("scope.Bitnami = %q, want read", scope.Bitnami)
	}
}
