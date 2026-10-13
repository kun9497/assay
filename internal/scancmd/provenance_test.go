package scancmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// D120's caller tests. Each scenario is one the 2026-10-13 measurement found
// the report could not explain — two runs that differed in exit code, input
// or waiver while their documents were byte-identical, or a run that ended
// with no record at all — driven through Run and asserted on the document a
// consumer reads, so deleting the code that fills any one field turns its
// test red.

const (
	provAdvID = "GHSA-prov-0001"
	provCVE   = "CVE-2031-7001"
	provPkg   = "example.com/provpkg"
	provPURL  = "pkg:golang/example.com/provpkg@1.0.0"
)

// provDB is a database holding one critical advisory on provPkg, with rating,
// EOL, frozen and renamed metadata so the database record has every field to
// carry. The rating source's Error holds an address the record must never
// copy.
func provDB(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Put(advisory.Advisory{
		ID: provAdvID, Kind: advisory.KindVulnerability, Database: "GHSA", Aliases: []string{provCVE},
		Severity: []advisory.Severity{{Type: "CVSS_V3", Score: vecCritical}},
		Affected: []advisory.Affected{{
			Ecosystem: "Go", Name: provPkg,
			Ranges: []advisory.Range{{Type: advisory.RangeSemver,
				Events: []advisory.Event{{Introduced: "0"}, {Fixed: "2.0.0"}}}},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt: time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{"osv": {
			Ecosystems: []string{"Go"},
			Frozen:     map[string]time.Time{"Debian:11": time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)},
			Renamed:    map[string]string{"Echo:PyPi": "Echo:PyPI"},
		}},
		Ratings: map[string]store.Provenance{
			"NVD":  {DataAsOf: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)},
			"EPSS": {Error: "dial tcp 10.9.8.7:443: internal-mirror.corp refused"},
		},
		EOLProvenance: &store.Provenance{DataAsOf: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// provSBOM writes a CycloneDX SBOM naming provPkg at version, with a
// serialNumber, to path.
func provSBOM(t *testing.T, path, version string) {
	t.Helper()
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,` +
		`"serialNumber":"urn:uuid:7d0c0b6e-0000-4000-8000-00000000d120","components":[` +
		`{"type":"library","name":"` + provPkg + `","version":"` + version + `",` +
		`"purl":"pkg:golang/` + provPkg + `@` + version + `"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// provVEX writes an OpenVEX document to path. suppress decides whether its
// one statement exonerates the finding (not_affected) or says it is affected.
func provVEX(t *testing.T, path, id string, suppress bool) {
	t.Helper()
	status := `"status":"affected"`
	if suppress {
		status = `"status":"not_affected","justification":"vulnerable_code_not_present"`
	}
	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"` + id + `",` +
		`"author":"D120 Test","timestamp":"2026-10-13T00:00:00Z","version":1,"statements":[` +
		`{"vulnerability":{"name":"` + provCVE + `"},"products":[{"@id":"` + provPURL + `"}],` + status + `}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// provRun runs one scan and returns stdout, stderr and the exit code.
func provRun(t *testing.T, db, target string, opts Options) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), db, target, opts, &out, &errOut)
	return out.String(), errOut.String(), code
}

// provenanceOf decodes a JSON report and returns its provenance object as a
// generic map, failing when there is none.
func provenanceOf(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
	}
	p, ok := doc["provenance"].(map[string]any)
	if !ok {
		t.Fatalf("report has no provenance object:\n%s", out)
	}
	return p
}

// at walks a decoded JSON value by keys and indexes.
func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, k := range path {
		switch k := k.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("at %v: %T is not an object", path, v)
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("at %v: %v has no index %d", path, v, k)
			}
			v = a[k]
		}
	}
	return v
}

// readSidecar reads and decodes a --provenance file.
func readSidecar(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no sidecar at %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("sidecar is not JSON: %v\n%s", err, data)
	}
	return m
}

func band(b severity.Band) *severity.Band { return &b }

// Scenario 1 of the measurement: --fail-on critical and --fail-on low wrote
// byte-identical JSON with exit codes 1 and 0. Now the documents differ, and
// ONLY in provenance.policy — and two identical runs stay byte-identical,
// because nothing per-run reached the report.
func TestRun_D120_GatesDifferOnlyInPolicyAndIdenticalRunsAreByteIdentical(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")

	crit, _, _ := provRun(t, db, sbom, Options{Output: "json", FailOn: band(severity.Critical)})
	low, _, _ := provRun(t, db, sbom, Options{Output: "json", FailOn: band(severity.Low)})
	again, _, _ := provRun(t, db, sbom, Options{Output: "json", FailOn: band(severity.Low)})

	if low != again {
		t.Errorf("two identical runs wrote different reports:\n%s\n---\n%s", low, again)
	}
	if crit == low {
		t.Fatal("--fail-on critical and --fail-on low still write byte-identical reports")
	}
	pc, pl := provenanceOf(t, crit), provenanceOf(t, low)
	if got := at(t, pc, "policy", "failOn"); got != "critical" {
		t.Errorf("policy.failOn = %v, want critical", got)
	}
	if got := at(t, pl, "policy", "failOn"); got != "low" {
		t.Errorf("policy.failOn = %v, want low", got)
	}
	// Everything else is the same document.
	var dc, dl map[string]any
	_ = json.Unmarshal([]byte(crit), &dc)
	_ = json.Unmarshal([]byte(low), &dl)
	delete(dc["provenance"].(map[string]any), "policy")
	delete(dl["provenance"].(map[string]any), "policy")
	if !reflect.DeepEqual(dc, dl) {
		t.Errorf("the two reports differ outside provenance.policy:\n%s\n---\n%s", crit, low)
	}
}

// Scenario 2: an ignore rule past its expiry wrote JSON byte-identical to no
// ignore file at all. Now the file, its hash and each rule's expiry, expired
// flag and match count are in the record.
func TestRun_D120_ExpiredIgnoreRuleIsVisibleInWaivers(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	cfg := filepath.Join(dir, "ignore.yaml")
	body := "ignore:\n" +
		"  - vulnerability: " + provCVE + "\n    reason: accepted until the vendor ships\n    expires: 2001-01-01\n" +
		"  - vulnerability: " + provCVE + "\n    reason: accepted again\n    expires: 2999-12-31\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))

	out, _, _ := provRun(t, db, sbom, Options{Output: "json", IgnoreFile: cfg})
	none, _, _ := provRun(t, db, sbom, Options{Output: "json", IgnoreFile: ""})
	p := provenanceOf(t, out)
	f := at(t, p, "waivers", "ignoreFile")
	if f == nil {
		t.Fatalf("waivers.ignoreFile is null with --config given:\n%s", out)
	}
	if got := at(t, f, "path"); got != cfg {
		t.Errorf("ignoreFile.path = %v, want the path as given %q", got, cfg)
	}
	if got := at(t, f, "discovered"); got != false {
		t.Errorf("ignoreFile.discovered = %v, want false for --config", got)
	}
	if got := at(t, f, "sha256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("ignoreFile.sha256 = %v, want the file's hash", got)
	}
	want := []struct {
		rule    float64
		expires string
		expired bool
		matched float64
	}{{1, "2001-01-01", true, 0}, {2, "2999-12-31", false, 1}}
	for i, w := range want {
		r := at(t, f, "rules", i)
		if at(t, r, "rule") != w.rule || at(t, r, "expires") != w.expires ||
			at(t, r, "expired") != w.expired || at(t, r, "matched") != w.matched {
			t.Errorf("rules[%d] = %v, want rule %v expires %s expired %v matched %v",
				i, r, w.rule, w.expires, w.expired, w.matched)
		}
	}
	if got := at(t, provenanceOf(t, none), "waivers", "ignoreFile"); got != nil {
		t.Errorf("waivers.ignoreFile = %v with no ignore file, want null", got)
	}
}

// Scenario 3: two VEX documents with the same name, one suppressing and one
// not; the second run was byte-identical to a run with no --vex. Now each is
// named by the path as given and told apart by its hash, with its @id and
// statement counts.
func TestRun_D120_SameNamedVEXDocumentsAreToldApartBySHA256(t *testing.T) {
	base := t.TempDir()
	db := provDB(t, base)
	sbom := filepath.Join(base, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	dirA, dirB := filepath.Join(base, "a"), filepath.Join(base, "b")
	for _, d := range []string{dirA, dirB} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	provVEX(t, filepath.Join(dirA, "vex.json"), "https://example.com/vex/a", true)
	provVEX(t, filepath.Join(dirB, "vex.json"), "https://example.com/vex/b", false)

	t.Chdir(dirA)
	outA, _, _ := provRun(t, db, sbom, Options{Output: "json", VEXFiles: []string{"vex.json"}})
	t.Chdir(dirB)
	outB, _, _ := provRun(t, db, sbom, Options{Output: "json", VEXFiles: []string{"vex.json"}})
	outNone, _, _ := provRun(t, db, sbom, Options{Output: "json"})

	if outB == outNone {
		t.Fatal("a non-suppressing --vex still writes the report a run with no --vex writes")
	}
	va := at(t, provenanceOf(t, outA), "waivers", "vex", 0)
	vb := at(t, provenanceOf(t, outB), "waivers", "vex", 0)
	if at(t, va, "path") != "vex.json" || at(t, vb, "path") != "vex.json" {
		t.Errorf("vex paths = %v, %v, want both \"vex.json\" as given", at(t, va, "path"), at(t, vb, "path"))
	}
	sa, sb := at(t, va, "sha256"), at(t, vb, "sha256")
	if sa == "" || sa == nil || sa == sb {
		t.Errorf("vex sha256 = %v and %v, want two different hashes", sa, sb)
	}
	if at(t, va, "id") != "https://example.com/vex/a" {
		t.Errorf("vex id = %v, want the document's @id", at(t, va, "id"))
	}
	if at(t, va, "statements") != 1.0 || at(t, va, "applied") != 1.0 || at(t, va, "unmatched") != 0.0 {
		t.Errorf("suppressing document counts = %v, want 1 statement, 1 applied, 0 unmatched", va)
	}
	// An affected statement matches the finding and suppresses nothing.
	if at(t, vb, "statements") != 1.0 || at(t, vb, "applied") != 0.0 || at(t, vb, "unmatched") != 0.0 {
		t.Errorf("affected-status document counts = %v, want 1 statement, 0 applied, 0 unmatched", vb)
	}
	if got := at(t, provenanceOf(t, outNone), "waivers", "vex"); !reflect.DeepEqual(got, []any{}) {
		t.Errorf("waivers.vex = %v with no --vex, want []", got)
	}
}

// Scenario 4: an SBOM changed in place produced different findings and
// nothing that identified the input. Now target.sha256 is the file's hash,
// and the SBOM's own serialNumber is beside it.
func TestRun_D120_AnSBOMChangedInPlaceChangesTargetSHA256(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	before, _ := os.ReadFile(sbom)
	out1, _, _ := provRun(t, db, sbom, Options{Output: "json"})
	provSBOM(t, sbom, "2.0.0")
	out2, _, _ := provRun(t, db, sbom, Options{Output: "json"})

	t1, t2 := at(t, provenanceOf(t, out1), "target"), at(t, provenanceOf(t, out2), "target")
	sum := sha256.Sum256(before)
	if got := at(t, t1, "sha256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("target.sha256 = %v, want the SBOM's hash %x", got, sum)
	}
	if at(t, t1, "sha256") == at(t, t2, "sha256") {
		t.Error("target.sha256 did not change when the SBOM changed in place")
	}
	if got := at(t, t1, "serialNumber"); got != "urn:uuid:7d0c0b6e-0000-4000-8000-00000000d120" {
		t.Errorf("target.serialNumber = %v, want the SBOM's own", got)
	}
	if at(t, t1, "argument") != sbom || at(t, t1, "kind") != "sbom" {
		t.Errorf("target = %v, want the argument as typed and kind sbom", t1)
	}
}

// A directory scan names every manifest it read, root-relative, with its hash.
func TestRun_D120_DirectoryManifestsCarryTheirHashes(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	root := filepath.Join(dir, "proj")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	gomod := "module example.com/x\n\ngo 1.21\n\nrequire " + provPkg + " v1.0.0\n"
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, _ := provRun(t, db, root, Options{Output: "json"})
	m := at(t, provenanceOf(t, out), "target", "manifests", 0)
	sum := sha256.Sum256([]byte(gomod))
	if at(t, m, "path") != "go.mod" || at(t, m, "sha256") != hex.EncodeToString(sum[:]) {
		t.Errorf("manifests[0] = %v, want go.mod with its hash", m)
	}
}

// The database record: schema, build time, every rating source's data-as-of
// (a failed one flagged, its error text never copied), the EOL catalogue, and
// the frozen and renamed keys by name. No artifact: a built database has no
// record beside it, and reports none.
func TestRun_D120_DatabaseRecord(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	out, _, _ := provRun(t, db, sbom, Options{Output: "json"})
	d := at(t, provenanceOf(t, out), "database")
	if at(t, d, "schema") != float64(store.SchemaVersion) || at(t, d, "builtAt") != "2026-10-12T03:00:00Z" {
		t.Errorf("database = %v, want schema %d built 2026-10-12T03:00:00Z", d, store.SchemaVersion)
	}
	if got := at(t, d, "artifact"); got != nil {
		t.Errorf("database.artifact = %v with no artifact record, want absent", got)
	}
	want := []any{
		map[string]any{"source": "EPSS", "dataAsOf": "", "failed": true},
		map[string]any{"source": "NVD", "dataAsOf": "2026-10-11T00:00:00Z"},
	}
	if got := at(t, d, "ratings"); !reflect.DeepEqual(got, want) {
		t.Errorf("database.ratings = %v, want %v", got, want)
	}
	if got := at(t, d, "eol", "dataAsOf"); got != "2026-10-10T00:00:00Z" {
		t.Errorf("database.eol.dataAsOf = %v", got)
	}
	if got := at(t, d, "frozen"); !reflect.DeepEqual(got, []any{map[string]any{"key": "Debian:11", "since": "2026-08-31"}}) {
		t.Errorf("database.frozen = %v", got)
	}
	if got := at(t, d, "renamed"); !reflect.DeepEqual(got, []any{map[string]any{"from": "Echo:PyPi", "to": "Echo:PyPI"}}) {
		t.Errorf("database.renamed = %v", got)
	}
	if strings.Contains(out, "internal-mirror") || strings.Contains(out, "10.9.8.7") {
		t.Errorf("a rating source's error text reached the report:\n%s", out)
	}

	// With a pull record beside the database, the artifact is named.
	if err := store.WriteArtifactRecord(db, store.ArtifactRecord{
		Reference: "ghcr.io/example/assay-db:v9", Digest: "sha256:" + strings.Repeat("ab", 32), PulledAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	out, _, _ = provRun(t, db, sbom, Options{Output: "json"})
	a := at(t, provenanceOf(t, out), "database", "artifact")
	if at(t, a, "reference") != "ghcr.io/example/assay-db:v9" || at(t, a, "digest") != "sha256:"+strings.Repeat("ab", 32) {
		t.Errorf("database.artifact = %v, want the record's reference and digest", a)
	}
}

// Scenario 5: seven exit-2 paths wrote zero bytes. Now --provenance is
// written on them — here a missing --vex file, which ends the scan after the
// match and before any renderer — with the exit code, the error, no report
// hash (nothing was written), and the document that failed named.
func TestRun_D120_SidecarIsWrittenOnAnExit2WithNoReport(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	side := filepath.Join(dir, "prov.json")
	missing := filepath.Join(dir, "absent-vex.json")

	out, _, code := provRun(t, db, sbom, Options{Output: "json", VEXFiles: []string{missing}, ProvenanceFile: side})
	if code != 2 || out != "" {
		t.Fatalf("Run = %d with stdout %q, want 2 and no report", code, out)
	}
	sc := readSidecar(t, side)
	if at(t, sc, "schemaVersion") != 1.0 {
		t.Errorf("sidecar schemaVersion = %v, want 1", at(t, sc, "schemaVersion"))
	}
	if at(t, sc, "run", "exitCode") != 2.0 {
		t.Errorf("run.exitCode = %v, want 2", at(t, sc, "run", "exitCode"))
	}
	if e, _ := at(t, sc, "run", "error").(string); !strings.Contains(e, "read vex document") {
		t.Errorf("run.error = %q, want the refusal's cause", e)
	}
	if at(t, sc, "run", "reportSha256") != nil {
		t.Errorf("run.reportSha256 = %v, want null: nothing was written", at(t, sc, "run", "reportSha256"))
	}
	if at(t, sc, "run", "output") != "json" {
		t.Errorf("run.output = %v, want json", at(t, sc, "run", "output"))
	}
	if at(t, sc, "provenance", "waivers", "vex", 0, "path") != missing {
		t.Errorf("the failing VEX document is not named in the record: %v", at(t, sc, "provenance", "waivers"))
	}
	for _, k := range []string{"startedAt", "finishedAt"} {
		if s, _ := at(t, sc, "run", k).(string); !strings.HasSuffix(s, "Z") {
			t.Errorf("run.%s = %q, want a UTC timestamp", k, s)
		}
	}
}

// The same on the earliest exit after classification — no database at all —
// where the error names the database path, which the record must not.
func TestRun_D120_SidecarOnAMissingDatabaseHidesItsPath(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	side := filepath.Join(dir, "prov.json")
	db := filepath.Join(dir, "nodb", "vulnerability.db")

	_, stderr, code := provRun(t, db, sbom, Options{ProvenanceFile: side})
	if code != 2 || !strings.Contains(stderr, db) {
		t.Fatalf("Run = %d, want 2 with the path on stderr (the human channel):\n%s", code, stderr)
	}
	sc := readSidecar(t, side)
	e, _ := at(t, sc, "run", "error").(string)
	if !strings.Contains(e, "vulnerability database not found") || !strings.Contains(e, "<database>") || strings.Contains(e, db) {
		t.Errorf("run.error = %q, want the cause with the database path replaced", e)
	}
	if at(t, sc, "provenance", "database") != nil {
		t.Errorf("provenance.database = %v for a scan that opened none, want absent", at(t, sc, "provenance", "database"))
	}
	if at(t, sc, "run", "output") != "table" {
		t.Errorf("run.output = %v, want table", at(t, sc, "run", "output"))
	}
}

// Scenario 6: the sidecar's reportSha256 is the hash of exactly the bytes
// written to stdout, and its provenance is the report's own object.
func TestRun_D120_ReportSHA256IsTheHashOfStdout(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	side := filepath.Join(dir, "prov.json")

	out, _, code := provRun(t, db, sbom, Options{Output: "json", FailOn: band(severity.High), ProvenanceFile: side})
	if code != 1 {
		t.Fatalf("Run = %d, want 1 (a critical finding under --fail-on high)", code)
	}
	sc := readSidecar(t, side)
	sum := sha256.Sum256([]byte(out))
	if got := at(t, sc, "run", "reportSha256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("run.reportSha256 = %v, want sha256 of stdout %x", got, sum)
	}
	if at(t, sc, "run", "exitCode") != 1.0 || at(t, sc, "run", "error") != "" {
		t.Errorf("run = %v, want exit 1 and no error", at(t, sc, "run"))
	}
	if got := at(t, sc, "provenance"); !reflect.DeepEqual(got, provenanceOf(t, out)) {
		t.Errorf("sidecar provenance differs from the report's:\n%v\n---\n%v", got, provenanceOf(t, out))
	}
	// The table writes a report too, and its bytes are what is hashed.
	tout, _, _ := provRun(t, db, sbom, Options{ProvenanceFile: side})
	tsum := sha256.Sum256([]byte(tout))
	if got := at(t, readSidecar(t, side), "run", "reportSha256"); got != hex.EncodeToString(tsum[:]) {
		t.Errorf("table run.reportSha256 = %v, want sha256 of stdout", got)
	}
}

// A sidecar that cannot be written is itself exit 2: the caller asked for a
// record and did not get one. The scan here would otherwise exit 0.
func TestRun_D120_AnUnwritableSidecarIsExit2(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	if _, _, code := provRun(t, db, sbom, Options{Output: "json"}); code != 0 {
		t.Fatalf("baseline Run = %d, want 0", code)
	}
	side := filepath.Join(dir, "no-such-dir", "prov.json")
	_, stderr, code := provRun(t, db, sbom, Options{Output: "json", ProvenanceFile: side})
	if code != 2 || !strings.Contains(stderr, "error: write provenance") {
		t.Errorf("Run = %d, want 2 with the write failure named:\n%s", code, stderr)
	}
}

// Nothing in the record identifies the machine or its user: run from a
// working directory with every input typed relative and the ignore file
// discovered, and no string anywhere in the report's provenance or the
// sidecar holds the directory, the database path, the username or the
// hostname.
func TestRun_D120_ProvenanceNamesNoMachinePath(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	t.Chdir(dir)
	provSBOM(t, "s.cdx.json", "1.0.0")
	provVEX(t, "vex.json", "https://example.com/vex/p", false)
	if err := os.WriteFile(".assay.yaml", []byte("ignore:\n  - package: nothing-here\n    reason: r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, _ := provRun(t, db, "s.cdx.json", Options{Output: "json", VEXFiles: []string{"vex.json"}, ProvenanceFile: "prov.json"})
	p := provenanceOf(t, out)
	if at(t, p, "waivers", "ignoreFile", "path") != ".assay.yaml" || at(t, p, "waivers", "ignoreFile", "discovered") != true {
		t.Errorf("a discovered ignore file = %v, want path .assay.yaml, discovered", at(t, p, "waivers", "ignoreFile"))
	}
	forbidden := []string{dir, filepath.ToSlash(dir), db}
	for _, k := range []string{"USERNAME", "USER"} {
		if u := os.Getenv(k); len(u) >= 3 {
			forbidden = append(forbidden, u)
		}
	}
	if h, err := os.Hostname(); err == nil && len(h) >= 3 {
		forbidden = append(forbidden, h)
	}
	for _, rec := range []any{p, readSidecar(t, "prov.json")} {
		walkStrings(rec, func(s string) {
			for _, f := range forbidden {
				if strings.Contains(strings.ToLower(s), strings.ToLower(f)) {
					t.Errorf("provenance string %q contains %q", s, f)
				}
			}
		})
	}
}

func walkStrings(v any, fn func(string)) {
	switch v := v.(type) {
	case string:
		fn(v)
	case map[string]any:
		for k, x := range v {
			fn(k)
			walkStrings(x, fn)
		}
	case []any:
		for _, x := range v {
			walkStrings(x, fn)
		}
	}
}

// Scenario 9: SARIF carries the same object in run.properties.provenance and
// the tool's semantic version, still with no timestamp.
func TestRun_D120_SARIFCarriesProvenance(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	opts := Options{Output: "sarif", Version: "v1.2.3", Commit: "abc1234", BuildDate: "2026-10-13T00:00:00Z"}
	out, _, _ := provRun(t, db, sbom, opts)
	again, _, _ := provRun(t, db, sbom, opts)
	if out != again {
		t.Error("two identical SARIF runs differ")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	run := at(t, doc, "runs", 0)
	if got := at(t, run, "tool", "driver", "semanticVersion"); got != "1.2.3" {
		t.Errorf("driver.semanticVersion = %v, want 1.2.3", got)
	}
	tool := at(t, run, "properties", "provenance", "tool")
	want := map[string]any{"name": "assay", "version": "v1.2.3", "commit": "abc1234", "buildDate": "2026-10-13T00:00:00Z", "dev": false}
	if !reflect.DeepEqual(tool, want) {
		t.Errorf("properties.provenance.tool = %v, want %v", tool, want)
	}
	if at(t, run, "properties", "provenance", "target", "kind") != "sbom" {
		t.Errorf("SARIF provenance has no target: %v", at(t, run, "properties", "provenance"))
	}
}

// An image scan defaulting --platform records the host's platform as
// defaulted, with D118's credential source by name and D119's image record;
// an archive has no registry and so no credential source; an SBOM records no
// platform. The duration gates are recorded in Go's own spelling.
func TestRun_D120_ImageTargetAndPlatformPolicy(t *testing.T) {
	isolateCredentials(t)
	ar := openRegistry(t)
	db := alpineVEXDB(t)
	img := vexRegistryImage(t, map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkThreePackages})
	ref := pushImage(t, ar.host, "library/alpine:3.19", img)

	doc, _ := scanVEXJSON(t, db, ref)
	if doc.Provenance == nil {
		t.Fatal("image report has no provenance")
	}
	tg := doc.Provenance.Target
	if tg.Kind != "image" || tg.RegistryCredentials != "none" || tg.Image == nil || tg.Image.ManifestDigest == "" {
		t.Errorf("image target = %+v, want kind image, credentials none, and the D119 record", tg)
	}
	want := source.DefaultPlatform().String()
	if pp := doc.Provenance.Policy.Platform; pp.Given || pp.Value != want {
		t.Errorf("defaulted platform = %+v, want %q not given", pp, want)
	}

	doc, _ = scanVEXJSON(t, db, alpineArchive(t, apkThreePackages))
	if doc.Provenance.Target.RegistryCredentials != "" {
		t.Errorf("an archive names a credential source %q, want none at all", doc.Provenance.Target.RegistryCredentials)
	}

	dir := t.TempDir()
	pdb := provDB(t, dir)
	sbom := filepath.Join(dir, "s.cdx.json")
	provSBOM(t, sbom, "1.0.0")
	side := filepath.Join(dir, "prov.json")
	// The age gate refuses this database (its provider has no data-as-of),
	// so the policy is read from the sidecar the refusal still writes.
	provRun(t, pdb, sbom, Options{Timeout: 90 * time.Second, DBMaxAge: 48 * time.Hour, ProvenanceFile: side})
	pol := at(t, readSidecar(t, side), "provenance", "policy")
	if !reflect.DeepEqual(at(t, pol, "platform"), map[string]any{"given": false}) {
		t.Errorf("an SBOM's platform policy = %v, want not given and no value", at(t, pol, "platform"))
	}
	if at(t, pol, "timeout") != "1m30s" || at(t, pol, "dbMaxAge") != "48h0m0s" || at(t, pol, "dbMaxRatingAge") != nil {
		t.Errorf("policy durations = %v", pol)
	}
}

// An SPDX SBOM is identified by its documentNamespace beside its hash.
func TestRun_D120_SPDXDocumentNamespace(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	const ns = "https://example.com/spdxdocs/d120-0001"
	doc := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","documentNamespace":"` + ns + `","packages":[` +
		`{"name":"provpkg","SPDXID":"SPDXRef-Package-provpkg","versionInfo":"1.0.0",` +
		`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
		`"referenceLocator":"` + provPURL + `"}]}]}`
	path := filepath.Join(dir, "s.spdx.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, _ := provRun(t, db, path, Options{Output: "json"})
	tg := at(t, provenanceOf(t, out), "target")
	sum := sha256.Sum256([]byte(doc))
	if at(t, tg, "documentNamespace") != ns || at(t, tg, "sha256") != hex.EncodeToString(sum[:]) {
		t.Errorf("SPDX target = %v, want its namespace and hash", tg)
	}
	if at(t, tg, "serialNumber") != nil {
		t.Errorf("SPDX target carries a serialNumber: %v", tg)
	}
}

// The one exit 2 that prints no error line still gives the sidecar a cause.
func TestRun_D120_IncompleteVerdictHasAnError(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	path := filepath.Join(dir, "s.cdx.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"` + provPkg + `","version":"1.0.0","purl":"` + provPURL + `"},` +
		`{"type":"library","name":"left-pad","version":"1.0.0","purl":"pkg:npm/left-pad@1.0.0"}]}`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	side := filepath.Join(dir, "prov.json")
	if _, _, code := provRun(t, db, path, Options{Output: "json", FailOnIncomplete: true, ProvenanceFile: side}); code != 2 {
		t.Fatalf("Run = %d, want 2 (npm is not covered)", code)
	}
	sc := readSidecar(t, side)
	if e := at(t, sc, "run", "error"); e != "evaluation incomplete (--fail-on-incomplete)" {
		t.Errorf("run.error = %v", e)
	}
	if at(t, sc, "run", "reportSha256") == nil {
		t.Error("run.reportSha256 is null although a report was written before the verdict")
	}
}

// A Go binary's and a jar's target.sha256 is the file's own hash. The binary
// is this test's own executable, the fixture the go-binary routing tests use.
func TestRun_D120_FileTargetsCarryTheirHashes(t *testing.T) {
	dir := t.TempDir()
	db := provDB(t, dir)
	self, err := os.Executable()
	if err != nil {
		t.Skip("no executable path:", err)
	}
	jarPath := writeJarFixture(t, "app.jar", "org.example", "app", "1.0.0")
	for _, target := range []string{"file:" + self, jarPath} {
		path := strings.TrimPrefix(target, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		side := filepath.Join(dir, "prov.json")
		provRun(t, db, target, Options{ProvenanceFile: side})
		if got := at(t, readSidecar(t, side), "provenance", "target", "sha256"); got != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: target.sha256 = %v, want the file's hash", target, got)
		}
	}
}
