package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/severity"
	"github.com/kun9497/assay/internal/version"
)

// sarifOf renders and decodes, so the assertions below run against the document
// a consumer would actually receive rather than against the structs that built
// it. A field that failed to marshal would be invisible to the second kind of
// test and is the whole point of the first.
func sarifOf(t *testing.T, res matcher.Result, cat cyclonedx.Stats) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if _, err := SARIF(&buf, res, cat, "example.com/img:1", "v0.0.0-test"); err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	return doc
}

func run0(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want exactly one", doc["runs"])
	}
	return runs[0].(map[string]any)
}

func rulesOf(t *testing.T, run map[string]any) []map[string]any {
	t.Helper()
	raw := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func resultsOf(t *testing.T, run map[string]any) []map[string]any {
	t.Helper()
	raw, _ := run["results"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		out = append(out, r.(map[string]any))
	}
	return out
}

func findingFixture(id, pkg string, band severity.Band, score float64, fixed string, state advisory.FixState) matcher.Finding {
	f := matcher.Finding{
		Package: pkgmeta.Package{
			Name: pkg, Version: "1.0.0", Ecosystem: "Debian:12",
			PURL:      "pkg:deb/debian/" + pkg + "@1.0.0",
			Locations: []pkgmeta.Location{{Path: "var/lib/dpkg/status"}},
		},
		Advisory:    advisory.Advisory{ID: id, Summary: "a summary"},
		Evidence:    version.Evidence{Fixed: fixed},
		MatchedName: pkg,
		Severity:    band,
		Score:       score,
		Ratings:     []matcher.Rating{{Database: "DEBIAN", AdvisoryID: id, Severity: band, Score: score, Fixed: fixed, FixState: state}},
	}
	return f
}

// TestSARIF_ShapeGitHubRequires pins the three things GitHub code scanning
// refuses a document without. They are not stylistic: a result with no
// partialFingerprints is not tracked across commits, so every push reopens
// every alert.
func TestSARIF_ShapeGitHubRequires(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		findingFixture("CVE-2026-1", "libc6", severity.High, 7.5, "1.0.1", advisory.FixStateFixed),
	}}
	doc := sarifOf(t, res, cyclonedx.Stats{Components: 1, Cataloged: 1})

	if doc["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", doc["version"])
	}
	if _, ok := doc["$schema"]; !ok {
		t.Error("no $schema; consumers validate against it")
	}
	run := run0(t, doc)
	r := resultsOf(t, run)[0]
	fp, ok := r["partialFingerprints"].(map[string]any)
	if !ok || len(fp) == 0 {
		t.Fatalf("result has no partialFingerprints: %v — GitHub cannot track it across commits", r)
	}
	if _, ok := r["locations"]; !ok {
		t.Error("result has no locations; GitHub drops results without one")
	}
	if got := rulesOf(t, run)[0]["properties"].(map[string]any)["security-severity"]; got != "7.5" {
		t.Errorf("security-severity = %v, want the string \"7.5\" — GitHub reads it off the "+
			"RULE and only as a string", got)
	}
}

// TestSARIF_DriverVersionIsTheBuildThatScanned pins the field D55's own
// comment on the Version parameter exists for: "a SARIF file is read
// detached from the command that produced it, so the document has to say
// what scanned." TestSARIF_ShapeGitHubRequires above asserts the SARIF
// FORMAT version (doc["version"], "2.1.0") but nothing anywhere asserts the
// tool driver's OWN version -- the assay build string threaded through
// SARIF's fifth parameter -- so blanking it (the field carries
// `omitempty`, so an empty value drops the JSON key entirely) leaves the
// whole suite green: a reader opening the document in a web UI, detached
// from the command that produced it, could not tell which build scanned.
func TestSARIF_DriverVersionIsTheBuildThatScanned(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		findingFixture("CVE-2026-3", "libc6", severity.High, 7.5, "1.0.1", advisory.FixStateFixed),
	}}
	run := run0(t, sarifOf(t, res, cyclonedx.Stats{Components: 1, Cataloged: 1}))
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if got := driver["version"]; got != "v0.0.0-test" {
		t.Errorf("driver.version = %v, want %q -- the build that produced this document",
			got, "v0.0.0-test")
	}
}

// TestSARIF_UnratedFindingCarriesNoSecuritySeverity is D17 at the SARIF
// boundary, and it is the assertion most likely to be "fixed" by someone
// wanting a tidier document.
//
// GitHub's scale starts above 0.0 and has no room for unknown. Writing 0.1 to
// fill the field bands an unrated finding as low, which is exactly the
// coercion D17 forbids — and it would be invisible, because the alert would
// look like every other low one.
func TestSARIF_UnratedFindingCarriesNoSecuritySeverity(t *testing.T) {
	res := matcher.Result{Findings: []matcher.Finding{
		findingFixture("CVE-2026-2", "zlib1g", severity.Unknown, 0, "", advisory.FixStateUnknown),
	}}
	run := run0(t, sarifOf(t, res, cyclonedx.Stats{Components: 1, Cataloged: 1}))
	props := rulesOf(t, run)[0]["properties"].(map[string]any)
	if v, ok := props["security-severity"]; ok {
		t.Errorf("security-severity = %v on an unrated finding; the field must be ABSENT, "+
			"not zeroed — any value in it is a band GitHub will show", v)
	}
	// It is still a result, still visible, and not demoted to informational.
	if got := resultsOf(t, run)[0]["level"]; got != "warning" {
		t.Errorf("level = %v, want warning — an unrated finding is still a finding", got)
	}
}

// TestSARIF_SkipsAreVisibleInBothPlaces is D55's whole reason for existing.
//
// The spec-native channel is invocations[].toolExecutionNotifications[], which
// GitHub does not support at all; a document that used only it would satisfy
// the spec and show a reader nothing. So each skip is ALSO a note-level result.
// Asserting one without the other would let the half that matters be deleted.
func TestSARIF_SkipsAreVisibleInBothPlaces(t *testing.T) {
	res := matcher.Result{
		Findings: []matcher.Finding{
			findingFixture("CVE-2026-3", "openssl", severity.Medium, 5.0, "", advisory.FixStateNotFixed),
		},
		Skipped: []matcher.Skipped{
			{
				Package: pkgmeta.Package{Name: "weird", Version: "9.9", Ecosystem: "Debian:12"},
				Reason:  "version could not be read",
				Cause:   matcher.SkipTarget,
			},
		},
	}
	run := run0(t, sarifOf(t, res, cyclonedx.Stats{Components: 2, Cataloged: 2}))

	var notEvaluated []map[string]any
	for _, r := range resultsOf(t, run) {
		if r["ruleId"] == notEvaluatedRuleID {
			notEvaluated = append(notEvaluated, r)
		}
	}
	if len(notEvaluated) != 1 {
		t.Fatalf("not-evaluated results = %d, want 1 — a skip invisible in GitHub is a "+
			"partial scan reading as a complete one", len(notEvaluated))
	}
	// The RULE has to be declared too, not just referenced. A result whose
	// ruleId names nothing in driver.rules is a degraded document that a
	// consumer may drop outright — and dropping it is precisely the silence
	// this decision exists to prevent. Found by mutation: deleting the rule
	// while keeping the results left every test here green.
	var declared bool
	for _, rule := range rulesOf(t, run) {
		if rule["id"] == notEvaluatedRuleID {
			declared = true
			if _, ok := rule["properties"].(map[string]any)["security-severity"]; ok {
				t.Error("the not-evaluated rule carries a security-severity; it makes no " +
					"security claim and must not be scored")
			}
		}
	}
	if !declared {
		t.Errorf("results reference %q but driver.rules does not declare it", notEvaluatedRuleID)
	}
	if got := notEvaluated[0]["level"]; got != "note" {
		t.Errorf("level = %v, want note: this is not a claim about the package's security", got)
	}
	if msg := notEvaluated[0]["message"].(map[string]any)["text"].(string); !strings.Contains(msg, "weird") ||
		!strings.Contains(msg, "version could not be read") {
		t.Errorf("message = %q, want it to name the package and the reason", msg)
	}

	inv := run["invocations"].([]any)[0].(map[string]any)
	notes := inv["toolExecutionNotifications"].([]any)
	// One summary plus one per skip. Asserting only "non-empty" would pass on a
	// document that dropped every skip and kept the summary.
	if len(notes) != 2 {
		t.Fatalf("toolExecutionNotifications = %d, want 2 (summary + one skip)", len(notes))
	}
	if !strings.Contains(notes[1].(map[string]any)["message"].(map[string]any)["text"].(string), "weird") {
		t.Errorf("the per-skip notification does not name the package: %v", notes[1])
	}
	// The summary says the run is worth trusting or not, and a scan that
	// evaluated something is.
	if inv["executionSuccessful"] != true {
		t.Errorf("executionSuccessful = %v, want true: one package was evaluated", inv["executionSuccessful"])
	}
}

// TestSARIF_NothingEvaluatedIsNotSuccessful is the case the format makes
// easiest to get wrong: zero findings serialises to an empty results array,
// which reads as a clean scan. It must not.
func TestSARIF_NothingEvaluatedIsNotSuccessful(t *testing.T) {
	res := matcher.Result{Skipped: []matcher.Skipped{
		{Package: pkgmeta.Package{Name: "a"}, Reason: "no comparer", Cause: matcher.SkipCoverage},
		{Package: pkgmeta.Package{Name: "b"}, Reason: "no comparer", Cause: matcher.SkipCoverage},
	}}
	run := run0(t, sarifOf(t, res, cyclonedx.Stats{Components: 2, Cataloged: 2}))
	inv := run["invocations"].([]any)[0].(map[string]any)
	if inv["executionSuccessful"] != false {
		t.Errorf("executionSuccessful = %v, want false — nothing was evaluated",
			inv["executionSuccessful"])
	}
	if got := inv["toolExecutionNotifications"].([]any)[0].(map[string]any)["level"]; got != "error" {
		t.Errorf("summary notification level = %v, want error", got)
	}
	if n := len(resultsOf(t, run)); n != 2 {
		t.Errorf("results = %d, want 2 — an empty array is what a clean scan looks like", n)
	}
}

// TestSARIF_FixStateReachesTheDocument. Neither grype nor trivy puts this in
// SARIF: grype prints an empty "Fix Version:" for every unfixed finding and
// says nothing about whether one is coming. Carrying D52 through to the one
// format a reviewer actually reads is most of why this renderer exists.
func TestSARIF_FixStateReachesTheDocument(t *testing.T) {
	for _, tt := range []struct {
		name      string
		state     advisory.FixState
		fixed     string
		wantProp  string
		wantInMsg string
	}{
		{"wont-fix", advisory.FixStateWontFix, "", "wont-fix", "will not be fixed"},
		{"not-fixed", advisory.FixStateNotFixed, "", "not-fixed", "no fix published yet"},
		{"unknown", advisory.FixStateUnknown, "", "unknown", "No source records a version"},
		{"fixed", advisory.FixStateFixed, "2.0", "fixed", "Fixed in 2.0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res := matcher.Result{Findings: []matcher.Finding{
				findingFixture("CVE-2026-9", "curl", severity.High, 7.0, tt.fixed, tt.state),
			}}
			run := run0(t, sarifOf(t, res, cyclonedx.Stats{Components: 1, Cataloged: 1}))
			rule := rulesOf(t, run)[0]
			if got := rule["properties"].(map[string]any)["fixState"]; got != tt.wantProp {
				t.Errorf("properties.fixState = %v, want %q", got, tt.wantProp)
			}
			msg := resultsOf(t, run)[0]["message"].(map[string]any)["text"].(string)
			if !strings.Contains(msg, tt.wantInMsg) {
				t.Errorf("message = %q, want it to contain %q", msg, tt.wantInMsg)
			}
			// The help text must not leave the blank grype leaves.
			help := rule["help"].(map[string]any)["text"].(string)
			if strings.Contains(help, "Fix: \n") {
				t.Errorf("help leaves an empty Fix line:\n%s", help)
			}
		})
	}
}

// TestSARIF_FingerprintIsStableAcrossAnUpgrade. A fingerprint keyed on the
// version would close every alert and open an identical one the moment a
// package moved, on a vulnerability that is still unfixed.
func TestSARIF_FingerprintIsStableAcrossAnUpgrade(t *testing.T) {
	fp := func(v string) string {
		f := findingFixture("CVE-2026-4", "libc6", severity.High, 7.5, "", advisory.FixStateNotFixed)
		f.Package.Version = v
		f.Package.Locations = []pkgmeta.Location{{Path: "some/other/path"}}
		run := run0(t, sarifOf(t, matcher.Result{Findings: []matcher.Finding{f}},
			cyclonedx.Stats{Components: 1, Cataloged: 1}))
		m := resultsOf(t, run)[0]["partialFingerprints"].(map[string]any)
		return m[fingerprintKey].(string)
	}
	if a, b := fp("1.0.0"), fp("1.0.1"); a != b {
		t.Errorf("fingerprint changed with the version (%s -> %s); the alert would be "+
			"closed and reopened on an unfixed vulnerability", a, b)
	}
	// And it does distinguish different vulnerabilities on the same package.
	f1 := findingFixture("CVE-2026-4", "libc6", severity.High, 7.5, "", advisory.FixStateNotFixed)
	f2 := findingFixture("CVE-2026-5", "libc6", severity.High, 7.5, "", advisory.FixStateNotFixed)
	run := run0(t, sarifOf(t, matcher.Result{Findings: []matcher.Finding{f1, f2}},
		cyclonedx.Stats{Components: 1, Cataloged: 1}))
	rs := resultsOf(t, run)
	a := rs[0]["partialFingerprints"].(map[string]any)[fingerprintKey]
	b := rs[1]["partialFingerprints"].(map[string]any)[fingerprintKey]
	if a == b {
		t.Errorf("two different CVEs share a fingerprint (%v); one alert would hide the other", a)
	}
}

// TestSARIF_SourcePackageMatchIsNamed. D8: the advisory names a package the
// image does not contain, and a reviewer who looks it up finds no mention of
// what is installed. In a web UI detached from the command, this sentence is
// the only place that can say so.
func TestSARIF_SourcePackageMatchIsNamed(t *testing.T) {
	f := findingFixture("CVE-2026-6", "libssl3", severity.High, 7.5, "", advisory.FixStateNotFixed)
	f.MatchedName = "openssl"
	run := run0(t, sarifOf(t, matcher.Result{Findings: []matcher.Finding{f}},
		cyclonedx.Stats{Components: 1, Cataloged: 1}))
	msg := resultsOf(t, run)[0]["message"].(map[string]any)["text"].(string)
	if !strings.Contains(msg, "openssl") || !strings.Contains(msg, "libssl3") {
		t.Errorf("message = %q, want both the installed and the advisory's package", msg)
	}
	if !strings.Contains(msg, "example.com/img:1") {
		t.Errorf("message = %q, want it to name the scanned target", msg)
	}
}
