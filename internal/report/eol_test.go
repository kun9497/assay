package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
)

// debianBookwormEOL is the D87 shape the design exists for: a release that
// is EOL under its own regular support yet still maintained under a
// differently-labelled extended phase (Debian's bookworm, security support
// ended, LTS still running).
var debianBookwormEOL = EOLStatus{
	Known: true, DistroID: "debian", Release: "12",
	EOL: true, EOLFrom: "2026-07-11", EOLLabel: "Debian Security Support",
	StillMaintained: true, EOESFrom: "2028-06-30", EOESLabel: "Debian LTS",
}

// TestTable_PrintsEOLLineWhenEOL is the caller-first test: Table must
// actually consult the eol argument and print something, not merely accept
// it and never look — deleting the Line() call inside Table (CLAUDE.md's
// "the helper is covered; nothing calls it" hazard) must turn this red.
func TestTable_PrintsEOLLineWhenEOL(t *testing.T) {
	var buf bytes.Buffer
	if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{}, debianBookwormEOL, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "EOL: debian 12 reached end of Debian Security Support on 2026-07-11") {
		t.Errorf("table did not print the EOL line:\n%s", out)
	}
	if !strings.Contains(out, "still under Debian LTS until 2028-06-30") {
		t.Errorf("table did not print the still-maintained fact:\n%s", out)
	}
}

// TestTable_NoEOLLineWhenNotEOL: the table stays silent when the release is
// current, or when there is nothing to say at all — D87's own "one line
// only when EOL" rule, and the counterpart to the test above (the two
// together are what makes the EOLStatus{} default used by every other
// table_test.go call site a proven no-op rather than an assumed one).
func TestTable_NoEOLLineWhenNotEOL(t *testing.T) {
	for name, st := range map[string]EOLStatus{
		"unknown":       {},
		"known-not-eol": {Known: true, DistroID: "rockylinux", Release: "9", EOL: false},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := Table(&buf, matcher.Result{}, cyclonedx.Stats{}, st, false); err != nil {
				t.Fatal(err)
			}
			if out := buf.String(); strings.Contains(out, "EOL:") {
				t.Errorf("table printed an EOL line when it must not have:\n%s", out)
			}
		})
	}
}

// TestJSON_AttachesEOLRecordWhenKnown is JSON's own caller-first test:
// Document.EOL must actually be populated from what Table's own fixture
// above proves is being consulted, not merely accepted and dropped.
func TestJSON_AttachesEOLRecordWhenKnown(t *testing.T) {
	var buf bytes.Buffer
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}, debianBookwormEOL); err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.EOL == nil {
		t.Fatal("Document.EOL = nil, want a populated record")
	}
	want := EOLRecord{
		DistroID: "debian", Release: "12", EOL: true, EOLFrom: "2026-07-11",
		EOLLabel: "Debian Security Support", StillMaintained: true,
		EOESFrom: "2028-06-30", EOESLabel: "Debian LTS",
	}
	if *doc.EOL != want {
		t.Errorf("Document.EOL = %+v, want %+v", *doc.EOL, want)
	}
}

// TestJSON_OmitsEOLKeyWhenUnknown: the "eol" key must be genuinely absent
// (not present-and-null) when there is no answer, so an older consumer's
// `.eol.distroId` does not have to special-case a null parent — the exact
// thing Document.EOL's own omitempty tag exists for.
func TestJSON_OmitsEOLKeyWhenUnknown(t *testing.T) {
	var buf bytes.Buffer
	if _, err := JSON(&buf, matcher.Result{}, cyclonedx.Stats{}, EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["eol"]; present {
		t.Errorf(`document carries an "eol" key when there is no answer: %v`, raw["eol"])
	}
}

// TestSARIF_AttachesEOLProperties is SARIF's own caller-first test, on the
// same reasoning as JSON's above: the invocation's properties bag must
// actually carry what EOLStatus.Properties() computes.
func TestSARIF_AttachesEOLProperties(t *testing.T) {
	var buf bytes.Buffer
	if _, err := SARIF(&buf, matcher.Result{}, cyclonedx.Stats{}, "img:1", "v0", debianBookwormEOL); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	invocations := run["invocations"].([]any)
	inv := invocations[0].(map[string]any)
	props, ok := inv["properties"].(map[string]any)
	if !ok {
		t.Fatalf("invocation has no properties bag: %+v", inv)
	}
	eol, ok := props["eol"].(map[string]any)
	if !ok {
		t.Fatalf("invocation properties has no \"eol\" entry: %+v", props)
	}
	if eol["distroId"] != "debian" || eol["release"] != "12" || eol["eol"] != true {
		t.Errorf("sarif eol properties = %+v, want debian/12/eol=true", eol)
	}
	if eol["eolFrom"] != "2026-07-11" || eol["eolLabel"] != "Debian Security Support" {
		t.Errorf("sarif eol properties missing eolFrom/eolLabel: %+v", eol)
	}
	if eol["stillMaintained"] != true || eol["eoesFrom"] != "2028-06-30" || eol["eoesLabel"] != "Debian LTS" {
		t.Errorf("sarif eol properties missing the still-maintained fact: %+v", eol)
	}
}

// TestSARIF_OmitsPropertiesWhenEOLUnknown mirrors
// TestJSON_OmitsEOLKeyWhenUnknown: an invocation with nothing to say about
// EOL must not carry an empty or null properties key either.
func TestSARIF_OmitsPropertiesWhenEOLUnknown(t *testing.T) {
	var buf bytes.Buffer
	if _, err := SARIF(&buf, matcher.Result{}, cyclonedx.Stats{}, "img:1", "v0", EOLStatus{}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	runs := doc["runs"].([]any)
	run := runs[0].(map[string]any)
	invocations := run["invocations"].([]any)
	inv := invocations[0].(map[string]any)
	if _, present := inv["properties"]; present {
		t.Errorf("invocation carries a properties key with no EOL answer: %+v", inv["properties"])
	}
}

// TestEOLStatus_Line covers Line() directly for the branches the two
// caller-first table tests above cannot reach through one fixture each:
// no label at all (falls back to generic wording), maintained with no
// EOES label/date (falls back to generic wording there too), and EOL true
// but not maintained (no second clause at all).
func TestEOLStatus_Line(t *testing.T) {
	for name, tc := range map[string]struct {
		st       EOLStatus
		wantOK   bool
		wantLine string
	}{
		"unknown": {st: EOLStatus{}, wantOK: false},
		"known not eol": {
			st:     EOLStatus{Known: true, DistroID: "rockylinux", Release: "9", EOL: false},
			wantOK: false,
		},
		"eol, not maintained": {
			st: EOLStatus{
				Known: true, DistroID: "amzn", Release: "2", EOL: true,
				EOLFrom: "2026-06-30", EOLLabel: "Security Support",
			},
			wantOK:   true,
			wantLine: "EOL: amzn 2 reached end of Security Support on 2026-06-30",
		},
		"eol, maintained with no eoes label or date": {
			st: EOLStatus{
				Known: true, DistroID: "x", Release: "1", EOL: true,
				EOLFrom: "2020-01-01", EOLLabel: "Support", StillMaintained: true,
			},
			wantOK:   true,
			wantLine: "EOL: x 1 reached end of Support on 2020-01-01; still under extended support",
		},
		"eol, no label at all": {
			st: EOLStatus{
				Known: true, DistroID: "x", Release: "1", EOL: true, EOLFrom: "2020-01-01",
			},
			wantOK:   true,
			wantLine: "EOL: x 1 reached end of support on 2020-01-01",
		},
	} {
		t.Run(name, func(t *testing.T) {
			line, ok := tc.st.Line()
			if ok != tc.wantOK {
				t.Fatalf("Line() ok = %v, want %v (line %q)", ok, tc.wantOK, line)
			}
			if ok && line != tc.wantLine {
				t.Errorf("Line() = %q, want %q", line, tc.wantLine)
			}
		})
	}
}

// TestEOLStatus_Record covers Record() directly: nil when unknown, and a
// not-EOL row still produces a non-nil record (unlike Line(), which stays
// silent — Record()'s own doc comment explains why a JSON consumer wants
// the not-yet-EOL answer too).
func TestEOLStatus_Record(t *testing.T) {
	if r := (EOLStatus{}).Record(); r != nil {
		t.Errorf("Record() on an unknown status = %+v, want nil", r)
	}
	st := EOLStatus{Known: true, DistroID: "rockylinux", Release: "9", EOL: false}
	r := st.Record()
	if r == nil {
		t.Fatal("Record() on a known, not-EOL status = nil, want a populated record")
	}
	if r.EOL {
		t.Errorf("Record().EOL = true, want false")
	}
}

// TestEOLStatus_Properties covers Properties() directly: nil when unknown,
// and the EOL-false shape (the eolFrom/eolLabel/stillMaintained/eoes* keys
// are omitted entirely, not present as zero values, since a current release
// has nothing to report about a phase it has not reached).
func TestEOLStatus_Properties(t *testing.T) {
	if p := (EOLStatus{}).Properties(); p != nil {
		t.Errorf("Properties() on an unknown status = %+v, want nil", p)
	}
	st := EOLStatus{Known: true, DistroID: "rockylinux", Release: "9", EOL: false}
	p := st.Properties()
	eol, ok := p["eol"].(map[string]any)
	if !ok {
		t.Fatalf("Properties() = %+v, want an \"eol\" entry", p)
	}
	for _, key := range []string{"eolFrom", "eolLabel", "stillMaintained", "eoesFrom", "eoesLabel"} {
		if _, present := eol[key]; present {
			t.Errorf("Properties()[%q] present on a not-EOL status, want omitted", key)
		}
	}
}
