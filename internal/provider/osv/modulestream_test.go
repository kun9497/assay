package osv

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// TestConvert_AttachesModuleStreamFromSummary is D82's caller-first test: it
// drives the real conversion path (Convert, the exported entry point
// fetchOne calls), not the token-extraction helper directly. A module-tagged
// affected entry (its fixed EVR carries "module+el") must come out carrying
// the ModuleStream read from the record's own summary; an ordinary entry in
// the SAME record must come out with none. Deleting the attachModuleStreams
// call in convert (record.go) turns this red -- verified below the test.
func TestConvert_AttachesModuleStreamFromSummary(t *testing.T) {
	const rec = `{
	  "id": "RLSA-2020-4641",
	  "summary": "Moderate: python38:3.8 security update",
	  "affected": [
	    {"package": {"name": "babel", "ecosystem": "Rocky Linux:8"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "0:2.7.0-10.module+el8.4.0+570+c2eaf144"}]}]},
	    {"package": {"name": "rocky-release", "ecosystem": "Rocky Linux:8"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "8.4-1"}]}]}
	  ]
	}`
	got, ok, err := Convert([]byte(rec), "Rocky Linux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Affected) != 2 {
		t.Fatalf("Affected = %d entries, want 2", len(got.Affected))
	}
	if got.Affected[0].ModuleStream != "python38:3.8" {
		t.Errorf("module-tagged entry ModuleStream = %q, want %q",
			got.Affected[0].ModuleStream, "python38:3.8")
	}
	if got.Affected[1].ModuleStream != "" {
		t.Errorf("plain entry ModuleStream = %q, want empty -- a non-module entry "+
			"must never gain a stream just because the record's summary looks like a "+
			"module title", got.Affected[1].ModuleStream)
	}
}

// TestConvert_AttachesModuleStreamFromSummary_AlmaSpelling is the same shape
// through the same caller, for AlmaLinux's "module_el" spelling -- the other
// half of moduleTaggedFixedEVR's duplicated check, and the archive that
// carries the CVE in `related` rather than `upstream`/`aliases` (D72),
// unrelated to this feature but part of what a real ALSA record looks like.
func TestConvert_AttachesModuleStreamFromSummary_AlmaSpelling(t *testing.T) {
	const rec = `{
	  "id": "ALSA-2026-9001",
	  "related": ["CVE-2026-90001"],
	  "summary": "Important: nodejs:20 security update",
	  "affected": [
	    {"package": {"name": "nodejs", "ecosystem": "AlmaLinux:9"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "1:20.15.1-1.module_el9.4.0+123+abcdef12"}]}]}
	  ]
	}`
	got, ok, err := Convert([]byte(rec), "AlmaLinux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("Affected = %d entries, want 1", len(got.Affected))
	}
	if got.Affected[0].ModuleStream != "nodejs:20" {
		t.Errorf("ModuleStream = %q, want %q", got.Affected[0].ModuleStream, "nodejs:20")
	}
}

// TestConvert_ModuleStream_ZeroTokensStaysStreamless drives convert directly
// (unexported, same package) with a *stats so the ZeroToken counter can be
// asserted -- Convert itself (the public, stats-less wrapper) cannot show
// it. A summary with no colon left after the severity prefix is stripped
// ("go-toolset security update", the exact shape measured on 8 live Rocky
// records) must leave the module-tagged entry stream-less and count the
// record once.
func TestConvert_ModuleStream_ZeroTokensStaysStreamless(t *testing.T) {
	const rec = `{
	  "id": "RLSA-2026-0100",
	  "summary": "Moderate: go-toolset security update",
	  "affected": [
	    {"package": {"name": "golang", "ecosystem": "Rocky Linux:9"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "0:1.20.10-1.module+el9.3.0+111+aaaaaaaa"}]}]}
	  ]
	}`
	var st stats
	got, ok, err := convert([]byte(rec), "Rocky Linux", &st, nil)
	if err != nil || !ok {
		t.Fatalf("convert: ok=%v err=%v", ok, err)
	}
	if got.Affected[0].ModuleStream != "" {
		t.Errorf("ModuleStream = %q, want empty -- the summary has no token to attach",
			got.Affected[0].ModuleStream)
	}
	if st.ModuleRecordsZeroToken != 1 {
		t.Errorf("ModuleRecordsZeroToken = %d, want 1", st.ModuleRecordsZeroToken)
	}
	if st.ModuleEntriesStreamed != 0 {
		t.Errorf("ModuleEntriesStreamed = %d, want 0", st.ModuleEntriesStreamed)
	}
}

// TestConvert_ModuleStream_TwoStreamsOfOneModuleStaysStreamless is the idm
// shape: one summary naming two streams of the SAME module (idm:DL1,
// idm:client) -- three real advisories carry exactly this and cannot be
// split, per-entry attribution being impossible from OSV's data at all.
func TestConvert_ModuleStream_TwoStreamsOfOneModuleStaysStreamless(t *testing.T) {
	const rec = `{
	  "id": "RLSA-2026-0101",
	  "summary": "Critical: idm:DL1 and idm:client security update",
	  "affected": [
	    {"package": {"name": "bind-dyndb-ldap", "ecosystem": "Rocky Linux:8"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "0:11.6-2.module+el8.4.0+222+bbbbbbbb"}]}]}
	  ]
	}`
	var st stats
	got, ok, err := convert([]byte(rec), "Rocky Linux", &st, nil)
	if err != nil || !ok {
		t.Fatalf("convert: ok=%v err=%v", ok, err)
	}
	if got.Affected[0].ModuleStream != "" {
		t.Errorf("ModuleStream = %q, want empty -- two streams of one module cannot "+
			"be split, so guessing either is wrong", got.Affected[0].ModuleStream)
	}
	if st.ModuleRecordsMultiToken != 1 {
		t.Errorf("ModuleRecordsMultiToken = %d, want 1", st.ModuleRecordsMultiToken)
	}
}

// TestConvert_ModuleStream_TwoDifferentModulesStaysStreamless is the other
// two-token shape: a summary naming two genuinely DIFFERENT modules
// ("python39:3.9 and python39-devel:3.9"). OSV's affected entry carries a
// bare component name with no way to say which module it belongs to, so this
// must be just as conservative as the idm case above even though the two
// tokens here are not the same module.
func TestConvert_ModuleStream_TwoDifferentModulesStaysStreamless(t *testing.T) {
	const rec = `{
	  "id": "RLSA-2026-0102",
	  "summary": "Moderate: python39:3.9 and python39-devel:3.9 security update",
	  "affected": [
	    {"package": {"name": "python39", "ecosystem": "Rocky Linux:9"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "0:3.9.18-1.module+el9.4.0+333+cccccccc"}]}]}
	  ]
	}`
	var st stats
	got, ok, err := convert([]byte(rec), "Rocky Linux", &st, nil)
	if err != nil || !ok {
		t.Fatalf("convert: ok=%v err=%v", ok, err)
	}
	if got.Affected[0].ModuleStream != "" {
		t.Errorf("ModuleStream = %q, want empty -- two different modules named in one "+
			"summary; OSV cannot say which component belongs to which", got.Affected[0].ModuleStream)
	}
	if st.ModuleRecordsMultiToken != 1 {
		t.Errorf("ModuleRecordsMultiToken = %d, want 1", st.ModuleRecordsMultiToken)
	}
}

// TestModuleStreamTokens_SeverityPrefixStripping pins the regex-level
// behaviour the design calls out by name: the severity prefix must be
// stripped BEFORE token extraction, not merely tolerated by it. Without the
// strip, "Important: idm:DL1 ..." reads its first token as "Important:idm"
// (consuming the colon the real token needs), and "Important: varnish ..."
// -- which has no OTHER colon at all -- fabricates a token
// ("Important:varnish") where none exists.
func TestModuleStreamTokens_SeverityPrefixStripping(t *testing.T) {
	got := moduleStreamTokens("Important: idm:DL1 security update")
	if len(got) != 1 || got[0] != "idm:DL1" {
		t.Errorf("moduleStreamTokens = %v, want [idm:DL1] -- the severity prefix must "+
			"not consume the real token's colon", got)
	}

	got = moduleStreamTokens("Important: varnish security update")
	if len(got) != 0 {
		t.Errorf("moduleStreamTokens = %v, want none -- the summary's ONLY colon pair "+
			"is the severity prefix itself, which must not be read as a token", got)
	}
}

// TestConvert_ModuleStream_NonRockyAlmaUntouched guards the ecosystem scope:
// a Red Hat entry with a module-tagged EVR sitting in the SAME record as a
// Rocky one must never gain a stream from this path -- D82 is Rocky/Alma
// only, Red Hat's own streams come from D80's structural CSAF read.
func TestConvert_ModuleStream_NonRockyAlmaUntouched(t *testing.T) {
	const rec = `{
	  "id": "RLSA-2026-0103",
	  "summary": "Moderate: python38:3.8 security update",
	  "affected": [
	    {"package": {"name": "python38", "ecosystem": "Rocky Linux:8"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "0:3.8.6-1.module+el8.3.0+444+dddddddd"}]}]},
	    {"package": {"name": "python38", "ecosystem": "Red Hat Enterprise Linux:8"},
	     "ranges": [{"type": "ECOSYSTEM", "events": [
	       {"introduced": "0"}, {"fixed": "0:3.8.6-1.module+el8.3.0+444+dddddddd"}]}]}
	  ]
	}`
	got, ok, err := Convert([]byte(rec), "Rocky Linux")
	if err != nil || !ok {
		t.Fatalf("Convert: ok=%v err=%v", ok, err)
	}
	if got.Affected[0].ModuleStream != "python38:3.8" {
		t.Errorf("Rocky entry ModuleStream = %q, want python38:3.8", got.Affected[0].ModuleStream)
	}
	if got.Affected[1].ModuleStream != "" {
		t.Errorf("foreign-ecosystem entry ModuleStream = %q, want empty -- D82 is "+
			"Rocky/AlmaLinux only", got.Affected[1].ModuleStream)
	}
}

// TestFetch_ModuleStreamStatsReachStderr is the top-of-the-stack caller-first
// check: it drives Fetch (what dbUpdateProviders actually calls in
// cmd/assay/main.go), over a served archive mixing all three cases -- one
// clean attachment, one zero-token record, one multi-token record -- and
// asserts both that the emitted advisory carries the stream and that the
// printed progress line (WithProgress, the opt-in every other provider's own
// Options.Progress mirrors) reports all three counts. Without this, a
// passing convert()-level test would prove the counting logic works while
// leaving nothing to prove Fetch (or WithProgress) actually surfaces it.
func TestFetch_ModuleStreamStatsReachStderr(t *testing.T) {
	body := zipWith(t, map[string]string{
		"RLSA-2026-0200.json": `{"id":"RLSA-2026-0200","summary":"Moderate: python38:3.8 security update",
			"affected":[{"package":{"name":"babel","ecosystem":"Rocky Linux:8"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},
					{"fixed":"0:2.7.0-10.module+el8.4.0+570+c2eaf144"}]}]}]}`,
		"RLSA-2026-0201.json": `{"id":"RLSA-2026-0201","summary":"Moderate: go-toolset security update",
			"affected":[{"package":{"name":"golang","ecosystem":"Rocky Linux:9"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},
					{"fixed":"0:1.20.10-1.module+el9.3.0+111+aaaaaaaa"}]}]}]}`,
		"RLSA-2026-0202.json": `{"id":"RLSA-2026-0202","summary":"Critical: idm:DL1 and idm:client security update",
			"affected":[{"package":{"name":"bind-dyndb-ldap","ecosystem":"Rocky Linux:8"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},
					{"fixed":"0:11.6-2.module+el8.4.0+222+bbbbbbbb"}]}]}]}`,
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Rocky Linux/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	var progress bytes.Buffer
	p := New([]string{"Rocky Linux"}, srv.URL).WithProgress(&progress)
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("Fetch emitted %d advisories, want 3", len(got))
	}

	byID := map[string]advisory.Advisory{}
	for _, a := range got {
		byID[a.ID] = a
	}
	if s := byID["RLSA-2026-0200"].Affected[0].ModuleStream; s != "python38:3.8" {
		t.Errorf("RLSA-2026-0200 ModuleStream = %q, want python38:3.8", s)
	}
	if s := byID["RLSA-2026-0201"].Affected[0].ModuleStream; s != "" {
		t.Errorf("RLSA-2026-0201 ModuleStream = %q, want empty (zero tokens)", s)
	}
	if s := byID["RLSA-2026-0202"].Affected[0].ModuleStream; s != "" {
		t.Errorf("RLSA-2026-0202 ModuleStream = %q, want empty (two tokens)", s)
	}

	line := progress.String()
	if !strings.Contains(line, "osv: ") {
		t.Fatalf("progress = %q, want an osv: line -- WithProgress must reach Fetch's print", line)
	}
	if !strings.Contains(line, "1 module-tagged Rocky/AlmaLinux entr") {
		t.Errorf("progress = %q, want it to report 1 entry streamed", line)
	}
	if !strings.Contains(line, "1 record(s) left stream-less for no token") {
		t.Errorf("progress = %q, want it to report 1 zero-token record", line)
	}
	if !strings.Contains(line, "1 record(s) left stream-less for 2+ tokens") {
		t.Errorf("progress = %q, want it to report 1 multi-token record", line)
	}
}
