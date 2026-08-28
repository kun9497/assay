package azurelinux

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
)

// serveDoc starts an httptest server that always serves body -- the same
// no-fixture-file shape oval_test.go's ovalBuilder produces, since (unlike
// oracle's bzip2 archive) these files need no compression step at all.
func serveDoc(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
}

// TestFetch_DownloadsBothFilesAndEmits drives the whole pipeline end to end
// for BOTH files: HTTP GET -> spool -> OVAL parse -> emit, once per release.
// Nothing in oval_test.go exercises the HTTP/spool half or the two-file
// DataAsOf aggregation; this is the only test that does. It also carries
// deliverable D's end-to-end proof (a Not Applicable definition dropped
// through the full Fetch path, not just parseOVAL directly) and D52's
// FixState stamping, so the caller (Fetch) is proven, not just the helper.
func TestFetch_DownloadsBothFilesAndEmits(t *testing.T) {
	azl3Builder := &ovalBuilder{}
	azl3Doc := azl3Builder.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("97575", "python-webob fix", "CVE-2026-54770", "", "Medium",
			azl3Builder.fixedCriterion("python-webob", "0:1.8.11-1.azl3")))
	azl3Srv := serveDoc(t, azl3Doc)
	defer azl3Srv.Close()

	m2Builder := &ovalBuilder{}
	notApplicable := definitionXML("13832", "syslinux no longer applicable", "CVE-2022-3857", "Not Applicable", "Medium",
		m2Builder.lastAffectedCriterion("syslinux", "0:6.04-10.cm2"))
	noPatch := definitionXML("13293", "pesign no patch", "CVE-2022-3560", "false", "Medium",
		m2Builder.lastAffectedCriterion("pesign", "0:0.112-32.cm2"))
	// Deliberately the OLDER of the two generator timestamps, so DataAsOf
	// must report THIS one (D12: the oldest upstream timestamp wins).
	m2Doc := m2Builder.doc("2026-05-06T13:07:20.548723963Z", notApplicable, noPatch)
	m2Srv := serveDoc(t, m2Doc)
	defer m2Srv.Close()

	p := New(Options{AZL3URL: azl3Srv.URL, Mariner2URL: m2Srv.URL})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Exactly two: python-webob (azl3) and pesign (mariner2). The syslinux
	// "Not Applicable" record must never reach emit at all.
	if len(got) != 2 {
		t.Fatalf("Fetch emitted %d advisories, want 2: %+v", len(got), got)
	}
	var webob, pesign advisory.Advisory
	for _, a := range got {
		switch a.ID {
		case "AZURELINUX-3-97575":
			webob = a
		case "AZURELINUX-2-13293":
			pesign = a
		default:
			t.Errorf("unexpected advisory id %q -- the syslinux Not Applicable record must be dropped (D16)", a.ID)
		}
	}
	if webob.ID == "" || pesign.ID == "" {
		t.Fatalf("did not find both expected advisories: %+v", got)
	}
	if webob.Affected[0].Ecosystem != "Azure Linux:3" {
		t.Errorf("webob Ecosystem = %q, want Azure Linux:3", webob.Affected[0].Ecosystem)
	}
	if pesign.Affected[0].Ecosystem != "Azure Linux:2" {
		t.Errorf("pesign Ecosystem = %q, want Azure Linux:2", pesign.Affected[0].Ecosystem)
	}
	if pesign.Affected[0].Ranges[0].FixState != advisory.FixStateNotFixed {
		t.Errorf("pesign FixState = %q, want %q (D52: patchable=false)", pesign.Affected[0].Ranges[0].FixState, advisory.FixStateNotFixed)
	}

	if prov.Records != 2 {
		t.Errorf("Records = %d, want 2", prov.Records)
	}
	wantEcos := map[string]bool{"Azure Linux:3": true, "Azure Linux:2": true}
	if len(prov.Ecosystems) != 2 {
		t.Fatalf("Ecosystems = %v, want exactly [Azure Linux:2 Azure Linux:3]", prov.Ecosystems)
	}
	for _, e := range prov.Ecosystems {
		if !wantEcos[e] {
			t.Errorf("Ecosystems contains unexpected %q", e)
		}
	}
	wantAsOf := time.Date(2026, 5, 6, 13, 7, 20, 548723963, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("DataAsOf = %v, want %v -- the OLDER of the two generator timestamps (D12)", prov.DataAsOf, wantAsOf)
	}
	if !strings.Contains(prov.Source, azl3Srv.URL) || !strings.Contains(prov.Source, m2Srv.URL) {
		t.Errorf("Source = %q, want it to name both fetched URLs", prov.Source)
	}
}

// TestFetch_PrintsSummary is the delete-goes-red proof that Fetch actually
// calls stats.String() through Options.Progress, the same discipline every
// other provider's own progress test holds (e.g. oracle.TestFetch_PrintsSummary).
func TestFetch_PrintsSummary(t *testing.T) {
	o := &ovalBuilder{}
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "foo fix", "CVE-2026-1", "", "Medium", o.fixedCriterion("foo", "0:1.0-1.azl3")))
	srv := serveDoc(t, doc)
	defer srv.Close()

	var progress strings.Builder
	p := New(Options{AZL3URL: srv.URL, Mariner2URL: srv.URL, Progress: &progress})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	out := progress.String()
	if !strings.Contains(out, "definitions") || !strings.Contains(out, "advisories") {
		t.Errorf("progress output = %q, want it to report definitions/advisories counts", out)
	}
}

// zeroAdvisoriesDoc is a document with one real <definition> (so parseOVAL's
// own zero-DEFINITIONS guard does not fire) that resolves to zero advisories
// -- here, its only definition is Not Applicable. This is the shape
// oval_test.go's own tests cannot reach, because they drive parseOVAL
// directly: only Fetch's own D20 guard (azurelinux.go) can catch a real,
// well-formed file whose every definition was filtered out.
func zeroAdvisoriesDoc() string {
	o := &ovalBuilder{}
	return o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "gone", "CVE-2026-1", "Not Applicable", "Medium",
			o.lastAffectedCriterion("foo", "0:1.0-1.azl3")))
}

// TestFetch_EitherFileYieldingZeroAdvisoriesIsAnError proves the D20
// coverage guard fires independently for EACH file: a database that
// silently has no Azure Linux:N coverage for one release while the other
// looks fine is exactly as dangerous as losing both.
func TestFetch_EitherFileYieldingZeroAdvisoriesIsAnError(t *testing.T) {
	goodBuilder := &ovalBuilder{}
	goodDoc := goodBuilder.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "foo fix", "CVE-2026-1", "", "Medium", goodBuilder.fixedCriterion("foo", "0:1.0-1.azl3")))

	for _, tt := range []struct {
		name          string
		azl3Body      string
		mariner2Body  string
		wantErrSubstr string
	}{
		{"azl3 empty", zeroAdvisoriesDoc(), goodDoc, "Azure Linux:3"},
		{"mariner2 empty", goodDoc, zeroAdvisoriesDoc(), "Azure Linux:2"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			azl3Srv := serveDoc(t, tt.azl3Body)
			defer azl3Srv.Close()
			m2Srv := serveDoc(t, tt.mariner2Body)
			defer m2Srv.Close()

			p := New(Options{AZL3URL: azl3Srv.URL, Mariner2URL: m2Srv.URL})
			_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
			if err == nil {
				t.Fatal("Fetch succeeded with zero advisories from one file, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error %q does not name %q", err, tt.wantErrSubstr)
			}
		})
	}
}

// TestFetch_HTTPErrorPropagates needs no XML body at all: a 404 on either
// file must surface as an error before anything tries to spool or parse a
// body that was never the feed.
func TestFetch_HTTPErrorPropagates(t *testing.T) {
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer failSrv.Close()

	p := New(Options{AZL3URL: failSrv.URL, Mariner2URL: failSrv.URL})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one for a 404 response")
	}
}

// TestFetch_LeavesNoSpoolFileBehind proves the temp files spool() creates
// (one per release) are removed on the success path -- D64's whole point is
// closing the connection quickly, not leaking two downloaded copies of the
// feed on every build.
func TestFetch_LeavesNoSpoolFileBehind(t *testing.T) {
	before, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	o := &ovalBuilder{}
	doc := o.doc("2026-08-27T13:07:55.105138033Z",
		definitionXML("1", "foo fix", "CVE-2026-1", "", "Medium", o.fixedCriterion("foo", "0:1.0-1.azl3")))
	srv := serveDoc(t, doc)
	defer srv.Close()

	p := New(Options{AZL3URL: srv.URL, Mariner2URL: srv.URL})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	after, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	for _, e := range after {
		if strings.HasPrefix(e.Name(), "assay-azurelinux-") {
			found := false
			for _, b := range before {
				if b.Name() == e.Name() {
					found = true
				}
			}
			if !found {
				t.Errorf("spool file %s left behind after Fetch returned", e.Name())
			}
		}
	}
}
