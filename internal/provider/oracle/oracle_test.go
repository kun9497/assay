package oracle

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

// mini-elsa.xml.bz2 is a hand-built, real-shaped OVAL 5.11 archive: two
// <definition>s (ELSA-2026-9001 on Oracle Linux 9 with a CVSS v3 vector and
// a CVE, ELSA-2013-9002 on Oracle Linux 6 with no CVSS vector at all --
// the v2-only shape) each joined against their own rpminfo tests/objects/
// states pools, plus the archive's own <generator><oval:timestamp>. 870
// bytes compressed.
//
// It is REGENERABLE, not hand-maintained as bytes: the plain XML this file
// compresses is the string built by TestParseOVAL_SinglePlatformPackageFix's
// own ovalBuilder shape (see that test), written out and compressed with
//
//	python -c "import bz2; open('mini-elsa.xml.bz2','wb').write(bz2.compress(open('mini-elsa.xml','rb').read(), 9))"
//
// -- compress/bzip2 in the Go standard library has no Writer, only a Reader
// (the oracle package doc comment explains why that shapes Fetch), so this
// is the one place in the whole slice that needs a real .bz2 byte blob
// rather than a string built at test time. Every criteria-walk edge case
// lives in oval_test.go instead, driven with plain (uncompressed) XML
// strings against parseOVAL directly.
const fixturePath = "testdata/mini-elsa.xml.bz2"

func serveFixture(t *testing.T, path string) *httptest.Server {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-bzip2")
		w.Write(b)
	}))
}

// TestFetch_DownloadsSpoolsDecompressesAndEmits drives the whole pipeline
// end to end: HTTP GET -> spool to a temp file -> bzip2 decompress -> OVAL
// parse -> normalize -> emit. Nothing about oval.go's own tests exercises
// any of the HTTP/spool/bzip2 half; this is the only test that does.
func TestFetch_DownloadsSpoolsDecompressesAndEmits(t *testing.T) {
	srv := serveFixture(t, fixturePath)
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d advisories, want 2: %+v", len(got), got)
	}

	var openssh, openssl advisory.Advisory
	for _, a := range got {
		switch a.ID {
		case "ELSA-2026-9001":
			openssh = a
		case "ELSA-2013-9002":
			openssl = a
		default:
			t.Errorf("unexpected advisory id %q", a.ID)
		}
	}
	if openssh.ID == "" || openssl.ID == "" {
		t.Fatalf("did not find both expected advisories: %+v", got)
	}

	if openssh.Database != "ELSA" || openssh.Source != SourceName {
		t.Errorf("openssh advisory Database/Source = %q/%q, want ELSA/%q", openssh.Database, openssh.Source, SourceName)
	}
	if len(openssh.Affected) != 1 || openssh.Affected[0].Ecosystem != "Oracle Linux:9" || openssh.Affected[0].Name != "openssh" {
		t.Fatalf("openssh Affected = %+v, want one Oracle Linux:9/openssh entry", openssh.Affected)
	}
	if len(openssh.Severity) != 2 {
		t.Errorf("openssh Severity = %+v, want a CVSS_V3 entry and a VENDOR_WORD entry", openssh.Severity)
	}

	if len(openssl.Affected) != 1 || openssl.Affected[0].Ecosystem != "Oracle Linux:6" || openssl.Affected[0].Name != "openssl" {
		t.Fatalf("openssl Affected = %+v, want one Oracle Linux:6/openssl entry", openssl.Affected)
	}
	// The v2-only shape survives the FULL pipeline with no synthetic vector.
	if len(openssl.Severity) != 1 || openssl.Severity[0].Type != "VENDOR_WORD" {
		t.Errorf("openssl Severity = %+v, want exactly one VENDOR_WORD entry (no CVSS_V3)", openssl.Severity)
	}

	wantAsOf := time.Date(2026, 8, 19, 10, 33, 28, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("DataAsOf = %v, want %v (the archive's own generator timestamp)", prov.DataAsOf, wantAsOf)
	}
	if prov.Records != 2 {
		t.Errorf("Records = %d, want 2", prov.Records)
	}
	if prov.Source != srv.URL {
		t.Errorf("Source = %q, want %q", prov.Source, srv.URL)
	}
	wantEcos := map[string]bool{"Oracle Linux:9": true, "Oracle Linux:6": true}
	if len(prov.Ecosystems) != 2 {
		t.Fatalf("Ecosystems = %v, want exactly [Oracle Linux:6 Oracle Linux:9]", prov.Ecosystems)
	}
	for _, e := range prov.Ecosystems {
		if !wantEcos[e] {
			t.Errorf("Ecosystems contains unexpected %q", e)
		}
	}
}

// TestFetch_PrintsSummary is the delete-goes-red proof that Fetch actually
// calls stats.String() through Options.Progress -- the same discipline
// amazon.TestFetch_PrintsExtrasDisclosure and redhat's own progress tests
// hold: a provider that discards part of its input and prints nothing about
// it is indistinguishable from one that is broken.
func TestFetch_PrintsSummary(t *testing.T) {
	srv := serveFixture(t, fixturePath)
	defer srv.Close()

	var progress strings.Builder
	p := New(Options{URL: srv.URL, Progress: &progress})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	out := progress.String()
	if !strings.Contains(out, "2 definitions") || !strings.Contains(out, "2 advisories") {
		t.Errorf("progress output = %q, want it to report definitions/advisories counts", out)
	}
}

// TestFetch_HTTPErrorPropagates needs no bz2 fixture at all: a 404 must
// surface as an error before anything tries to spool or decompress a body
// that was never the archive.
func TestFetch_HTTPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	p := New(Options{URL: srv.URL})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one for a 404 response")
	}
}

// TestFetch_LeavesNoSpoolFileBehind proves the temp file spool() creates is
// removed on both the success and the failure path -- D64's whole point is
// closing the connection quickly, not leaking a downloaded copy of the
// archive on every build.
func TestFetch_LeavesNoSpoolFileBehind(t *testing.T) {
	before, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	srv := serveFixture(t, fixturePath)
	defer srv.Close()
	p := New(Options{URL: srv.URL})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	after, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("read temp dir: %v", err)
	}
	for _, e := range after {
		if strings.HasPrefix(e.Name(), "assay-oracle-") {
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
