package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

func zipWith(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFetch(t *testing.T) {
	body := zipWith(t, map[string]string{
		"GHSA-keep.json": `{"id":"GHSA-keep","affected":[{"package":{"name":"x","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`,
		"GHSA-gone.json": `{"id":"GHSA-gone","withdrawn":"2024-01-01T00:00:00Z",
			"affected":[{"package":{"name":"y","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
		"MAL-2024-1.json": `{"id":"MAL-2024-1","affected":[{"package":{"name":"z","ecosystem":"Go"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`,
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/Go/all.zip" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Last-Modified", "Tue, 29 Jul 2026 00:00:00 GMT")
		w.Write(body)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "GHSA-keep" {
		t.Fatalf("Fetch emitted %d advisories (%v), want only GHSA-keep", len(got), got)
	}
	if prov.Records != 1 {
		t.Errorf("Provenance.Records = %d, want 1", prov.Records)
	}
	// DataAsOf must come from the upstream response, not from time.Now (D12).
	if prov.DataAsOf.Year() != 2026 || prov.DataAsOf.Month() != 7 || prov.DataAsOf.Day() != 29 {
		t.Errorf("Provenance.DataAsOf = %v, want 2026-07-29 from Last-Modified", prov.DataAsOf)
	}
	if prov.Source == "" {
		t.Error("Provenance.Source is empty; the URL actually fetched must be recorded")
	}
}

func TestFetch_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := New([]string{"Go"}, srv.URL)
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Error("Fetch over a failing server = nil error, want error")
	}
}
