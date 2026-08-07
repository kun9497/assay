package redhat

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/kun9497/assay/internal/advisory"
)

// nl is a newline, assembled rather than typed. CLAUDE.md records the hazard
// and it fired again while this package was being written.
var nl = string(rune(10))

// archiveOf builds a zstd-compressed tar of CSAF documents, the shape Red Hat
// publishes. Built rather than committed: the real archive is 262 MB.
func archiveOf(t *testing.T, docs map[string]string) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range docs {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	// A directory entry, which every real archive has and which must be
	// skipped rather than decoded as an empty document.
	if err := tw.WriteHeader(&tar.Header{Name: "2024/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// docJSON renders one CSAF document with the given products.
func docJSON(t *testing.T, cve string, cpes map[string]string, fixed, affected []string) string {
	t.Helper()
	var kids []map[string]any
	for id, c := range cpes {
		kids = append(kids, map[string]any{
			"category": "product_name", "name": id,
			"product": map[string]any{
				"product_id":                    id,
				"product_identification_helper": map[string]any{"cpe": c},
			},
		})
	}
	b, err := json.Marshal(map[string]any{
		"document": map[string]any{
			"title":    "test",
			"tracking": map[string]any{"id": cve},
		},
		"product_tree": map[string]any{"branches": []any{map[string]any{
			"category": "vendor", "name": "Red Hat", "branches": kids,
		}}},
		"vulnerabilities": []any{map[string]any{
			"cve": cve,
			"product_status": map[string]any{
				"fixed": fixed, "known_affected": affected,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// serve stands up a feed: a pointer file and the archive it names.
func serve(t *testing.T, pointer string, archive []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+pointerFile, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, pointer+nl)
	})
	// EVERY other path serves the archive, deliberately. An earlier version
	// 404'd anything that did not end in .tar.zst, which made
	// TestFetch_RefusesABadPointerFile pass from the 404 rather than from the
	// validation it names: deleting the pointer-file checks entirely left it
	// green. A server that answers anything means only a real refusal can
	// produce an error.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if archive == nil {
			http.NotFound(w, r)
			return
		}
		w.Write(archive)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func fetchAll(t *testing.T, s *httptest.Server) ([]advisory.Advisory, string, error) {
	t.Helper()
	var progress bytes.Buffer
	p := New(Options{BaseURL: s.URL, Progress: &progress})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		return nil, progress.String(), err
	}
	t.Logf("provenance: source=%s asOf=%s records=%d ecosystems=%v",
		prov.Source, prov.DataAsOf.Format("2006-01-02"), prov.Records, prov.Ecosystems)
	return got, progress.String(), nil
}

func TestFetch(t *testing.T) {
	s := serve(t, "csaf_vex_2026-08-05.tar.zst", archiveOf(t, map[string]string{
		"2024/cve-2024-6387.json": docJSON(t, "CVE-2024-6387",
			map[string]string{"BaseOS-9": "cpe:/o:redhat:enterprise_linux:9::baseos"},
			[]string{"BaseOS-9:openssh-0:8.7p1-38.el9_4.1.x86_64"}, nil),
		"2002/cve-2002-2439.json": docJSON(t, "CVE-2002-2439",
			map[string]string{"RHEL5": "cpe:/o:redhat:enterprise_linux:5"},
			nil, []string{"RHEL5:gcc"}),
		// A document about a product this provider does not ingest: read,
		// converted to nothing, and not emitted.
		"2024/cve-2024-9999.json": docJSON(t, "CVE-2024-9999",
			map[string]string{"CEPH": "cpe:/a:redhat:ceph_storage:5"},
			[]string{"CEPH:ceph-0:1-1.x86_64"}, nil),
		// Not a document at all. Real archives carry an index and checksums.
		"index.txt": "2024/cve-2024-6387.json" + nl,
	}))

	got, progress, err := fetchAll(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d advisories, want 2: %+v", len(got), got)
	}
	byID := map[string]advisory.Advisory{}
	for _, a := range got {
		byID[a.ID] = a
	}
	fix := byID["CVE-2024-6387"]
	if len(fix.Affected) != 1 || fix.Affected[0].Ecosystem != "Red Hat:9" || fix.Affected[0].Name != "openssh" {
		t.Errorf("CVE-2024-6387 affected = %+v", fix.Affected)
	}
	unfixed := byID["CVE-2002-2439"]
	if len(unfixed.Affected) != 1 {
		t.Fatalf("CVE-2002-2439 affected = %+v", unfixed.Affected)
	}
	// The record this provider exists for: affected everywhere, no fix.
	ev := unfixed.Affected[0].Ranges[0].Events
	if len(ev) != 1 || ev[0].Introduced != "0" || ev[0].Fixed != "" {
		t.Errorf("CVE-2002-2439 events = %+v, want one introduced-0 event and no fixed one", ev)
	}
	// Discards are disclosed, not silent.
	if !strings.Contains(progress, "non-mainline") {
		t.Errorf("progress = %q, want it to account for what was dropped", progress)
	}
}

// D12: how current the data is comes from the archive Red Hat built, never
// from the clock on the machine running the sync.
func TestFetch_DataAsOfComesFromTheArchiveName(t *testing.T) {
	s := serve(t, "csaf_vex_2026-08-05.tar.zst", archiveOf(t, map[string]string{
		"a.json": docJSON(t, "CVE-2024-0001",
			map[string]string{"R": "cpe:/o:redhat:enterprise_linux:9"},
			[]string{"R:x-0:1-1.el9.x86_64"}, nil),
	}))
	p := New(Options{BaseURL: s.URL})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(want) {
		t.Errorf("DataAsOf = %s, want %s — a mirror serving a stale snapshot fetched today "+
			"must not report as fresh", prov.DataAsOf, want)
	}
	if prov.Ecosystems == nil || prov.Ecosystems[0] != "Red Hat:9" {
		t.Errorf("Ecosystems = %v, want the keys actually seen (D20)", prov.Ecosystems)
	}
}

func TestArchiveDate(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"csaf_vex_2026-08-05.tar.zst", true},
		{"2026-08-05.tar.zst", true},
		{"csaf_vex_latest.tar.zst", false},
		{"csaf_vex_2026-13-45.tar.zst", false},
		{"csaf_vex.tar.zst", false},
	} {
		_, err := archiveDate(tc.name)
		if (err == nil) != tc.ok {
			t.Errorf("archiveDate(%q) err = %v, want ok=%v — a name with no date must fail rather "+
				"than fall back to the fetch time (D12)", tc.name, err, tc.ok)
		}
	}
}

// The pointer file's contents become a URL, so anything that is not a plain
// archive filename is refused before it is requested.
func TestFetch_RefusesABadPointerFile(t *testing.T) {
	// A perfectly good archive is served at every path, so a pointer that
	// slipped past validation would SUCCEED rather than 404. Without that,
	// this test passes on the wrong error.
	good := archiveOf(t, map[string]string{
		"a.json": docJSON(t, "CVE-2024-0001",
			map[string]string{"R": "cpe:/o:redhat:enterprise_linux:9"},
			[]string{"R:x-0:1-1.el9.x86_64"}, nil),
	})
	// The first three carry a PERFECTLY VALID DATE, and that is the point.
	// Without them every case was caught downstream by archiveDate instead —
	// so deleting the pointer-file checks entirely left the test green while
	// the provider happily turned the file's contents into a URL and fetched
	// it. Each of these must be refused by the validation itself, named.
	for _, pointer := range []string{
		"https://example.invalid/csaf_vex_2026-08-05.tar.zst",
		"../../../csaf_vex_2026-08-05.tar.zst",
		"a/b/csaf_vex_2026-08-05.tar.zst",
		"",
		"csaf_vex_2026-08-05.tar.gz",
		"<html>404 Not Found</html>",
	} {
		t.Run(pointer, func(t *testing.T) {
			s := serve(t, pointer, good)
			_, _, err := fetchAll(t, s)
			if err == nil {
				t.Fatalf("pointer %q was accepted, and its contents became a URL this "+
					"provider then fetched", pointer)
			}
			if !strings.Contains(err.Error(), pointerFile) {
				t.Errorf("pointer %q was rejected by something other than the pointer-file "+
					"validation, so that validation is not what is being tested: %v", pointer, err)
			}
		})
	}
}

// D20's guard. An archive that yields no Red Hat records must fail the build
// rather than write a database whose every RHEL scan reports clean.
func TestFetch_NoRecordsIsAnError(t *testing.T) {
	s := serve(t, "csaf_vex_2026-08-05.tar.zst", archiveOf(t, map[string]string{
		"a.json": docJSON(t, "CVE-2024-0001",
			map[string]string{"CEPH": "cpe:/a:redhat:ceph_storage:5"},
			[]string{"CEPH:ceph-0:1-1.x86_64"}, nil),
	}))
	_, _, err := fetchAll(t, s)
	if err == nil {
		t.Fatal("an archive with no mainline Red Hat records was accepted")
	}
	if !strings.Contains(err.Error(), "no mainline Red Hat records") {
		t.Errorf("error = %v, want it to name what was missing", err)
	}
}

// One unreadable document is counted and the sync continues. A 17 GB archive
// with a single truncated entry must not cost a whole build.
func TestFetch_OneBadDocumentDoesNotFailTheSync(t *testing.T) {
	s := serve(t, "csaf_vex_2026-08-05.tar.zst", archiveOf(t, map[string]string{
		"bad.json": "{not json",
		"good.json": docJSON(t, "CVE-2024-0001",
			map[string]string{"R": "cpe:/o:redhat:enterprise_linux:9"},
			[]string{"R:openssh-0:1-1.el9.x86_64"}, nil),
	}))
	got, progress, err := fetchAll(t, s)
	if err != nil {
		t.Fatalf("one unreadable document failed the whole sync: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("emitted %d advisories, want the one that parsed", len(got))
	}
	if !strings.Contains(progress, "1 unreadable documents") {
		t.Errorf("progress = %q, want the unreadable document counted", progress)
	}
}

// A context cancelled MID-STREAM stops the walk. The real archive holds 67,261
// documents and takes about ninety seconds, so this is the difference between
// Ctrl-C working and not.
//
// Cancelling before the call would prove nothing: the HTTP request fails on
// its own, and the check inside the loop could be deleted with the test still
// green. This one cancels from the emit callback, after the response body has
// already been delivered, so only the loop's own ctx.Err() can stop it.
func TestFetch_HonoursContextCancellation(t *testing.T) {
	docs := map[string]string{}
	for i := 0; i < 50; i++ {
		docs[fmt.Sprintf("cve-2024-%04d.json", i)] = docJSON(t, fmt.Sprintf("CVE-2024-%04d", i),
			map[string]string{"R": "cpe:/o:redhat:enterprise_linux:9"},
			[]string{"R:x-0:1-1.el9.x86_64"}, nil)
	}
	s := serve(t, "csaf_vex_2026-08-05.tar.zst", archiveOf(t, docs))

	ctx, cancel := context.WithCancel(context.Background())
	emitted := 0
	_, err := New(Options{BaseURL: s.URL}).Fetch(ctx, func(advisory.Advisory) error {
		emitted++
		cancel()
		return nil
	})
	if err == nil {
		t.Fatal("a context cancelled mid-stream did not stop the fetch")
	}
	if emitted > 2 {
		t.Errorf("kept emitting after cancellation: %d advisories out of %d documents", emitted, len(docs))
	}
}
