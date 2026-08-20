package amazon

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/severity"
)

// updateFixture is one <update> element's raw ingredients, rendered to XML by
// updatesXML below rather than hand-typed per test -- the real schema nests
// four levels deep (pkglist>collection>package) and a hand-written string
// literal per test would drift from updateinfo.go's structs unnoticed.
type updateFixture struct {
	typ      string // defaults to "security"
	id       string
	title    string
	issued   string
	updated  string
	severity string
	cves     []string
	pkgs     []pkgFixture
}

type pkgFixture struct {
	name, epoch, version, release, arch string
}

// updatesXML renders a full updateinfo.xml document, matching the shape
// verified directly against AL2 and AL2023's live core feeds 2026-08-19.
func updatesXML(t *testing.T, ups []updateFixture) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" ?>` + "\n<updates>")
	for _, u := range ups {
		typ := u.typ
		if typ == "" {
			typ = "security"
		}
		fmt.Fprintf(&b, `<update status="final" version="1.4" type="%s" from="linux-security@amazon.com">`, typ)
		fmt.Fprintf(&b, `<id>%s</id><title>%s</title>`, xmlEscape(u.id), xmlEscape(u.title))
		if u.issued != "" {
			fmt.Fprintf(&b, `<issued date="%s" />`, u.issued)
		}
		if u.updated != "" {
			fmt.Fprintf(&b, `<updated date="%s" />`, u.updated)
		}
		if u.severity != "" {
			fmt.Fprintf(&b, `<severity>%s</severity>`, xmlEscape(u.severity))
		}
		b.WriteString(`<references>`)
		for _, cve := range u.cves {
			fmt.Fprintf(&b, `<reference href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s" title="" id="%s" type="cve" />`,
				xmlEscape(cve), xmlEscape(cve))
		}
		b.WriteString(`</references>`)
		b.WriteString(`<pkglist><collection short="amazon-linux"><name>Amazon Linux</name>`)
		for _, pk := range u.pkgs {
			arch := pk.arch
			if arch == "" {
				arch = "x86_64"
			}
			fmt.Fprintf(&b, `<package name="%s" version="%s" release="%s" epoch="%s" arch="%s"><filename>%s-%s-%s.%s.rpm</filename></package>`,
				xmlEscape(pk.name), xmlEscape(pk.version), xmlEscape(pk.release), xmlEscape(pk.epoch), xmlEscape(arch),
				xmlEscape(pk.name), xmlEscape(pk.version), xmlEscape(pk.release), xmlEscape(arch))
		}
		b.WriteString(`</collection></pkglist>`)
		b.WriteString(`</update>`)
	}
	b.WriteString(`</updates>`)
	return b.Bytes()
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		panic(err)
	}
	return b.String()
}

// gzipOf compresses b, the shape every real updateinfo.xml.gz is served in.
func gzipOf(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// repoServer stands up one repo's mirror.list -> repomd.xml ->
// updateinfo.xml.gz chain behind an httptest server, resolving through a
// SEPARATE "mirror" path the way the real cdn.amazonlinux.com does (a
// rotating GUID/hash segment) rather than serving updateinfo directly off
// the mirror.list URL -- proving the indirection is actually followed, not
// hardcoded past.
func repoServer(t *testing.T, ups []updateFixture) *httptest.Server {
	t.Helper()
	gz := gzipOf(t, updatesXML(t, ups))
	mux := http.NewServeMux()
	mux.HandleFunc("/mirror.list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "http://%s/resolved/guid-abc123/\n", r.Host)
	})
	mux.HandleFunc("/resolved/guid-abc123/repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<repomd xmlns="http://linux.duke.edu/metadata/repo">`+
			`<revision>1700000000</revision>`+
			`<data type="primary"><location href="repodata/primary.xml.gz" /></data>`+
			`<data type="updateinfo"><location href="repodata/updateinfo.xml.gz" /></data>`+
			`</repomd>`)
	})
	mux.HandleFunc("/resolved/guid-abc123/repodata/updateinfo.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "binary/octet-stream")
		w.Write(gz)
	})
	return httptest.NewServer(mux)
}

// TestFetch_ResolvesIndirectionAndEmitsAdvisories drives Fetch end to end
// through the real mirror.list -> repomd.xml -> updateinfo.xml.gz chain
// (repoServer builds the mirror URL from a value only mirror.list's response
// body names, "guid-abc123" -- if Fetch hardcoded a "repodata/..." path off
// the mirror.list URL itself rather than following its response, this 404s).
func TestFetch_ResolvesIndirectionAndEmitsAdvisories(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0001", title: "important priority package update for openssh",
		issued: "2026-01-05 10:00:00", updated: "2026-01-06 11:00:00",
		severity: "important",
		cves:     []string{"CVE-2026-1001"},
		pkgs: []pkgFixture{
			{name: "openssh", epoch: "0", version: "8.7p1", release: "38.amzn2"},
			{name: "openssh-server", epoch: "0", version: "8.7p1", release: "38.amzn2"},
		},
	}})
	defer srv.Close()

	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}}})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("emitted %d advisories, want 1: %+v", len(got), got)
	}
	a := got[0]
	if a.ID != "ALAS2-2026-0001" {
		t.Errorf("ID = %q, want ALAS2-2026-0001", a.ID)
	}
	if a.Database != "ALAS2" {
		t.Errorf("Database = %q, want ALAS2", a.Database)
	}
	if a.Source != SourceName {
		t.Errorf("Source = %q, want %q", a.Source, SourceName)
	}
	if len(a.Related) != 1 || a.Related[0] != "CVE-2026-1001" {
		t.Errorf("Related = %v, want [CVE-2026-1001]", a.Related)
	}
	if len(a.Severity) != 1 || a.Severity[0].Type != "VENDOR_WORD" || a.Severity[0].Score != "Important" {
		t.Errorf("Severity = %+v, want one VENDOR_WORD/Important entry", a.Severity)
	}
	if len(a.Affected) != 2 {
		t.Fatalf("Affected = %d entries, want 2 (openssh, openssh-server): %+v", len(a.Affected), a.Affected)
	}
	for _, aff := range a.Affected {
		if aff.Ecosystem != "Amazon Linux:2" {
			t.Errorf("Affected[%s].Ecosystem = %q, want Amazon Linux:2", aff.Name, aff.Ecosystem)
		}
		if len(aff.Ranges) != 1 || len(aff.Ranges[0].Events) != 2 {
			t.Fatalf("Affected[%s].Ranges = %+v, want one ECOSYSTEM range with 2 events", aff.Name, aff.Ranges)
		}
		if aff.Ranges[0].Type != advisory.RangeEcosystem {
			t.Errorf("Affected[%s] range type = %q, want ECOSYSTEM", aff.Name, aff.Ranges[0].Type)
		}
		if got := aff.Ranges[0].Events[1].Fixed; got != "8.7p1-38.amzn2" {
			t.Errorf("Affected[%s] fixed = %q, want 8.7p1-38.amzn2 (epoch 0 omitted)", aff.Name, got)
		}
	}
	// Provenance: freshness comes from the advisory's own dates, not repomd's
	// <revision> (which this fixture set to a much older 2023 timestamp) --
	// the hazard the research this slice shipped from flagged explicitly.
	wantAsOf := time.Date(2026, 1, 6, 11, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("DataAsOf = %v, want %v (the update's own <updated> date, not repomd's <revision>)",
			prov.DataAsOf, wantAsOf)
	}
	if prov.Records != 1 {
		t.Errorf("Records = %d, want 1", prov.Records)
	}
	if len(prov.Ecosystems) != 1 || prov.Ecosystems[0] != "Amazon Linux:2" {
		t.Errorf("Ecosystems = %v, want [Amazon Linux:2]", prov.Ecosystems)
	}
}

// TestFetch_SeverityCasingBothNormalize proves AL2's lowercase and AL2023's
// Title-case severities land on the identical VENDOR_WORD score, so a
// finding from either repo bands the same way (severity.Highest compares by
// score across a mix of sources).
func TestFetch_SeverityCasingBothNormalize(t *testing.T) {
	al2 := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0002", severity: "critical", // AL2's own lowercase spelling
		pkgs: []pkgFixture{{name: "kernel", epoch: "0", version: "5.10.1", release: "1.amzn2"}},
	}})
	defer al2.Close()
	al2023 := repoServer(t, []updateFixture{{
		id: "ALAS2023-2026-0003", severity: "Critical", // AL2023's own Title-case spelling
		pkgs: []pkgFixture{{name: "kernel", epoch: "0", version: "6.1.1", release: "1.amzn2023"}},
	}})
	defer al2023.Close()

	p := New(Options{Repos: []Repo{
		{Ecosystem: "Amazon Linux:2", MirrorListURL: al2.URL + "/mirror.list"},
		{Ecosystem: "Amazon Linux:2023", MirrorListURL: al2023.URL + "/mirror.list"},
	}})
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("emitted %d advisories, want 2: %+v", len(got), got)
	}
	for _, a := range got {
		if len(a.Severity) != 1 || a.Severity[0].Score != "Critical" {
			t.Errorf("%s: Severity = %+v, want one VENDOR_WORD/Critical entry regardless of upstream casing",
				a.ID, a.Severity)
		}
	}
}

// TestFetch_MediumIsAmazonsSpellingForModerate pins the D73 map extension:
// Amazon's own word is "Medium" (AL2023) / "medium" (AL2), not RHSA's
// "Moderate" -- and it must normalize to something severity.Of can actually
// score, or every AL2/AL2023 medium-severity advisory bands Unknown (D17)
// silently.
func TestFetch_MediumIsAmazonsSpellingForModerate(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2023-2026-0004", severity: "Medium",
		pkgs: []pkgFixture{{name: "curl", epoch: "0", version: "8.1.0", release: "1.amzn2023"}},
	}})
	defer srv.Close()
	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/mirror.list"}}})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Severity) != 1 || got.Severity[0].Score != "Medium" {
		t.Fatalf("Severity = %+v, want one VENDOR_WORD/Medium entry", got.Severity)
	}
	// The stored word must actually be scorable, or this is theater: without
	// severity.vendorSeverityWords carrying a "Medium" entry (only "Moderate"
	// existed before D73), severity.Of("Medium") returns ErrUnscorable and
	// every Amazon Linux medium-severity finding bands Unknown (D17) silently.
	band, score, err := severity.Of(got.Severity[0].Score)
	if err != nil {
		t.Fatalf("severity.Of(%q) = %v, want a real band -- the word map needs a "+
			"\"Medium\" entry alongside RHSA's \"Moderate\"", got.Severity[0].Score, err)
	}
	if band != severity.Medium || score != 4.0 {
		t.Errorf("severity.Of(%q) = %v/%v, want medium/4.0 (the same band+score as \"Moderate\")",
			got.Severity[0].Score, band, score)
	}
}

// TestFetch_ZeroAdvisoryRepoErrors is the per-repo guard from D20's own
// reasoning (osv.Provider.Fetch's per-ecosystem guard, applied here): a repo
// whose updateinfo carries no security advisories at all must fail the
// build rather than silently produce a database that answers every scan of
// that release with "no advisories".
func TestFetch_ZeroAdvisoryRepoErrors(t *testing.T) {
	// Every update here is bugfix-typed, not security-typed -- Convert drops
	// them all, leaving this repo with zero.
	srv := repoServer(t, []updateFixture{{
		typ: "bugfix", id: "ALAS2-2026-0005", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	defer srv.Close()
	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}}})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one -- a repo with zero kept advisories must fail the build")
	}
	if !strings.Contains(err.Error(), "Amazon Linux:2") {
		t.Errorf("error %q does not name the repo that yielded nothing", err)
	}
}

// TestFetch_NonSecurityUpdateIsSkippedNotEmitted is the caller-first half of
// the type=="security" filter in convertUpdate: a bugfix update sitting
// alongside real security ones must not become a finding with no severity
// and no real vulnerability behind it.
func TestFetch_NonSecurityUpdateIsSkippedNotEmitted(t *testing.T) {
	srv := repoServer(t, []updateFixture{
		{typ: "bugfix", id: "ALAS2-2026-0006", severity: "low",
			pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}}},
		{id: "ALAS2-2026-0007", severity: "low",
			pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "2.amzn2"}}},
	})
	defer srv.Close()
	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}}})
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ALAS2-2026-0007" {
		t.Fatalf("emitted %+v, want exactly the one security-typed update", got)
	}
}

// TestFetch_DedupesAcrossArch proves buildAffected keeps one Affected entry
// per package NAME even when the pkglist lists it under several arches (the
// real shape: x86_64, aarch64, i686, noarch inside ONE update, measured 0
// cross-arch EVR divergence 2026-08-19) -- without the dedup this test would
// see 2 Affected entries for "kernel", both with the identical fixed
// version, which is what "harmless but bloats affected[]" in the research
// meant.
func TestFetch_DedupesAcrossArch(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0008", severity: "important",
		pkgs: []pkgFixture{
			{name: "kernel", epoch: "0", version: "5.10.1", release: "1.amzn2", arch: "x86_64"},
			{name: "kernel", epoch: "0", version: "5.10.1", release: "1.amzn2", arch: "aarch64"},
		},
	}})
	defer srv.Close()
	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}}})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Affected) != 1 {
		t.Fatalf("Affected = %d entries, want 1 (deduped across arch): %+v", len(got.Affected), got.Affected)
	}
}

// TestFetch_EpochIncludedOnlyWhenNonZero pins the rpmEVR convention against
// the actual epoch attribute Amazon's feed always states, including "0" --
// the fixed string must still omit it, matching rpmdb/header.go's own evr()
// for the installed side and every other RPM-family provider's fixed
// strings (D46).
func TestFetch_EpochIncludedOnlyWhenNonZero(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0009", severity: "important",
		pkgs: []pkgFixture{
			{name: "zero-epoch", epoch: "0", version: "1.2.3", release: "4.amzn2"},
			{name: "nonzero-epoch", epoch: "10", version: "1.5.3", release: "141.amzn2.5.3"},
		},
	}})
	defer srv.Close()
	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}}})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	fixed := map[string]string{}
	for _, aff := range got.Affected {
		fixed[aff.Name] = aff.Ranges[0].Events[1].Fixed
	}
	if fixed["zero-epoch"] != "1.2.3-4.amzn2" {
		t.Errorf("zero-epoch fixed = %q, want 1.2.3-4.amzn2 (no epoch prefix)", fixed["zero-epoch"])
	}
	if fixed["nonzero-epoch"] != "10:1.5.3-141.amzn2.5.3" {
		t.Errorf("nonzero-epoch fixed = %q, want 10:1.5.3-141.amzn2.5.3", fixed["nonzero-epoch"])
	}
}

// TestFetch_PrintsExtrasDisclosure is the delete-goes-red test for item 4's
// wiring: if the extrasDisclosure line is ever removed from Fetch, this is
// the only thing that notices, the same way CLAUDE.md's "the helper is
// covered; nothing calls it" warns a wiring line needs a test that actually
// observes the call, not just that the string constant exists somewhere.
func TestFetch_PrintsExtrasDisclosure(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0010", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	defer srv.Close()
	var progress strings.Builder
	p := New(Options{
		Repos:    []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		Progress: &progress,
	})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	out := progress.String()
	if !strings.Contains(out, "extras repos") || !strings.Contains(out, "CORE") {
		t.Errorf("progress output = %q, want it to disclose the core-only extras gap", out)
	}
}

// TestFetch_NoCVERefsStillEmits pins the ~1.5% hazard the research recorded:
// an advisory with no CVE reference at all must still become a finding
// reachable by its own ALAS id, not be dropped for lacking Related.
func TestFetch_NoCVERefsStillEmits(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0011", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	defer srv.Close()
	p := New(Options{Repos: []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}}})
	var got advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = a
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.ID != "ALAS2-2026-0011" {
		t.Errorf("ID = %q, want ALAS2-2026-0011", got.ID)
	}
	if len(got.Related) != 0 {
		t.Errorf("Related = %v, want empty", got.Related)
	}
}
