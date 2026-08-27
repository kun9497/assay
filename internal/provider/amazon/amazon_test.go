package amazon

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
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

// mountRepo mounts one repo's mirror.list -> repomd.xml -> updateinfo.xml.gz
// chain onto mux at the given path prefix ("" for the root, the way the
// original single-repo repoServer used it; "/extras/<topic>/latest/x86_64"
// for an extras topic, matching the real URL shape so a test proves the
// production URL construction rather than standing in for it). Resolves
// through a SEPARATE "resolved/guid/" path the way the real
// cdn.amazonlinux.com does (a rotating GUID/hash segment) rather than
// serving updateinfo directly off the mirror.list URL -- proving the
// indirection is actually followed, not hardcoded past.
func mountRepo(t *testing.T, mux *http.ServeMux, path string, ups []updateFixture) {
	t.Helper()
	gz := gzipOf(t, updatesXML(t, ups))
	resolved := path + "/resolved/guid/"
	mux.HandleFunc(path+"/mirror.list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "http://%s%s\n", r.Host, resolved)
	})
	mux.HandleFunc(resolved+"repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<repomd xmlns="http://linux.duke.edu/metadata/repo">`+
			`<revision>1700000000</revision>`+
			`<data type="primary"><location href="repodata/primary.xml.gz" /></data>`+
			`<data type="updateinfo"><location href="repodata/updateinfo.xml.gz" /></data>`+
			`</repomd>`)
	})
	mux.HandleFunc(resolved+"repodata/updateinfo.xml.gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "binary/octet-stream")
		w.Write(gz)
	})
}

// mountRepoNoUpdateinfo mounts a repo whose repomd.xml names NO updateinfo
// entry at all -- the OTHER zero-advisory shape measured live 2026-08-20 (14
// of 73 AL2 extras topics, e.g. emacs), distinct from an updateinfo.xml.gz
// that decodes to zero <update> elements. Exercises errNoUpdateinfo's own
// branch in fetchRepo rather than convertUpdate's ordinary empty-list path.
func mountRepoNoUpdateinfo(t *testing.T, mux *http.ServeMux, path string) {
	t.Helper()
	resolved := path + "/resolved/guid/"
	mux.HandleFunc(path+"/mirror.list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "http://%s%s\n", r.Host, resolved)
	})
	mux.HandleFunc(resolved+"repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<repomd xmlns="http://linux.duke.edu/metadata/repo">`+
			`<revision>1700000000</revision>`+
			`<data type="primary"><location href="repodata/primary.xml.gz" /></data>`+
			`</repomd>`)
	})
}

// mountExtrasCatalog mounts AL2's extras-catalog-x86_64.json, naming exactly
// the topics given -- proving fetchExtrasTopics reads the real "n" field
// (not "name") and that Fetch enumerates whatever the catalog names, nothing
// hardcoded past it. The real document's other top-level and per-topic
// fields ("motd", "whitelists", "inst", "deprecated-at", ...) are omitted on
// purpose: extrasCatalogDoc's own doc comment explains why there is no
// allowlist to keep in sync with them.
func mountExtrasCatalog(t *testing.T, mux *http.ServeMux, topics []string) {
	t.Helper()
	mux.HandleFunc("/extras-catalog-x86_64.json", func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(`{"status":"ok","version":1,"topics":[`)
		for i, name := range topics {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"n":%s}`, mustJSONString(t, name))
		}
		b.WriteString(`]}`)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, b.String())
	})
}

func mustJSONString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// quietExtrasServer stands up an extras catalog naming one topic whose repo
// publishes no updateinfo at all -- the quietest legitimate shape the live
// feed has (14 of 73 topics measured 2026-08-20) -- for every test in this
// file that is not itself testing extras behaviour: Options.ExtrasBaseURL
// defaults to the live CDN (DefaultExtrasBaseURL), so any test that left it
// unset would reach cdn.amazonlinux.com from `go test`. It cannot serve a
// zero-topic catalog instead, because Fetch's zero-topics guard refuses that
// as a shape change (TestFetch_ExtrasCatalogZeroTopicsErrors).
func quietExtrasServer(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"quiet-topic"})
	mountRepoNoUpdateinfo(t, mux, "/extras/quiet-topic/latest/x86_64")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// repoServer stands up one repo's mirror.list -> repomd.xml ->
// updateinfo.xml.gz chain behind an httptest server of its own -- the single-
// repo shape every pre-D78 test in this file uses, now built on mountRepo.
func repoServer(t *testing.T, ups []updateFixture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mountRepo(t, mux, "", ups)
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

	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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

// TestFetch_AggregateDataAsOfIsTheStalestRepo is the caller-first proof for
// D12's own rule on this branch (Fetch's comment: "The stalest repo wins ...
// reporting the newest would hide that"): two core repos with distinct
// dates, driven through the real Fetch path, must report the EARLIER
// (stalest) of the two as the aggregate DataAsOf, never the later one.
// TestFetch_ResolvesIndirectionAndEmitsAdvisories above is single-repo and
// cannot tell min from max; TestFetch_SeverityCasingBothNormalize's two
// repos carry no dates at all. A newer AL2023 repo silently hiding a stale
// AL2 core feed's own staleness is exactly the over-claim D12 exists to
// prevent.
func TestFetch_AggregateDataAsOfIsTheStalestRepo(t *testing.T) {
	mux := http.NewServeMux()
	mountRepo(t, mux, "/stale", []updateFixture{{
		id: "ALAS2-2026-0002", title: "stale repo update",
		issued: "2026-01-05 10:00:00", updated: "2026-01-06 11:00:00",
		severity: "important",
		pkgs:     []pkgFixture{{name: "curl", epoch: "0", version: "7.0", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/fresh", []updateFixture{{
		id: "ALAS2023-2026-0003", title: "fresh repo update",
		issued: "2026-06-01 10:00:00", updated: "2026-06-02 11:00:00",
		severity: "important",
		pkgs:     []pkgFixture{{name: "openssl", epoch: "0", version: "3.0", release: "1.amzn2023"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos: []Repo{
			{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/stale/mirror.list"},
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/fresh/mirror.list"},
		},
		ExtrasBaseURL: quietExtrasServer(t),
	})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	wantAsOf := time.Date(2026, 1, 6, 11, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("DataAsOf = %v, want %v -- the stalest repo's own date, not the fresher repo's "+
			"(D12: reporting the newest would hide that the database is only as fresh as its "+
			"least current source)", prov.DataAsOf, wantAsOf)
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

	p := New(Options{
		Repos: []Repo{
			{Ecosystem: "Amazon Linux:2", MirrorListURL: al2.URL + "/mirror.list"},
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: al2023.URL + "/mirror.list"},
		},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
//
// D100 closed the AL2023 extras gap this disclosure used to name -- the
// assertion now proves the line describes NVIDIA and kernel-livepatch as
// FETCHED, not as a remaining gap. If DefaultRepos' two new entries were
// ever removed without updating this string, this line would be actively
// lying about coverage, which is exactly what extrasDisclosure exists to
// prevent.
func TestFetch_PrintsExtrasDisclosure(t *testing.T) {
	srv := repoServer(t, []updateFixture{{
		id: "ALAS2-2026-0010", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	defer srv.Close()
	var progress strings.Builder
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
		Progress:      &progress,
	})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	out := progress.String()
	if !strings.Contains(out, "NVIDIA") || !strings.Contains(out, "kernel-livepatch") {
		t.Errorf("progress output = %q, want it to disclose AL2023's NVIDIA and kernel-livepatch "+
			"repos as fetched (D100)", out)
	}
}

// TestDefaultRepos_IncludesAL2023NvidiaAndLivepatch is the caller-first pin
// for D100's whole slice: New's only caller of DefaultRepos is its own
// zero-value fallback (New(Options{}) with Repos unset), and that path
// cannot be driven through Fetch in a hermetic test without reaching
// cdn.amazonlinux.com -- DefaultRepos is itself the exported contract
// (Options.Repos' own doc comment already treats it as one: "the same role
// redhat.Options.BaseURL plays"). Deleting either entry below silently drops
// an entire class of advisories (306 NVIDIA / 58 CVEs, 286 kernel-livepatch /
// 85 CVEs, zero overlap with core on the NVIDIA side) from a real `assay db
// build`, with nothing else in this file able to notice -- every other test
// in this file substitutes Options.Repos and never reads DefaultRepos at all.
func TestDefaultRepos_IncludesAL2023NvidiaAndLivepatch(t *testing.T) {
	want := []Repo{
		{Ecosystem: "Amazon Linux:2023", MirrorListURL: "https://cdn.amazonlinux.com/al2023/nvidia/mirrors/latest/x86_64/mirror.list"},
		{Ecosystem: "Amazon Linux:2023", MirrorListURL: "https://cdn.amazonlinux.com/al2023/kernel-livepatch/mirrors/latest/x86_64/mirror.list"},
	}
	for _, w := range want {
		var found bool
		for _, r := range DefaultRepos {
			if r == w {
				found = true
			}
		}
		if !found {
			t.Errorf("DefaultRepos missing %+v -- a real `assay db build` would silently drop this "+
				"repo's advisories (D100)", w)
		}
	}
}

// TestFetch_NvidiaAndLivepatchParticipateInDataAsOfFold is the caller-first
// proof for item 4: the stalest-repo-wins fold in Fetch (D12,
// TestFetch_AggregateDataAsOfIsTheStalestRepo's own proof for two repos) must
// also apply when NVIDIA and kernel-livepatch are among the repos being
// folded, not just the two CORE repos every existing test exercises. Here
// the STALEST date belongs to the kernel-livepatch-shaped repo; if fetchRepo
// or Fetch's fold ever special-cased which repos contribute a date, this
// would report one of the fresher repos' dates instead and go unnoticed by
// every pre-D100 test in this file.
func TestFetch_NvidiaAndLivepatchParticipateInDataAsOfFold(t *testing.T) {
	mux := http.NewServeMux()
	mountRepo(t, mux, "/core", []updateFixture{{
		id: "ALAS2023-2026-0100", severity: "important",
		issued: "2026-03-01 10:00:00", updated: "2026-03-02 10:00:00",
		pkgs: []pkgFixture{{name: "openssl", epoch: "0", version: "3.0", release: "1.amzn2023"}},
	}})
	mountRepo(t, mux, "/nvidia", []updateFixture{{
		id: "ALAS2023NVIDIA-2026-0001", severity: "important",
		issued: "2026-04-01 10:00:00", updated: "2026-04-02 10:00:00",
		cves: []string{"CVE-2026-9001"},
		pkgs: []pkgFixture{{name: "cuda-toolkit-12-8", epoch: "0", version: "12.8.0", release: "1"}},
	}})
	mountRepo(t, mux, "/lp", []updateFixture{{
		id: "ALAS2023LIVEPATCH-2026-0001", severity: "important",
		// The STALEST date of the three -- this one must win the fold.
		issued: "2026-01-01 10:00:00", updated: "2026-01-02 10:00:00",
		cves: []string{"CVE-2026-9002"},
		pkgs: []pkgFixture{{name: "kernel-livepatch-6.1.12-19.43", epoch: "0", version: "1.0", release: "1.amzn2023"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos: []Repo{
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/core/mirror.list"},
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/nvidia/mirror.list"},
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/lp/mirror.list"},
		},
		ExtrasBaseURL: quietExtrasServer(t),
	})
	prov, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	wantAsOf := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	if !prov.DataAsOf.Equal(wantAsOf) {
		t.Errorf("DataAsOf = %v, want %v -- the kernel-livepatch-shaped repo's own (stalest) date "+
			"must win the fold across all three AL2023 repos, not just the two CORE repos every "+
			"pre-D100 test exercised", prov.DataAsOf, wantAsOf)
	}
}

// TestFetch_LivepatchPackageNamesStayFullyQualified is the fixture-driven
// guard for the hazard amazon.go's own doc comment measures away for AL2023's
// kernel-livepatch repo (D100): package names trimmed from the real
// updateinfo-lp.xml artifact must land in Affected exactly as qualified
// ("kernel-livepatch-<kernelver>-<patchver>"), never collapsed to a bare
// "kernel" or merged across distinct kernel versions. Two DIFFERENT kernel
// versions are fixtured deliberately (buildAffected dedupes by exact name,
// not by prefix) -- if a future change ever truncated or generalized the
// name, this is what would notice; deleting the qualified names below and
// substituting a bare "kernel" turns this red.
func TestFetch_LivepatchPackageNamesStayFullyQualified(t *testing.T) {
	srv := repoServer(t, []updateFixture{
		{
			id: "ALAS2023LIVEPATCH-2023-001", severity: "important",
			cves: []string{"CVE-2023-26545"},
			pkgs: []pkgFixture{{name: "kernel-livepatch-6.1.12-19.43", epoch: "0", version: "1.0", release: "1.amzn2023"}},
		},
		{
			id: "ALAS2023LIVEPATCH-2023-002", severity: "important",
			cves: []string{"CVE-2023-28466"},
			pkgs: []pkgFixture{{name: "kernel-livepatch-6.1.19-30.43", epoch: "0", version: "1.0", release: "1.amzn2023"}},
		},
	})
	defer srv.Close()
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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
	names := map[string]bool{}
	for _, a := range got {
		for _, aff := range a.Affected {
			names[aff.Name] = true
			if aff.Name == "kernel" {
				t.Fatalf("advisory %s named bare \"kernel\" -- the exact collision hazard this "+
					"repo's own measurement (0/120 names) found nothing to guard against", a.ID)
			}
		}
	}
	for _, want := range []string{"kernel-livepatch-6.1.12-19.43", "kernel-livepatch-6.1.19-30.43"} {
		if !names[want] {
			t.Errorf("Affected names = %v, want %q present and fully qualified", names, want)
		}
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
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/mirror.list"}},
		ExtrasBaseURL: quietExtrasServer(t),
	})
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

// TestFetch_ExtrasTopicsEnumeratedAndAdvisoriesLand is the caller-first proof
// for D78's whole slice: Fetch must enumerate AL2's extras catalog and fetch
// every topic it names, not merely have fetchExtrasTopics sitting unused.
// Deleting the p.fetchExtrasTopics(ctx) call in Fetch (or the loop that turns
// its result into Repo entries) makes ALAS2DOCKER-2099-001 never land, and
// this is the only test that would notice.
//
// Two topics are mounted -- "docker" carrying one advisory, "quiet-topic"
// carrying none -- alongside the two ordinary CORE repos, all behind ONE
// httptest server, proving Options.Repos and Options.ExtrasBaseURL can point
// at the same server a hermetic test needs even though a real deployment
// never would.
func TestFetch_ExtrasTopicsEnumeratedAndAdvisoriesLand(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"docker", "quiet-topic"})
	// "extrpkg" and "ALAS2DOCKER-2099-001" share no substring (CLAUDE.md's
	// substring-collision rule) -- neither could pass this test by landing on
	// the wrong column.
	mountRepo(t, mux, "/extras/docker/latest/x86_64", []updateFixture{{
		id: "ALAS2DOCKER-2099-001", severity: "important",
		cves: []string{"CVE-2099-5001"},
		pkgs: []pkgFixture{{name: "extrpkg", epoch: "0", version: "1.0", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/extras/quiet-topic/latest/x86_64", nil) // 0 <update> elements
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2099-100", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Progress wired here (unlike before) so the extras-advisories COUNT
	// itself, not just the emitted advisory, is asserted: the only other test
	// where the count is non-zero is this one, and every test that reads the
	// stats line (TestFetch_ExtrasEmptyTopicCountedNotError,
	// TestFetch_ExtrasTopicWithNoUpdateinfoEntryCountedNotError) does so in a
	// scenario where "0 advisories ingested" is right either way.
	var progress strings.Builder
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
		Progress:      &progress,
	})
	var got []advisory.Advisory
	prov, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if want := "extras: 2 topics enumerated, 1 with zero advisories, 1 advisories ingested"; !strings.Contains(progress.String(), want) {
		t.Errorf("progress output = %q, want it to contain %q -- the one extras advisory that "+
			"landed must be counted in st.ExtrasAdvisories, not just ride the undifferentiated total",
			progress.String(), want)
	}

	var extrasAdv *advisory.Advisory
	for i := range got {
		if got[i].ID == "ALAS2DOCKER-2099-001" {
			extrasAdv = &got[i]
		}
	}
	if extrasAdv == nil {
		t.Fatalf("extras advisory ALAS2DOCKER-2099-001 was never emitted (topic enumeration did not run); "+
			"got %d advisories: %+v", len(got), got)
	}
	if len(extrasAdv.Affected) != 1 || extrasAdv.Affected[0].Name != "extrpkg" {
		t.Fatalf("extras advisory Affected = %+v, want exactly one entry named extrpkg", extrasAdv.Affected)
	}
	if extrasAdv.Affected[0].Ecosystem != "Amazon Linux:2" {
		t.Errorf("extras advisory Ecosystem = %q, want Amazon Linux:2 (same key core uses)",
			extrasAdv.Affected[0].Ecosystem)
	}

	var coreFound bool
	for _, a := range got {
		if a.ID == "ALAS2-2099-100" {
			coreFound = true
		}
	}
	if !coreFound {
		t.Errorf("core advisory ALAS2-2099-100 missing from %+v -- extras enumeration must not crowd out core", got)
	}
	if len(got) != 2 {
		t.Errorf("emitted %d advisories, want exactly 2 (one extras, one core): %+v", len(got), got)
	}
	if prov.Records != 2 {
		t.Errorf("Records = %d, want 2", prov.Records)
	}
}

// TestFetch_ExtrasCatalogZeroTopicsErrors holds the zero-topics guard: a
// catalog that parses cleanly but names no topics is a shape change (a
// renamed "n" field decodes to exactly this), not a smaller feed -- the live
// catalog carried 73 topics measured 2026-08-20 -- and shipping past it
// would rebuild the silently core-only database D78 exists to close.
// Deleting the guard in Fetch turns this red.
func TestFetch_ExtrasCatalogZeroTopicsErrors(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, nil)
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2099-100", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
	})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch succeeded against a zero-topic extras catalog; want the shape-change error")
	}
	if !strings.Contains(err.Error(), "zero topics") {
		t.Errorf("error %q does not name the zero-topic condition", err)
	}
}

// TestFetch_ExtrasEmptyTopicCountedNotError is the zero-advisory scoping
// test (item 3): an extras topic whose updateinfo.xml.gz decodes to zero
// <update> elements (28 of 73 measured live 2026-08-20) must not fail the
// build the way a CORE repo doing the same does
// (TestFetch_ZeroAdvisoryRepoErrors, unchanged by D78) -- it must be counted
// in the stats line instead. Deleting the `if !r.Extras` guard in Fetch's
// zero-kept branch turns this red.
func TestFetch_ExtrasEmptyTopicCountedNotError(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"quiet-topic"})
	mountRepo(t, mux, "/extras/quiet-topic/latest/x86_64", nil)
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2099-200", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var progress strings.Builder
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
		Progress:      &progress,
	})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v, want no error -- an empty extras topic must be counted, not fatal", err)
	}
	want := "extras: 1 topics enumerated, 1 with zero advisories, 0 advisories ingested"
	if !strings.Contains(progress.String(), want) {
		t.Errorf("progress output = %q, want it to contain %q", progress.String(), want)
	}
}

// TestFetch_ExtrasTopicWithNoUpdateinfoEntryCountedNotError exercises the
// OTHER zero-advisory shape measured live 2026-08-20 (14 of 73 AL2 extras
// topics, e.g. emacs): repomd.xml names no <data type="updateinfo"> entry at
// all -- the errNoUpdateinfo branch in fetchRepo, distinct from
// TestFetch_ExtrasEmptyTopicCountedNotError's updateinfo.xml.gz that decodes
// to zero <update> elements, and not reached by that test or the
// caller-first test above. Deleting the errors.Is(err, errNoUpdateinfo)
// check in fetchRepo turns this red.
func TestFetch_ExtrasTopicWithNoUpdateinfoEntryCountedNotError(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"no-updateinfo-topic"})
	mountRepoNoUpdateinfo(t, mux, "/extras/no-updateinfo-topic/latest/x86_64")
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2099-300", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var progress strings.Builder
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
		Progress:      &progress,
	})
	if _, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil }); err != nil {
		t.Fatalf("Fetch: %v, want no error -- a topic with no updateinfo entry at all must be counted, not fatal", err)
	}
	want := "extras: 1 topics enumerated, 1 with zero advisories, 0 advisories ingested"
	if !strings.Contains(progress.String(), want) {
		t.Errorf("progress output = %q, want it to contain %q", progress.String(), want)
	}
}

// TestFetch_ExtrasFetchErrorNamesTheMirrorURL proves a genuine fetch failure
// on an extras topic (as opposed to a legitimate zero) still fails the
// build, and that the error names WHICH topic failed: with up to 73 extras
// repos sharing one ecosystem string ("Amazon Linux:2"), r.Ecosystem alone
// (core's own error shape) would not say which one. Also pins the real URL
// shape (item 1): <base>/extras/<topic>/latest/x86_64/mirror.list.
func TestFetch_ExtrasFetchErrorNamesTheMirrorURL(t *testing.T) {
	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"broken-topic"})
	// No handler mounted for /extras/broken-topic/... at all: mirror.list
	// 404s, the same as a topic the CDN stopped serving mid-build.
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2099-500", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"}},
		ExtrasBaseURL: srv.URL,
	})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one -- broken-topic's mirror.list 404s")
	}
	if !strings.Contains(err.Error(), "/extras/broken-topic/latest/x86_64/mirror.list") {
		t.Errorf("error = %q, want it to name the failing topic's mirror.list URL", err)
	}
}

// TestFetch_CoreZeroAdvisoryErrorCountsOnlyThatRepo proves the per-repo delta
// Fetch now tracks (updatesBefore): with dozens of extras repos able to share
// one stats accumulator, the zero-advisory error must report the FAILING
// repo's own update count, not the running total across every repo already
// processed in the loop. AL2 core here contributes one update before
// AL2023's (empty) chain is read; the error must say "0 updates", not "1".
func TestFetch_CoreZeroAdvisoryErrorCountsOnlyThatRepo(t *testing.T) {
	mux := http.NewServeMux()
	mountRepo(t, mux, "/core-al2", []updateFixture{{
		id: "ALAS2-2099-400", severity: "low",
		pkgs: []pkgFixture{{name: "bash", epoch: "0", version: "5.1", release: "1.amzn2"}},
	}})
	mountRepo(t, mux, "/core-al2023", nil) // 0 <update> elements: the guard must fire here
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{
		Repos: []Repo{
			{Ecosystem: "Amazon Linux:2", MirrorListURL: srv.URL + "/core-al2/mirror.list"},
			{Ecosystem: "Amazon Linux:2023", MirrorListURL: srv.URL + "/core-al2023/mirror.list"},
		},
		ExtrasBaseURL: quietExtrasServer(t),
	})
	_, err := p.Fetch(context.Background(), func(advisory.Advisory) error { return nil })
	if err == nil {
		t.Fatal("Fetch: no error, want one -- Amazon Linux:2023 yielded zero advisories")
	}
	if !strings.Contains(err.Error(), "Amazon Linux:2023") {
		t.Errorf("error %q does not name the repo that yielded nothing", err)
	}
	if !strings.Contains(err.Error(), "out of 0 updates") {
		t.Errorf("error = %q, want it to report 0 updates for Amazon Linux:2023 itself, "+
			"not the 1 update Amazon Linux:2 (processed first) contributed to the running total", err)
	}
}

// TestFetchExtrasTopics_SkipsEmptyNamesAndIgnoresUnknownFields is a direct
// unit test of the helper for a branch the caller-first test does not
// exercise: a topic entry with an empty "n" (never seen live, but the
// catalog is third-party JSON) must not become a mirror.list URL that could
// only 404, and the catalog's other real fields (motd, whitelists, inst,
// versions, deprecated-at -- all present live 2026-08-20, none read by
// extrasTopic) must not break decoding.
func TestFetchExtrasTopics_SkipsEmptyNamesAndIgnoresUnknownFields(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/extras-catalog-x86_64.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"motd":"hello","status":"ok","version":1,"whitelists":[[0,1]],`+
			`"topics":[{"n":"docker","inst":["docker"],"versions":["stable"],"deprecated-at":"2023-09-30"},`+
			`{"n":""},{"n":"livepatch","versions":["stable"]}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := New(Options{ExtrasBaseURL: srv.URL})
	topics, err := p.fetchExtrasTopics(context.Background())
	if err != nil {
		t.Fatalf("fetchExtrasTopics: %v", err)
	}
	if want := []string{"docker", "livepatch"}; !reflect.DeepEqual(topics, want) {
		t.Errorf("fetchExtrasTopics = %v, want %v (empty-name entry skipped)", topics, want)
	}
}
