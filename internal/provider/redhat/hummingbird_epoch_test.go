package redhat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// QA 2026-11-20 (P1). Red Hat's feed writes one Hummingbird build both ways:
// cve-2026-95101 and cve-2026-97629 list nginx 1.30.6-1.hum1 with no "epoch"
// qualifier, cve-2026-120993 lists the same build with "epoch=2". The
// installed nginx is 2:1.30.4-2.hum1, so an epoch-less fix sorts below it and
// the image was judged clean for both CVEs. The epoch is restored from the
// feed as a whole, after every document has been read.

// hbDocJSON is a Hummingbird document fixing each product id at its purl.
func hbDocJSON(t *testing.T, cve string, purls map[string]string) string {
	t.Helper()
	type prod struct {
		ProductID string `json:"product_id"`
		Helper    struct {
			CPE  string `json:"cpe,omitempty"`
			Purl string `json:"purl,omitempty"`
		} `json:"product_identification_helper"`
	}
	platform := prod{ProductID: "Red Hat Hardened Images"}
	platform.Helper.CPE = "cpe:/a:redhat:hummingbird:1"
	kids := []map[string]any{{"category": "product_name", "name": platform.ProductID, "product": platform}}
	var fixed []string
	for id, purl := range purls {
		p := prod{ProductID: id}
		p.Helper.Purl = purl
		kids = append(kids, map[string]any{"category": "product_version", "name": id, "product": p})
		fixed = append(fixed, "Red Hat Hardened Images:"+id)
	}
	b, err := json.Marshal(map[string]any{
		"document": map[string]any{"title": "a test advisory", "tracking": map[string]any{"id": cve}},
		"product_tree": map[string]any{"branches": []any{map[string]any{
			"category": "vendor", "name": "Red Hat",
			"branches": []any{map[string]any{"category": "product_family", "name": "fam", "branches": kids}},
		}}},
		"vulnerabilities": []any{map[string]any{
			"cve":            cve,
			"product_status": map[string]any{"fixed": fixed},
			"scores": []any{map[string]any{
				"cvss_v3": map[string]any{"vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func hbPurl(name, versionRelease, epoch string) string {
	p := "pkg:rpm/redhat/" + name + "@" + versionRelease + "?arch=x86_64&distro=hummingbird-20251124"
	if epoch != "" {
		p += "&epoch=" + epoch
	}
	return p + "&repository_id=public-hummingbird-x86_64-rpms"
}

// hummingbirdFixes is the fixed version each emitted record stores for one
// Hummingbird package, by record id.
func hummingbirdFixes(t *testing.T, advs []advisory.Advisory, name string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, adv := range advs {
		for _, a := range adv.Affected {
			if a.Ecosystem != hummingbirdEcosystem || a.Name != name {
				continue
			}
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						out[adv.ID] = e.Fixed
					}
				}
			}
		}
	}
	return out
}

// The caller's test: through Fetch, off an archive. Four shapes in one feed.
func TestFetch_HummingbirdEpochIsRestoredFromTheFeed(t *testing.T) {
	s := serve(t, &feed{pointer: "csaf_vex_2026-11-20.tar.zst", archive: archiveOf(t, map[string]string{
		// One build, written both ways (the live shape).
		"2026/cve-2026-95101.json": hbDocJSON(t, "CVE-2026-95101", map[string]string{
			"nginx-0:1.30.6-1.hum1@x86_64": hbPurl("nginx", "1.30.6-1.hum1", "")}),
		"2026/cve-2026-120993.json": hbDocJSON(t, "CVE-2026-120993", map[string]string{
			"nginx-2:1.30.6-1.hum1@x86_64": hbPurl("nginx", "1.30.6-1.hum1", "2")}),
		// A build only an epoch-less document mentions, of a package the
		// feed puts at one epoch everywhere else.
		"2026/cve-2026-130001.json": hbDocJSON(t, "CVE-2026-130001", map[string]string{
			"nginx-0:1.30.8-1.hum1@x86_64": hbPurl("nginx", "1.30.8-1.hum1", "")}),
		// A package no document gives an epoch: left alone.
		"2026/cve-2026-50811.json": hbDocJSON(t, "CVE-2026-50811", map[string]string{
			"freetype-main@x86_64": hbPurl("freetype", "2.14.3-1.2.hum1", "")}),
		// A package the feed puts at two epochs: a third, epoch-less build
		// is not guessed at.
		"2026/cve-2026-130002.json": hbDocJSON(t, "CVE-2026-130002", map[string]string{
			"tomcat-1:10.1.1-1.hum1@x86_64": hbPurl("tomcat", "10.1.1-1.hum1", "1")}),
		"2026/cve-2026-130003.json": hbDocJSON(t, "CVE-2026-130003", map[string]string{
			"tomcat-2:11.0.1-1.hum1@x86_64": hbPurl("tomcat", "11.0.1-1.hum1", "2")}),
		"2026/cve-2026-130004.json": hbDocJSON(t, "CVE-2026-130004", map[string]string{
			"tomcat-0:11.0.5-1.hum1@x86_64": hbPurl("tomcat", "11.0.5-1.hum1", "")}),
	})})
	got, progress, err := fetchAll(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("emitted %d records, want all 7: a held record must still be emitted", len(got))
	}

	nginx := hummingbirdFixes(t, got, "nginx")
	for id, want := range map[string]string{
		"REDHAT-CVE-2026-95101":  "2:1.30.6-1.hum1", // the same build, stated with its epoch elsewhere
		"REDHAT-CVE-2026-120993": "2:1.30.6-1.hum1", // already right
		"REDHAT-CVE-2026-130001": "2:1.30.8-1.hum1", // the package's one epoch
	} {
		if nginx[id] != want {
			t.Errorf("%s fixes nginx at %q, want %q", id, nginx[id], want)
		}
	}
	if got := hummingbirdFixes(t, got, "freetype")["REDHAT-CVE-2026-50811"]; got != "2.14.3-1.2.hum1" {
		t.Errorf("freetype fixed at %q, want it left epoch-less: no document gives it one", got)
	}
	if got := hummingbirdFixes(t, got, "tomcat")["REDHAT-CVE-2026-130004"]; got != "11.0.5-1.hum1" {
		t.Errorf("tomcat fixed at %q, want it left as written: the feed gives tomcat two epochs", got)
	}
	for _, want := range []string{
		"1 more given the epoch another document states for the same build",
		"1 the one epoch the feed gives the package, 1 left epoch-less between two",
	} {
		if !strings.Contains(progress, want) {
			t.Errorf("progress line lacks %q:%s%s", want, nl, progress)
		}
	}

	// What a host is told. Before the fix both rows were clean.
	judged := false
	for _, adv := range got {
		if adv.ID != "REDHAT-CVE-2026-95101" {
			continue
		}
		judged = true
		v := verdictsOf(t, adv,
			pkgmeta.Package{Name: "nginx", Version: "2:1.30.4-2.hum1", Ecosystem: "Hummingbird"},
			pkgmeta.Package{Name: "nginx", Version: "2:1.30.6-1.hum1", Ecosystem: "Hummingbird"})
		if v["Hummingbird/nginx@2:1.30.4-2.hum1"] != "2:1.30.6-1.hum1" {
			t.Errorf("installed nginx 2:1.30.4-2.hum1 = %q, want the fix 2:1.30.6-1.hum1", v["Hummingbird/nginx@2:1.30.4-2.hum1"])
		}
		if v["Hummingbird/nginx@2:1.30.6-1.hum1"] != "" {
			t.Errorf("installed nginx 2:1.30.6-1.hum1 = %q, want clean: it is the fixed build", v["Hummingbird/nginx@2:1.30.6-1.hum1"])
		}
	}
	if !judged {
		t.Error("REDHAT-CVE-2026-95101 was not emitted, so nothing was judged")
	}
}

// Two copies of one document reach the store in emission order, and the
// later one wins (D129, D135). Holding only the copy that carries a
// Hummingbird entry would emit it after a newer copy that does not.
func TestHummingbirdHold_KeepsTwoCopiesOfOneDocumentInOrder(t *testing.T) {
	hb := advisory.Advisory{ID: "REDHAT-CVE-1", Summary: "older", Affected: []advisory.Affected{{Ecosystem: hummingbirdEcosystem, Name: "nginx"}}}
	plain := advisory.Advisory{ID: "REDHAT-CVE-1", Summary: "newer", Affected: []advisory.Affected{{Ecosystem: "Red Hat:9", Name: "nginx"}}}
	other := advisory.Advisory{ID: "REDHAT-CVE-2", Affected: []advisory.Affected{{Ecosystem: "Red Hat:9", Name: "curl"}}}

	var h hummingbirdHold
	if !h.take(hb) {
		t.Fatal("a record with a Hummingbird entry was not held")
	}
	if h.take(other) {
		t.Fatal("an unrelated mainline record was held")
	}
	if !h.take(plain) {
		t.Fatal("the second copy of a held document was emitted ahead of the first")
	}
	var order []string
	var st stats
	if err := h.release(&st, func(a advisory.Advisory) error { order = append(order, a.Summary); return nil }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "older,newer" {
		t.Errorf("released %v, want older then newer", order)
	}
}

// A build stated at two epochs is not settled by either statement.
func TestHummingbirdHold_ADisputedBuildIsNotGuessed(t *testing.T) {
	fix := func(id, fixed string) advisory.Advisory {
		return advisory.Advisory{ID: id, Affected: []advisory.Affected{{Ecosystem: hummingbirdEcosystem, Name: "tomcat",
			Ranges: []advisory.Range{{Type: advisory.RangeEcosystem, Events: []advisory.Event{{Introduced: "0"}, {Fixed: fixed}}}}}}}
	}
	var h hummingbirdHold
	for _, a := range []advisory.Advisory{fix("A", "1:10.1.1-1.hum1"), fix("B", "2:10.1.1-1.hum1"), fix("C", "10.1.1-1.hum1")} {
		h.take(a)
	}
	var out []advisory.Advisory
	var st stats
	if err := h.release(&st, func(a advisory.Advisory) error { out = append(out, a); return nil }); err != nil {
		t.Fatal(err)
	}
	if got := hummingbirdFixes(t, out, "tomcat")["C"]; got != "10.1.1-1.hum1" {
		t.Errorf("C fixed at %q, want it left as written", got)
	}
	if st.HummingbirdEpochUnsettled != 1 || st.HummingbirdEpochFromBuild != 0 {
		t.Errorf("unsettled=%d fromBuild=%d, want 1 and 0", st.HummingbirdEpochUnsettled, st.HummingbirdEpochFromBuild)
	}
}
