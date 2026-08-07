package redhat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// Every product ID, CPE and package name below was taken from the live
// archive, not invented. The two shapes that matter most are real rows:
//
//	AppStream-9.0.0.Z.E4S:openssh-askpass-0:8.7p1-12.el9_0.1.aarch64
//	red_hat_enterprise_linux_5:mailman
//
// The first is a fix; the second is Red Hat saying a package is affected at
// every version it ships, with nothing to upgrade to.

func TestEcosystemFor(t *testing.T) {
	for _, tc := range []struct {
		cpe  string
		want string
		why  string
	}{
		// Mainline, in every repository shape the archive uses. All of them
		// collapse to the major, because that is the only key a scan can
		// derive from /etc/os-release (D47).
		{"cpe:/o:redhat:enterprise_linux:9", "Red Hat:9", "the bare form"},
		{"cpe:/o:redhat:enterprise_linux:9::baseos", "Red Hat:9", "3,974,934 entries carry the bare form, 640,398 this one"},
		{"cpe:/a:redhat:enterprise_linux:9::appstream", "Red Hat:9", "the 'a' prefix is application content, not a different product"},
		{"cpe:/a:redhat:enterprise_linux:9::crb", "Red Hat:9", ""},
		{"cpe:/o:redhat:enterprise_linux:7::server", "Red Hat:7", ""},
		{"cpe:/o:redhat:enterprise_linux:7::workstation", "Red Hat:7", ""},
		{"cpe:/o:redhat:enterprise_linux:7::computenode", "Red Hat:7", ""},
		// RHEL 10 publishes per-minor mainline CPEs. A parser written for the
		// common shape drops these silently, which is 244,865 records.
		{"cpe:/o:redhat:enterprise_linux:10", "Red Hat:10", ""},
		{"cpe:/o:redhat:enterprise_linux:10.2", "Red Hat:10", "the per-minor mainline form RHEL 10 uses"},

		// Everything else. The support channel a CPE encodes is a subscription
		// attribute with no filesystem representation, so a scan cannot know
		// which of these to pick — and matching all of them makes 29.7% of
		// groups resolve to more than one fixed version.
		{"cpe:/a:redhat:rhel_eus:9.4::appstream", "", "extended update support"},
		{"cpe:/o:redhat:rhel_eus:9.2::baseos", "", ""},
		{"cpe:/a:redhat:rhel_e4s:9.0::appstream", "", "update services for SAP"},
		{"cpe:/a:redhat:rhel_aus:8.4", "", "advanced update support"},
		{"cpe:/a:redhat:rhel_tus:8.6::appstream", "", ""},
		{"cpe:/a:redhat:rhel_extras:7", "", ""},
		{"cpe:/a:redhat:rhel_software_collections:3::el7", "", ""},

		// Unrelated products that share the namespace. A prefix match on
		// "redhat" pulls in 9,118 JBoss entries alone.
		{"cpe:/a:redhat:openstack:10::el7", "", "OpenStack is not RHEL"},
		{"cpe:/a:redhat:jboss_enterprise_application_platform:6", "", ""},
		{"cpe:/a:redhat:satellite:6::el7", "", ""},
		{"cpe:/a:redhat:ceph_storage:5", "", ""},
		{"cpe:/o:redhat:enterprise_linux_nvidia:10::el10", "", "a different product with a longer name"},
		{"cpe:/a:redhat:enterprise_linux_eus:10.0", "", "likewise, and it is NOT the mainline key"},
		{"", "", "no CPE at all"},

		// The rows that make the ANCHORS load-bearing. Every shape above is
		// rejected by an unanchored pattern too — `enterprise_linux_nvidia:` is
		// simply not `enterprise_linux:` — so without these a mutation that
		// dropped the ^ and $ survived the whole table. A trailing component
		// that is not a `::` repository is the shape that separates them, and
		// it must be refused for the same reason EUS is: it names a channel
		// this scan cannot know it is on.
		{"cpe:/o:redhat:enterprise_linux:9:beta", "", "a trailing component that is not a :: repository"},
		{"cpe:/o:redhat:enterprise_linux:9-preview", "", "a suffix on the version"},
		{"x cpe:/o:redhat:enterprise_linux:9", "", "a CPE with something before it is not a CPE"},
	} {
		got, ok := ecosystemFor(tc.cpe)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("ecosystemFor(%q) = %q, %v; want %q — %s", tc.cpe, got, ok, tc.want, tc.why)
		}
	}
}

// The name/version split, which is where "affected with no fix" is
// distinguished from "fixed in X" — the whole reason this provider exists.
func TestSplitNEVRA(t *testing.T) {
	for _, tc := range []struct{ in, name, evr, why string }{
		{"openssh-askpass-0:8.7p1-12.el9_0.1", "openssh-askpass", "0:8.7p1-12.el9_0.1",
			"the name ends at the last hyphen BEFORE the epoch colon"},
		{"openssh-0:8.7p1-38.el9_4.1", "openssh", "0:8.7p1-38.el9_4.1", ""},
		{"python3-perf-0:5.14.0-427.el9", "python3-perf", "0:5.14.0-427.el9",
			"two interior hyphens; splitting on the first gives 'python3', a different package"},
		{"nodejs-1:20.20.2-2.el9", "nodejs", "1:20.20.2-2.el9", "a non-zero epoch"},
		// The shape that carries the statement. No colon means no version,
		// which means Red Hat ships no fix.
		{"mailman", "mailman", "", "a bare name is 'affected at every version'"},
		{"compat-gcc-295", "compat-gcc-295", "", "hyphens in a bare name are part of it"},
		{"jbcs-httpd24-runtime", "jbcs-httpd24-runtime", "", ""},
	} {
		name, evr := splitNEVRA(tc.in)
		if name != tc.name || evr != tc.evr {
			t.Errorf("splitNEVRA(%q) = (%q, %q), want (%q, %q) — %s", tc.in, name, evr, tc.name, tc.evr, tc.why)
		}
	}
}

func TestStripArch(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"openssh-0:8.7p1-38.el9_4.1.x86_64", "openssh-0:8.7p1-38.el9_4.1"},
		{"openssh-0:8.7p1-38.el9_4.1.aarch64", "openssh-0:8.7p1-38.el9_4.1"},
		{"openssh-0:8.7p1-38.el9_4.1.ppc64le", "openssh-0:8.7p1-38.el9_4.1"},
		{"openssh-0:8.7p1-38.el9_4.1.s390x", "openssh-0:8.7p1-38.el9_4.1"},
		{"openssh-0:8.7p1-38.el9_4.1.src", "openssh-0:8.7p1-38.el9_4.1"},
		{"jbcs-httpd24.src", "jbcs-httpd24"},
		{"kernel-0:5.14.0-427.el9.noarch", "kernel-0:5.14.0-427.el9"},
		{"mailman", "mailman"},
		// The release string ends in something that is not an architecture.
		{"systemd-0:252-67.el9_8.4", "systemd-0:252-67.el9_8.4"},
	} {
		if got := stripArch(tc.in); got != tc.want {
			t.Errorf("stripArch(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Module builds are dropped rather than stored. The release string records the
// platform build and a context hash but NOT the stream name, so two streams of
// one module are indistinguishable — and picking either is wrong in a
// different direction.
func TestIsModule(t *testing.T) {
	for _, tc := range []struct {
		evr  string
		want bool
	}{
		{"1:20.20.2-2.module+el9.6.0+24220+c44c288d", true},
		{"0:1.19.9-1.module+el8.5.0+12236+c988d830", true},
		{"0:1.0-1.module_el8.5.0+119+9a9ec082", true}, // AlmaLinux's spelling
		{"0:8.7p1-38.el9_4.1", false},
		{"0:252-67.el9_8.4", false},
		{"", false},
	} {
		if got := isModule(tc.evr); got != tc.want {
			t.Errorf("isModule(%q) = %v, want %v", tc.evr, got, tc.want)
		}
	}
}

// buildDoc assembles a CSAF document from platform->CPE pairs and product
// status lists, in the JSON shape Red Hat actually publishes.
func buildDoc(t *testing.T, cve string, cpes map[string]string, fixed, affected []string) *document {
	t.Helper()
	type prod struct {
		ProductID string `json:"product_id"`
		Helper    struct {
			CPE string `json:"cpe"`
		} `json:"product_identification_helper"`
	}
	var kids []map[string]any
	for id, c := range cpes {
		p := prod{ProductID: id}
		p.Helper.CPE = c
		kids = append(kids, map[string]any{"category": "product_name", "name": id, "product": p})
	}
	raw := map[string]any{
		"document": map[string]any{
			"title":    "a test advisory",
			"tracking": map[string]any{"id": cve},
		},
		"product_tree": map[string]any{
			"branches": []any{map[string]any{
				"category": "vendor", "name": "Red Hat",
				"branches": []any{map[string]any{
					"category": "product_family", "name": "fam", "branches": kids,
				}},
			}},
			// Present and deliberately ignored: 2.8 MB of CVE-2024-6387's
			// 4.7 MB is relationships, and nothing here needs them.
			"relationships": []any{map[string]any{"category": "default_component_of"}},
		},
		"vulnerabilities": []any{map[string]any{
			"cve": cve,
			"product_status": map[string]any{
				"fixed":          fixed,
				"known_affected": affected,
				// The biggest list in a real document, and never read.
				"known_not_affected": []string{"red_hat_enterprise_linux_9:something-0:1-1.el9.x86_64"},
			},
			"scores": []any{map[string]any{
				"cvss_v3": map[string]any{"vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			}},
		}},
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var d document
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func affectedByName(adv advisory.Advisory) map[string]advisory.Affected {
	m := map[string]advisory.Affected{}
	for _, a := range adv.Affected {
		m[a.Ecosystem+"/"+a.Name] = a
	}
	return m
}

// The conversion, end to end, over one document carrying every shape at once.
func TestConvert(t *testing.T) {
	d := buildDoc(t, "CVE-2024-6387",
		map[string]string{
			"BaseOS-9":    "cpe:/o:redhat:enterprise_linux:9::baseos",
			"AppStream-9": "cpe:/a:redhat:enterprise_linux:9::appstream",
			"EUS-9.4":     "cpe:/a:redhat:rhel_eus:9.4::appstream",
			"JBoss":       "cpe:/a:redhat:jboss_enterprise_application_platform:6",
			"RHEL5":       "cpe:/o:redhat:enterprise_linux:5",
		},
		[]string{
			// One package, four architectures: must collapse to one range.
			"BaseOS-9:openssh-0:8.7p1-38.el9_4.1.x86_64",
			"BaseOS-9:openssh-0:8.7p1-38.el9_4.1.aarch64",
			"BaseOS-9:openssh-0:8.7p1-38.el9_4.1.ppc64le",
			"BaseOS-9:openssh-0:8.7p1-38.el9_4.1.s390x",
			// A different binary from the same source.
			"AppStream-9:openssh-askpass-0:8.7p1-38.el9_4.1.x86_64",
			// A module build: dropped.
			"AppStream-9:nodejs-1:20.20.2-2.module+el9.6.0+24220+c44c288d.x86_64",
			// Non-mainline and unrelated products: dropped.
			"EUS-9.4:openssh-0:8.7p1-12.el9_4.3.x86_64",
			"JBoss:httpd22-0:2.2.26-1.x86_64",
			// A container image: dropped.
			"BaseOS-9:rhcos@sha256:6beed8c4338c1fb80f6afc840ba00ea4e2230d22f166dd1e86e53dc4fe7fa72e_x86_64",
			// A platform this document's tree never declared.
			"Unknown-42:openssh-0:1-1.el9.x86_64",
		},
		[]string{
			// The statement this provider exists for: affected, no fix.
			"RHEL5:mailman",
			"RHEL5:compat-gcc-295",
		})

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document that names mainline RHEL packages")
	}
	if adv.ID != "CVE-2024-6387" || adv.Database != "REDHAT" || adv.Source != SourceName {
		t.Errorf("identity = %q/%q/%q", adv.ID, adv.Database, adv.Source)
	}
	// D3: a reader grepping either field for the CVE must find it.
	if len(adv.Upstream) != 1 || adv.Upstream[0] != "CVE-2024-6387" {
		t.Errorf("Upstream = %v, want the CVE", adv.Upstream)
	}
	if len(adv.Severity) != 1 || !strings.HasPrefix(adv.Severity[0].Score, "CVSS:3.1/") {
		t.Errorf("Severity = %+v, want the document's CVSS v3 vector", adv.Severity)
	}

	by := affectedByName(adv)
	if len(by) != 4 {
		t.Fatalf("produced %d affected entries, want 4: %+v", len(by), adv.Affected)
	}

	// A fix: one range, introduced-to-fixed, and ONE of them despite four
	// architectures naming the same version.
	openssh := by["Red Hat:9/openssh"]
	if len(openssh.Ranges) != 1 {
		t.Fatalf("openssh has %d ranges, want 1 — four architectures name one version", len(openssh.Ranges))
	}
	ev := openssh.Ranges[0].Events
	if len(ev) != 2 || ev[0].Introduced != "0" || ev[1].Fixed != "0:8.7p1-38.el9_4.1" {
		t.Errorf("openssh events = %+v, want introduced 0 then fixed 0:8.7p1-38.el9_4.1", ev)
	}
	if _, ok := by["Red Hat:9/openssh-askpass"]; !ok {
		t.Error("openssh-askpass was dropped; it is a separate binary package with its own advisory reach")
	}

	// Affected with no fix: an introduced event and NOTHING else. This is the
	// assertion the whole provider turns on — a fixed event here, or a dropped
	// entry, would put the record back inside what OSV can already say.
	for _, name := range []string{"mailman", "compat-gcc-295"} {
		a := by["Red Hat:5/"+name]
		if len(a.Ranges) != 1 {
			t.Fatalf("%s has %d ranges, want 1", name, len(a.Ranges))
		}
		if len(a.Ranges[0].Events) != 1 || a.Ranges[0].Events[0].Introduced != "0" {
			t.Errorf("%s events = %+v, want exactly one introduced-0 event and no fixed event", name, a.Ranges[0].Events)
		}
		if a.Ranges[0].Events[0].Fixed != "" {
			t.Errorf("%s carries a fixed version; Red Hat says there is none", name)
		}
	}

	// And every discard is counted. A provider that drops most of its input
	// silently is indistinguishable from one that is broken.
	if st.SkippedModule != 1 {
		t.Errorf("SkippedModule = %d, want 1", st.SkippedModule)
	}
	if st.SkippedNonRHEL != 2 {
		t.Errorf("SkippedNonRHEL = %d, want 2 (the EUS and JBoss entries)", st.SkippedNonRHEL)
	}
	if st.SkippedImage != 1 {
		t.Errorf("SkippedImage = %d, want 1", st.SkippedImage)
	}
	if st.SkippedNoCPE != 1 {
		t.Errorf("SkippedNoCPE = %d, want 1 (the undeclared platform)", st.SkippedNoCPE)
	}
	if st.Unfixable != 2 {
		t.Errorf("Unfixable = %d, want 2", st.Unfixable)
	}
	if st.Affected != 4 {
		t.Errorf("Affected = %d, want 4", st.Affected)
	}
}

// A package fixed on one release and unfixed on another is BOTH, and the
// record has to say so. Collapsing to one answer loses whichever is not
// chosen, and losing the unfixed half is a silent miss.
func TestConvert_FixedAndUnfixedTogether(t *testing.T) {
	d := buildDoc(t, "CVE-2024-0001",
		map[string]string{
			"RHEL9": "cpe:/o:redhat:enterprise_linux:9",
			"RHEL7": "cpe:/o:redhat:enterprise_linux:7",
		},
		[]string{"RHEL9:curl-0:7.76.1-31.el9.x86_64"},
		[]string{"RHEL7:curl"})

	var st stats
	adv, _ := convert(d, &st)
	by := affectedByName(adv)
	if got := by["Red Hat:9/curl"]; len(got.Ranges) != 1 || got.Ranges[0].Events[1].Fixed == "" {
		t.Errorf("RHEL 9 curl = %+v, want a fixed range", got.Ranges)
	}
	if got := by["Red Hat:7/curl"]; len(got.Ranges) != 1 || len(got.Ranges[0].Events) != 1 {
		t.Errorf("RHEL 7 curl = %+v, want one unfixed range", got.Ranges)
	}
}

// Two fixed versions for one (release, package) — 6.1% of mainline groups
// after modules are dropped. Both ranges are kept: taking one and discarding
// the other would report a host running the version the discarded range fixes
// as still vulnerable, or as clean when it is not.
func TestConvert_TwoFixedVersionsKeepBoth(t *testing.T) {
	d := buildDoc(t, "CVE-2024-0002",
		map[string]string{
			"BaseOS-9":    "cpe:/o:redhat:enterprise_linux:9::baseos",
			"AppStream-9": "cpe:/a:redhat:enterprise_linux:9::appstream",
		},
		[]string{
			"BaseOS-9:zlib-0:1.2.11-40.el9.x86_64",
			"AppStream-9:zlib-0:1.2.11-41.el9.x86_64",
		}, nil)

	var st stats
	adv, _ := convert(d, &st)
	a := affectedByName(adv)["Red Hat:9/zlib"]
	if len(a.Ranges) != 2 {
		t.Fatalf("zlib has %d ranges, want 2: %+v", len(a.Ranges), a.Ranges)
	}
	// Deterministic order, so two builds of one archive produce one database
	// and `db push` layers a delta rather than a rewrite.
	if a.Ranges[0].Events[1].Fixed != "0:1.2.11-40.el9" || a.Ranges[1].Events[1].Fixed != "0:1.2.11-41.el9" {
		t.Errorf("ranges are not in a stable order: %+v", a.Ranges)
	}
}

// A document naming nothing this provider ingests produces no record at all,
// rather than an advisory with an empty Affected list that the store would
// hold and nothing could ever match.
func TestConvert_DropsDocumentsWithNothingToStore(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cve   string
		cpes  map[string]string
		fixed []string
	}{
		{"only containers", "CVE-2024-0003",
			map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
			[]string{"RHEL9:rhcos@sha256:abc_x86_64"}},
		{"only other products", "CVE-2024-0004",
			map[string]string{"CEPH": "cpe:/a:redhat:ceph_storage:5"},
			[]string{"CEPH:ceph-0:1-1.x86_64"}},
		{"not a CVE id", "RHBZ-12345",
			map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
			[]string{"RHEL9:openssh-0:1-1.el9.x86_64"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var st stats
			if _, ok := convert(buildDoc(t, tc.cve, tc.cpes, tc.fixed, nil), &st); ok {
				t.Error("a document with nothing storable produced an advisory")
			}
		})
	}
}
