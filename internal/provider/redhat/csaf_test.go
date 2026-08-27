package redhat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/version"
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

		// D98: Project Hummingbird. The one shape measured live on the
		// 2026-08-27 archive (125 confirmed documents).
		{"cpe:/a:redhat:hummingbird:1", "Hummingbird", "the measured live shape"},
		// The trailing digit is matched, not pinned to "1" -- see
		// hummingbirdCPE's own doc comment for why a future CPE version bump
		// must still resolve the same release-less key.
		{"cpe:/a:redhat:hummingbird:2", "Hummingbird", "a hypothetical future CPE version"},
		// The anchors matter here too, the same way they matter for
		// mainlineCPE above: a name that merely shares the prefix is a
		// different product.
		{"cpe:/a:redhat:hummingbirdx:1", "", "shares a prefix but is not Hummingbird"},
		{"cpe:/a:redhat:hummingbird:1:beta", "", "a trailing component"},
		// QA round 5: the FRONT anchor specifically. hummingbirdx above tests
		// a different name; only garbage BEFORE a real hummingbird CPE
		// exercises the ^, and dropping it survived the table until this row.
		{"xcpe:/a:redhat:hummingbird:1", "", "something before the cpe is not a cpe (front anchor)"},
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
	// D90: the ID is REDHAT-prefixed so it never collides with SUSE's record
	// for the same CVE in the store's by-id bucket. The exact ID is asserted
	// (not a Contains check) because "REDHAT-CVE-2024-6387" contains
	// "CVE-2024-6387" as a substring — CLAUDE.md's substring-assertion trap.
	if adv.ID != "REDHAT-CVE-2024-6387" || adv.Database != "REDHAT" || adv.Source != SourceName {
		t.Errorf("identity = %q/%q/%q", adv.ID, adv.Database, adv.Source)
	}
	// D25 grouping runs on ID+aliases, not upstream: the bare CVE has to be
	// here for a SUSE record naming the same CVE to join this one.
	if len(adv.Aliases) != 1 || adv.Aliases[0] != "CVE-2024-6387" {
		t.Errorf("Aliases = %v, want the CVE", adv.Aliases)
	}
	if len(adv.Upstream) != 0 {
		t.Errorf("Upstream = %v, want empty -- the CVE now lives in Aliases (D90)", adv.Upstream)
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

// The module/flatpak context, and the ordering that makes it matter.
//
// Found by a differential run against grype on a real ubi9 image: assay
// reported CVE-2022-2309 against `python3`, which grype did not. Red Hat's
// document names `python3-lxml::inkscape:flatpak` — a different package, in a
// flatpak whose contents are not in the rpmdb at all — and splitNEVRA read the
// context's colon as an epoch separator, truncating the name at the hyphen
// before it.
func TestSplitContext(t *testing.T) {
	for _, tc := range []struct{ in, component, context string }{
		{"python3-lxml::inkscape:flatpak", "python3-lxml", "inkscape:flatpak"},
		{"Judy.src::mariadb:10.3", "Judy.src", "mariadb:10.3"},
		{"389-ds-base::389-directory-server:1.4", "389-ds-base", "389-directory-server:1.4"},
		{"ant-antlr::ant:1.10", "ant-antlr", "ant:1.10"},
		// A fixed entry with an epoch AND a context: the epoch colon comes
		// first, so this one parsed correctly even before the fix. It is here
		// so a change that split on the FIRST colon rather than on "::" fails.
		{"389-ds-base-0:1.4.1.3-7.module+el8.1.0+4150+5b8c2c1f.x86_64::389-directory-server:1.4",
			"389-ds-base-0:1.4.1.3-7.module+el8.1.0+4150+5b8c2c1f.x86_64", "389-directory-server:1.4"},
		// No context at all: the ordinary case, unchanged.
		{"openssh-0:8.7p1-38.el9_4.1.x86_64", "openssh-0:8.7p1-38.el9_4.1.x86_64", ""},
		{"mailman", "mailman", ""},
	} {
		comp, ctx := splitContext(tc.in)
		if comp != tc.component || ctx != tc.context {
			t.Errorf("splitContext(%q) = (%q, %q), want (%q, %q)", tc.in, comp, ctx, tc.component, tc.context)
		}
	}
}

// The original defect, re-scoped by D80: a context-scoped entry must not put
// a vulnerability on a package that only looks like its prefix. Before D80
// the fix was to drop every context-scoped entry, so the assertion was "not
// stored under the truncated name"; D80 now KEEPS the module-scoped two of
// these three, so the assertion becomes "stored under the FULL, correct
// name" for those, while the flatpak-scoped one stays dropped exactly as
// before.
func TestConvert_ModuleContextDoesNotRenameThePackage(t *testing.T) {
	d := buildDoc(t, "CVE-2022-2309",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{
			"RHEL9:python3-lxml::inkscape:flatpak",
			"RHEL9:389-ds-base::389-directory-server:1.4",
			"RHEL9:ant-antlr::ant:1.10",
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming mainline module packages")
	}
	by := affectedByName(adv)
	if len(by) != 2 {
		t.Fatalf("produced %d affected entries, want 2 (the flatpak entry stays dropped): %+v", len(by), adv.Affected)
	}
	// The names a colon-blind split would have invented. Each is a REAL
	// package, which is what made the original bug a false positive rather
	// than a harmless miss: `python3` is installed on almost every RHEL image.
	for _, wrong := range []string{"python3", "389-ds", "ant"} {
		if _, ok := by["Red Hat:9/"+wrong]; ok {
			t.Errorf("stored a finding against %q, which is a different package from the "+
				"one the advisory names", wrong)
		}
	}
	ds, ok := by["Red Hat:9/389-ds-base"]
	if !ok {
		t.Fatal("389-ds-base was dropped; it is a real module-scoped known_affected entry (D80)")
	}
	if ds.ModuleStream != "389-directory-server:1.4" {
		t.Errorf("389-ds-base ModuleStream = %q, want %q", ds.ModuleStream, "389-directory-server:1.4")
	}
	antlr, ok := by["Red Hat:9/ant-antlr"]
	if !ok {
		t.Fatal("ant-antlr was dropped; it is a real module-scoped known_affected entry (D80)")
	}
	if antlr.ModuleStream != "ant:1.10" {
		t.Errorf("ant-antlr ModuleStream = %q, want %q", antlr.ModuleStream, "ant:1.10")
	}
	if st.SkippedFlatpak != 1 {
		t.Errorf("SkippedFlatpak = %d, want 1 (python3-lxml::inkscape:flatpak)", st.SkippedFlatpak)
	}
}

// A flatpak-scoped entry alongside ordinary ones: the ordinary ones still
// land, so the exclusion drops what it should and nothing else.
func TestConvert_ContextScopedEntriesDoNotSuppressTheRest(t *testing.T) {
	d := buildDoc(t, "CVE-2024-0009",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		[]string{"RHEL9:openssh-0:8.7p1-38.el9_4.1.x86_64"},
		[]string{"RHEL9:python3-lxml::inkscape:flatpak", "RHEL9:tar"})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("the whole document was dropped")
	}
	got := affectedByName(adv)
	if len(got) != 2 {
		t.Fatalf("stored %d entries, want openssh and tar only: %+v", len(got), adv.Affected)
	}
	if _, ok := got["Red Hat:9/openssh"]; !ok {
		t.Error("the fixed openssh entry was lost")
	}
	if _, ok := got["Red Hat:9/tar"]; !ok {
		t.Error("the unscoped tar entry was lost")
	}
	if st.SkippedFlatpak != 1 {
		t.Errorf("SkippedFlatpak = %d, want 1", st.SkippedFlatpak)
	}
}

// buildDocWithRemediations is buildDoc plus a vulnerabilities[].remediations
// list. Kept separate rather than adding a parameter to buildDoc: only the
// D52 tests below need remediations, and threading an extra argument through
// every existing buildDoc call site would touch tests that have nothing to do
// with fix state.
func buildDocWithRemediations(t *testing.T, cve string, cpes map[string]string, fixed, affected []string, remediations []map[string]any) *document {
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
		},
		"vulnerabilities": []any{map[string]any{
			"cve": cve,
			"product_status": map[string]any{
				"fixed":          fixed,
				"known_affected": affected,
			},
			"remediations": remediations,
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

// D52: a known_affected package named by a no_fix_planned remediation is
// "won't fix", not merely "no fix yet" — the distinction the whole feature
// exists to make.
func TestConvert_RemediationNoFixPlanned(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1001",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:libwontfix"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libwontfix"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a mainline package")
	}
	a := affectedByName(adv)["Red Hat:9/libwontfix"]
	if len(a.Ranges) != 1 {
		t.Fatalf("libwontfix has %d ranges, want 1: %+v", len(a.Ranges), a.Ranges)
	}
	if a.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q (no_fix_planned)", a.Ranges[0].FixState, advisory.FixStateWontFix)
	}
	if st.UnfixableWontFix != 1 {
		t.Errorf("UnfixableWontFix = %d, want 1", st.UnfixableWontFix)
	}
}

// The other half of the same distinction: none_available is "no fix yet", a
// reason to keep watching the CVE rather than to stop expecting one.
func TestConvert_RemediationNoneAvailable(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1002",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:libnotfixedyet"},
		[]map[string]any{
			{"category": "none_available", "product_ids": []string{"RHEL9:libnotfixedyet"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a mainline package")
	}
	a := affectedByName(adv)["Red Hat:9/libnotfixedyet"]
	if len(a.Ranges) != 1 {
		t.Fatalf("libnotfixedyet has %d ranges, want 1: %+v", len(a.Ranges), a.Ranges)
	}
	if a.Ranges[0].FixState != advisory.FixStateNotFixed {
		t.Errorf("FixState = %q, want %q (none_available)", a.Ranges[0].FixState, advisory.FixStateNotFixed)
	}
	if st.UnfixableNotFixed != 1 {
		t.Errorf("UnfixableNotFixed = %d, want 1", st.UnfixableNotFixed)
	}
}

// Both reasons named for one package: fixStateFor's comment says the tie
// breaks toward wont-fix on purpose (a false "never" costs a reader one
// dismissed scan; a false "not yet" leaves them waiting on a fix that will
// never come). Both the resolved state and the overlap counter are asserted
// — a tie-break that resolves right but forgets to record the overlap would
// look identical on the FixState alone.
func TestConvert_RemediationBothReasons(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1003",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:libbothreasons"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libbothreasons"}},
			{"category": "none_available", "product_ids": []string{"RHEL9:libbothreasons"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a mainline package")
	}
	a := affectedByName(adv)["Red Hat:9/libbothreasons"]
	if len(a.Ranges) != 1 || a.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("Ranges = %+v, want a single range resolved to %q", a.Ranges, advisory.FixStateWontFix)
	}
	if st.UnfixableBothReasons != 1 {
		t.Errorf("UnfixableBothReasons = %d, want 1", st.UnfixableBothReasons)
	}
	// The tie-break must not also book the package under NotFixed.
	if st.UnfixableWontFix != 1 || st.UnfixableNotFixed != 0 {
		t.Errorf("UnfixableWontFix/UnfixableNotFixed = %d/%d, want 1/0", st.UnfixableWontFix, st.UnfixableNotFixed)
	}
}

// A package the product_status calls affected but no remediation explains,
// and one that only carries vendor_fix or workaround — neither of which
// answers "is there a fix" — all come out unstated rather than guessed at
// (D17's rule for absent severity, applied here to absent intent).
func TestConvert_RemediationUnstated(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1004",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:libnoremedy", "RHEL9:libvendorfixonly", "RHEL9:libworkaroundonly"},
		[]map[string]any{
			{"category": "vendor_fix", "product_ids": []string{"RHEL9:libvendorfixonly"}},
			{"category": "workaround", "product_ids": []string{"RHEL9:libworkaroundonly"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming mainline packages")
	}
	by := affectedByName(adv)
	for _, name := range []string{"libnoremedy", "libvendorfixonly", "libworkaroundonly"} {
		a := by["Red Hat:9/"+name]
		if len(a.Ranges) != 1 {
			t.Fatalf("%s has %d ranges, want 1: %+v", name, len(a.Ranges), a.Ranges)
		}
		// Resolved through String() rather than compared to "" directly: D52's
		// contract is that the empty store value and the literal "unknown" mean
		// the same thing to a reader, and this test is about the meaning, not
		// about which of the two spellings this code path happens to pick.
		if got := a.Ranges[0].FixState.String(); got != advisory.FixStateUnknown.String() {
			t.Errorf("%s FixState.String() = %q, want %q", name, got, advisory.FixStateUnknown.String())
		}
	}
	if st.UnfixableUnstated != 3 {
		t.Errorf("UnfixableUnstated = %d, want 3", st.UnfixableUnstated)
	}
}

// resolveProduct's doc comment promises that a remediation naming a product
// outside the mainline slice "is not a discard at all — it is a statement
// about something this store never held", and that counting it alongside
// product_status discards "would roughly triple every skip line for no
// gain". Each shape below is named ONLY from a remediation, never from
// product_status, so any increment on these counters can only have leaked
// out of the remediation loop.
func TestConvert_RemediationOutsideMainlineDoesNotInflateSkipped(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1005",
		map[string]string{
			"RHEL9": "cpe:/o:redhat:enterprise_linux:9",
			"EUS":   "cpe:/a:redhat:rhel_eus:9.4::appstream",
		},
		nil,
		[]string{"RHEL9:libreal"},
		[]map[string]any{
			// A non-RHEL CPE.
			{"category": "no_fix_planned", "product_ids": []string{"EUS:libeus"}},
			// A container image, identified by digest rather than a version.
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:animage@sha256:abc123_x86_64"}},
			// A flatpak-scoped id — still a genuine discard after D80, unlike
			// the module-scoped shape this test used to name here (D80 makes
			// that one resolve successfully, with a stream, so it stopped
			// testing this promise at all).
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libctx::inkscape:flatpak"}},
			// A "::" context that is not the measured name:stream shape.
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libbadctx::nocolonhere"}},
			// A platform this document's product_tree never declared.
			{"category": "no_fix_planned", "product_ids": []string{"Undeclared:libundeclared"}},
		})
	var st stats
	if _, ok := convert(d, &st); !ok {
		t.Fatal("convert dropped a document naming a mainline package")
	}
	if st.SkippedNonRHEL != 0 {
		t.Errorf("SkippedNonRHEL = %d, want 0 — only product_status discards are counted", st.SkippedNonRHEL)
	}
	if st.SkippedImage != 0 {
		t.Errorf("SkippedImage = %d, want 0", st.SkippedImage)
	}
	if st.SkippedFlatpak != 0 {
		t.Errorf("SkippedFlatpak = %d, want 0", st.SkippedFlatpak)
	}
	if st.SkippedModuleContext != 0 {
		t.Errorf("SkippedModuleContext = %d, want 0", st.SkippedModuleContext)
	}
	if st.SkippedNoCPE != 0 {
		t.Errorf("SkippedNoCPE = %d, want 0", st.SkippedNoCPE)
	}
}

// GroupIDs names a product_tree.product_groups entry Red Hat's feed has never
// used (see the GroupIDs field comment); it is counted so a feed that started
// using it would show up as a number climbing off zero. One remediation
// carries group_ids and one does not, so a mutation that counts every
// remediation — not just grouped ones — is caught by the second entry staying
// uncounted.
func TestConvert_RemediationGroupedIsCounted(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1006",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:libgrouped", "RHEL9:libungrouped"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libgrouped"}, "group_ids": []string{"G1"}},
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libungrouped"}},
		})
	var st stats
	if _, ok := convert(d, &st); !ok {
		t.Fatal("convert dropped a document naming mainline packages")
	}
	if st.RemediationGrouped != 1 {
		t.Errorf("RemediationGrouped = %d, want 1", st.RemediationGrouped)
	}
}

// D52 rides on the same fixed/unfixed split TestConvert_FixedAndUnfixedTogether
// covers: FixState is a property of the RANGE, not the package, so the fixed
// release's range must carry no FixState even though the very same package is
// won't-fix on another release.
func TestConvert_FixedAndUnfixedTogether_FixState(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1007",
		map[string]string{
			"RHEL9": "cpe:/o:redhat:enterprise_linux:9",
			"RHEL7": "cpe:/o:redhat:enterprise_linux:7",
		},
		[]string{"RHEL9:curl-0:7.76.1-31.el9.x86_64"},
		[]string{"RHEL7:curl"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"RHEL7:curl"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming mainline packages")
	}
	by := affectedByName(adv)
	fixedSide := by["Red Hat:9/curl"]
	if len(fixedSide.Ranges) != 1 || fixedSide.Ranges[0].FixState != "" {
		t.Errorf("RHEL 9 curl ranges = %+v, want one fixed range with no FixState", fixedSide.Ranges)
	}
	unfixedSide := by["Red Hat:7/curl"]
	if len(unfixedSide.Ranges) != 1 || unfixedSide.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("RHEL 7 curl ranges = %+v, want one range resolved to %q", unfixedSide.Ranges, advisory.FixStateWontFix)
	}
}

// The three D52 counters are disjoint and documented to sum to Unfixable, so
// a future change that makes one range take two paths — or forgets one —
// shows up here as a drift rather than only inside the individual counters
// asserted above.
func TestConvert_UnfixableCountersSumToTotal(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-1008",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:libsumwont", "RHEL9:libsumnotfixed", "RHEL9:libsumunstated"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"RHEL9:libsumwont"}},
			{"category": "none_available", "product_ids": []string{"RHEL9:libsumnotfixed"}},
		})
	var st stats
	if _, ok := convert(d, &st); !ok {
		t.Fatal("convert dropped a document naming mainline packages")
	}
	if st.Unfixable != 3 {
		t.Fatalf("Unfixable = %d, want 3", st.Unfixable)
	}
	if sum := st.UnfixableWontFix + st.UnfixableNotFixed + st.UnfixableUnstated; sum != st.Unfixable {
		t.Errorf("UnfixableWontFix(%d) + UnfixableNotFixed(%d) + UnfixableUnstated(%d) = %d, want Unfixable(%d)",
			st.UnfixableWontFix, st.UnfixableNotFixed, st.UnfixableUnstated, sum, st.Unfixable)
	}
}

// D80's caller-first test: a module fix's "::" context is no longer an
// unconditional drop. The fixture is a real product id from the archive —
// buildah in container-tools:rhel8, on RHEL 8.5 — chosen because deleting
// the ctx-parse call this test drives (not merely testing splitContext or
// resolveProduct in isolation) must turn it red: without the stream, this
// entry either vanishes (back to the pre-D80 unconditional drop) or lands
// under a truncated name (the pre-splitContext defect), and either way the
// assertions below fail.
func TestConvert_ModuleContextKeptWithStream(t *testing.T) {
	d := buildDoc(t, "CVE-2025-2000",
		map[string]string{"AppStream-8.5.0.GA": "cpe:/a:redhat:enterprise_linux:8::appstream"},
		[]string{
			"AppStream-8.5.0.GA:buildah-0:1.22.3-2.module+el8.5.0+12582+56d94c81.x86_64::container-tools:rhel8",
		}, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a mainline module package")
	}
	if len(adv.Affected) != 1 {
		t.Fatalf("produced %d affected entries, want 1: %+v", len(adv.Affected), adv.Affected)
	}
	a := adv.Affected[0]
	if a.Name != "buildah" {
		t.Errorf("Name = %q, want %q", a.Name, "buildah")
	}
	if a.ModuleStream != "container-tools:rhel8" {
		t.Errorf("ModuleStream = %q, want %q", a.ModuleStream, "container-tools:rhel8")
	}
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 ||
		a.Ranges[0].Events[1].Fixed != "0:1.22.3-2.module+el8.5.0+12582+56d94c81" {
		t.Errorf("Ranges = %+v, want a fixed range at %q (the full EVR, module tail included)",
			a.Ranges, "0:1.22.3-2.module+el8.5.0+12582+56d94c81")
	}
	if st.ModuleKept != 1 {
		t.Errorf("ModuleKept = %d, want 1", st.ModuleKept)
	}
}

// known_affected flows through the same fix-state machinery as an unscoped
// entry, now carrying the stream — and this is also the end-to-end check for
// the remediation-reason join: resolveProduct used to resolve every
// module-scoped id to skipModuleContext unconditionally, which the
// remediation loop reads as "not this store's product" and silently drops,
// so a won't-fix/not-fixed reason could never reach a module package. With
// D80 resolving it to skipNone (carrying the stream in the key), the same
// join that already worked for an ordinary package now reaches this one too.
func TestConvert_KnownAffectedModuleKeptWithStream(t *testing.T) {
	d := buildDocWithRemediations(t, "CVE-2025-2003",
		map[string]string{"AppStream-8": "cpe:/a:redhat:enterprise_linux:8::appstream"},
		nil,
		[]string{"AppStream-8:libmodnofix::container-tools:rhel8"},
		[]map[string]any{
			{"category": "none_available", "product_ids": []string{"AppStream-8:libmodnofix::container-tools:rhel8"}},
		})
	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a mainline module package")
	}
	a := affectedByName(adv)["Red Hat:8/libmodnofix"]
	if a.ModuleStream != "container-tools:rhel8" {
		t.Errorf("ModuleStream = %q, want %q", a.ModuleStream, "container-tools:rhel8")
	}
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 1 || a.Ranges[0].Events[0].Introduced != "0" {
		t.Fatalf("Ranges = %+v, want one introduced-0 event and no fixed event", a.Ranges)
	}
	if a.Ranges[0].Events[0].Fixed != "" {
		t.Error("libmodnofix carries a fixed version; Red Hat says there is none")
	}
	if a.Ranges[0].FixState != advisory.FixStateNotFixed {
		t.Errorf("FixState = %q, want %q — the remediation reason must reach a module-scoped package "+
			"the same way it reaches an unscoped one", a.Ranges[0].FixState, advisory.FixStateNotFixed)
	}
	if st.ModuleKept != 1 {
		t.Errorf("ModuleKept = %d, want 1", st.ModuleKept)
	}
}

// Two streams of one module land as two Affected entries, not one merged by
// name — the reason productKey now carries the stream. "nodejs:18" and
// "nodejs:20" fix on independent timelines (isModule's doc comment gives the
// real CVE-2021-20291/buildah/container-tools row that showed why merging
// them is wrong in both directions), so a document naming both streams must
// keep both, each with its own fixed EVR.
func TestConvert_TwoModuleStreamsKeptSeparately(t *testing.T) {
	d := buildDoc(t, "CVE-2025-2002",
		map[string]string{"AppStream-9": "cpe:/a:redhat:enterprise_linux:9::appstream"},
		[]string{
			"AppStream-9:nodejs-1:18.20.4-1.module+el9.6.0+11111+aaaaaaaa.x86_64::nodejs:18",
			"AppStream-9:nodejs-1:20.18.1-1.module+el9.6.0+22222+bbbbbbbb.x86_64::nodejs:20",
		}, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming mainline module packages")
	}
	if len(adv.Affected) != 2 {
		t.Fatalf("produced %d affected entries, want 2 (one per stream): %+v", len(adv.Affected), adv.Affected)
	}
	byStream := map[string]advisory.Affected{}
	for _, a := range adv.Affected {
		if a.Name != "nodejs" {
			t.Errorf("Name = %q, want %q", a.Name, "nodejs")
		}
		byStream[a.ModuleStream] = a
	}
	n18, ok18 := byStream["nodejs:18"]
	n20, ok20 := byStream["nodejs:20"]
	if !ok18 || !ok20 {
		t.Fatalf("streams present = %v, want nodejs:18 and nodejs:20: %+v", byStream, adv.Affected)
	}
	if len(n18.Ranges) != 1 || n18.Ranges[0].Events[1].Fixed != "1:18.20.4-1.module+el9.6.0+11111+aaaaaaaa" {
		t.Errorf("nodejs:18 ranges = %+v, want a fixed range at 1:18.20.4-1.module+el9.6.0+11111+aaaaaaaa", n18.Ranges)
	}
	if len(n20.Ranges) != 1 || n20.Ranges[0].Events[1].Fixed != "1:20.18.1-1.module+el9.6.0+22222+bbbbbbbb" {
		t.Errorf("nodejs:20 ranges = %+v, want a fixed range at 1:20.18.1-1.module+el9.6.0+22222+bbbbbbbb", n20.Ranges)
	}
	if st.ModuleKept != 2 {
		t.Errorf("ModuleKept = %d, want 2", st.ModuleKept)
	}
}

// Flatpak content is not in the rpmdb at all (D47), so it is excluded rather
// than treated as a module stream — "flatpak" is not a stream name, and this
// asserts the stored side of that as well as the drop: nothing in ModuleKept
// and no Affected entry carries a ModuleStream ending ":flatpak".
func TestConvert_FlatpakContextSkipped(t *testing.T) {
	d := buildDoc(t, "CVE-2022-2309",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:python3-lxml::inkscape:flatpak"})
	var st stats
	adv, ok := convert(d, &st)
	if ok {
		t.Fatalf("a document naming only a flatpak-scoped entry produced an advisory: %+v", adv.Affected)
	}
	if st.SkippedFlatpak != 1 {
		t.Errorf("SkippedFlatpak = %d, want 1", st.SkippedFlatpak)
	}
	if st.ModuleKept != 0 {
		t.Errorf("ModuleKept = %d, want 0 — a flatpak context is not a module stream", st.ModuleKept)
	}
}

// D80's load-bearing zero, re-verified after the rewrite: a module-TAGGED
// EVR (its release string carries "module+el") with NO "::" context at all
// still cannot say which stream it belongs to, and is still dropped rather
// than guessed at. Distinguished from TestConvert's existing nodejs case by
// asserting the counter under its new name and confirming ModuleKept stays
// at 0 — a mutation that let a context-less module build through would trip
// this without necessarily changing TestConvert's affected-entry count.
func TestConvert_ModuleTaggedWithoutContextStillDropped(t *testing.T) {
	d := buildDoc(t, "CVE-2025-2005",
		map[string]string{"AppStream-9": "cpe:/a:redhat:enterprise_linux:9::appstream"},
		[]string{
			"AppStream-9:nodejs-1:20.20.2-2.module+el9.6.0+24220+c44c288d.x86_64",
		}, nil)
	var st stats
	adv, ok := convert(d, &st)
	if ok {
		t.Fatalf("a document naming only a context-less module build produced an advisory: %+v", adv.Affected)
	}
	if st.SkippedModule != 1 {
		t.Errorf("SkippedModule = %d, want 1", st.SkippedModule)
	}
	if st.ModuleKept != 0 {
		t.Errorf("ModuleKept = %d, want 0", st.ModuleKept)
	}
}

// The guard for a "::" context that is not the measured shape at all — no
// colon, so it cannot be split into module and stream. Never seen on the
// real archive (100% of contexts measured parse cleanly); kept for the same
// reason isModule's zero is kept, and exercised directly here since nothing
// on today's archive reaches it.
func TestConvert_MalformedModuleContextIsDroppedAndCounted(t *testing.T) {
	d := buildDoc(t, "CVE-2025-2004",
		map[string]string{"RHEL9": "cpe:/o:redhat:enterprise_linux:9"},
		nil,
		[]string{"RHEL9:weirdpkg::nocolonhere"})
	var st stats
	adv, ok := convert(d, &st)
	if ok {
		t.Fatalf("a document naming only a malformed module context produced an advisory: %+v", adv.Affected)
	}
	if st.SkippedModuleContext != 1 {
		t.Errorf("SkippedModuleContext = %d, want 1", st.SkippedModuleContext)
	}
}

// resolveProduct directly, table-driven, the same density TestSplitNEVRA and
// TestIsModule give their helpers. Fixture package names are distinct across
// rows on purpose (D80's own substring-collision lesson): "buildah" and
// "nodejs" never appear twice, so a row cannot pass by matching another
// row's output.
func TestResolveProduct(t *testing.T) {
	cpe := map[string]string{
		"BaseOS-9":                "cpe:/o:redhat:enterprise_linux:9::baseos",
		"AppStream-8":             "cpe:/a:redhat:enterprise_linux:8::appstream",
		"EUS-9.4":                 "cpe:/a:redhat:rhel_eus:9.4::appstream",
		"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1",
	}
	// D98: the real purls TestConvert_Hummingbird* draws from, keyed the way
	// collectHummingbirdPackages would populate them.
	hbPkgs := map[string]packageInfo{
		"freetype-main@x86_64": {name: "freetype", version: "2.14.3-1.2.hum1"},
		"nodejs25.src":         {name: "nodejs25", version: ""}, // D47's bare-name convention
		// "hi/opentofu" is deliberately ABSENT: a real "pkg:oci/opentofu?..."
		// purl is never inserted here at all (hummingbirdPackageOf refuses
		// it), so its absence from this map is what a real document
		// produces, not a gap in the fixture.
	}
	for _, tc := range []struct {
		name       string
		id         string
		wantEco    string
		wantPkg    string
		wantStream string
		wantEVR    string
		wantWhy    skipReason
	}{
		{"ordinary fixed", "BaseOS-9:openssh-0:8.7p1-38.el9_4.1.x86_64",
			"Red Hat:9", "openssh", "", "0:8.7p1-38.el9_4.1", skipNone},
		{"ordinary known_affected", "BaseOS-9:mailman",
			"Red Hat:9", "mailman", "", "", skipNone},
		{"module fixed with context", "AppStream-8:buildah-0:1.22.3-2.module+el8.5.0+12582+56d94c81.x86_64::container-tools:rhel8",
			"Red Hat:8", "buildah", "container-tools:rhel8", "0:1.22.3-2.module+el8.5.0+12582+56d94c81", skipNone},
		{"module known_affected with context", "AppStream-8:libmodnofix::container-tools:rhel8",
			"Red Hat:8", "libmodnofix", "container-tools:rhel8", "", skipNone},
		{"flatpak context", "BaseOS-9:python3-lxml::inkscape:flatpak",
			"", "", "", "", skipFlatpak},
		{"malformed context, no colon", "BaseOS-9:weirdpkg::nocolonhere",
			"", "", "", "", skipModuleContext},
		{"module-tagged EVR, no context", "AppStream-8:nodejs-1:20.20.2-2.module+el9.6.0+24220+c44c288d.x86_64",
			"", "", "", "", skipModule},
		{"non-mainline CPE", "EUS-9.4:openssh-0:8.7p1-12.el9_4.3.x86_64",
			"", "", "", "", skipNonRHEL},
		{"container image", "BaseOS-9:rhcos@sha256:abc_x86_64",
			"", "", "", "", skipImage},
		{"whole product, no separator", "Red Hat Enterprise Linux 5",
			"", "", "", "", skipWholeProduct},
		{"no CPE for platform", "Undeclared-9:openssh-0:1-1.el9.x86_64",
			"", "", "", "", skipNoCPE},

		// D98: Project Hummingbird. The component is a stream label, not an
		// NEVRA, so the name and version come from hbPkgs (the purl-derived
		// map), never from splitContext/splitNEVRA.
		{"hummingbird fixed, versioned purl", "Red Hat Hardened Images:freetype-main@x86_64",
			"Hummingbird", "freetype", "", "2.14.3-1.2.hum1", skipNone},
		{"hummingbird known_affected, bare purl (D47)", "Red Hat Hardened Images:nodejs25.src",
			"Hummingbird", "nodejs25", "", "", skipNone},
		{"hummingbird component with no matching purl leaf", "Red Hat Hardened Images:hi/opentofu",
			"", "", "", "", skipNoPurl},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, evr, why := resolveProduct(tc.id, cpe, hbPkgs)
			if why != tc.wantWhy {
				t.Fatalf("resolveProduct(%q) skipReason = %v, want %v", tc.id, why, tc.wantWhy)
			}
			if why != skipNone {
				return
			}
			if k.eco != tc.wantEco || k.pkg != tc.wantPkg || k.stream != tc.wantStream || evr != tc.wantEVR {
				t.Errorf("resolveProduct(%q) = (%+v, %q), want eco=%q pkg=%q stream=%q evr=%q",
					tc.id, k, evr, tc.wantEco, tc.wantPkg, tc.wantStream, tc.wantEVR)
			}
		})
	}
}

// buildHummingbirdDoc extends buildDoc with product-tree leaves carrying
// purls (D98): the shape a Hummingbird package's real name and version live
// in, since its product id is a stream label rather than an NEVRA. purls
// maps a product-tree leaf's product id to its purl string; cpes and the
// fixed/known_affected/remediations arguments are otherwise identical to
// buildDoc's and buildDocWithRemediations', so one document can carry both
// mainline RHEL and Hummingbird content side by side (both are just
// "platform:component" strings -- only resolveProduct's own CPE-driven
// branch tells them apart).
func buildHummingbirdDoc(t *testing.T, cve string, cpes, purls map[string]string,
	fixed, affected []string, remediations []map[string]any) *document {
	t.Helper()
	type prod struct {
		ProductID string `json:"product_id"`
		Helper    struct {
			CPE  string `json:"cpe"`
			Purl string `json:"purl"`
		} `json:"product_identification_helper"`
	}
	var kids []map[string]any
	for id, c := range cpes {
		p := prod{ProductID: id}
		p.Helper.CPE = c
		kids = append(kids, map[string]any{"category": "product_name", "name": id, "product": p})
	}
	for id, purl := range purls {
		p := prod{ProductID: id}
		p.Helper.Purl = purl
		kids = append(kids, map[string]any{"category": "product_version", "name": id, "product": p})
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
		},
		"vulnerabilities": []any{map[string]any{
			"cve": cve,
			"product_status": map[string]any{
				"fixed":          fixed,
				"known_affected": affected,
			},
			"remediations": remediations,
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

// TestConvert_HummingbirdFixed is D98's caller-first proof: convert() itself
// -- not resolveProduct or hummingbirdPackageOf in isolation -- must read a
// Hummingbird purl and produce a Hummingbird-ecosystem Affected entry.
// Deleting the eco == hummingbirdEcosystem branch this test drives (back to
// always running splitContext/splitNEVRA) turns this red: "freetype-main"
// has no epoch colon for splitNEVRA to find, so the whole component would be
// read as a bare name called "freetype-main@x86_64", not "freetype".
//
// The purl is real, trimmed from cve-2026-50811.json.
func TestConvert_HummingbirdFixed(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2026-50811",
		map[string]string{"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1"},
		map[string]string{
			"freetype-main@x86_64": "pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
		},
		[]string{"Red Hat Hardened Images:freetype-main@x86_64"},
		nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a Hummingbird package")
	}
	by := affectedByName(adv)
	a, ok := by["Hummingbird/freetype"]
	if !ok {
		t.Fatalf("no Hummingbird/freetype entry, got: %+v", adv.Affected)
	}
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 ||
		a.Ranges[0].Events[0].Introduced != "0" || a.Ranges[0].Events[1].Fixed != "2.14.3-1.2.hum1" {
		t.Errorf("freetype ranges = %+v, want introduced 0 then fixed 2.14.3-1.2.hum1", a.Ranges)
	}
}

// TestConvert_HummingbirdStreamLabelFansOutToTwoPackages is the shape D98's
// whole purl-based path exists for: "perl-main" is a STREAM LABEL, and its
// two architecture-scoped ids resolve to two DIFFERENT real packages
// (perl-main@noarch ships perl-Attribute-Handlers, not perl) -- not one
// package fixed at two architectures the way mainline's stripArch/splitNEVRA
// path would collapse them. Real purls, trimmed from cve-2017-12837.json.
func TestConvert_HummingbirdStreamLabelFansOutToTwoPackages(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2017-12837",
		map[string]string{"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1"},
		map[string]string{
			"perl-main@x86_64": "pkg:rpm/redhat/perl@5.42.2-524.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
			"perl-main@noarch": "pkg:rpm/redhat/perl-Attribute-Handlers@1.03-524.hum1?arch=noarch&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
		},
		[]string{
			"Red Hat Hardened Images:perl-main@x86_64",
			"Red Hat Hardened Images:perl-main@noarch",
		},
		nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming Hummingbird packages")
	}
	by := affectedByName(adv)
	if len(by) != 2 {
		t.Fatalf("produced %d affected entries, want 2 (one per real package): %+v", len(by), adv.Affected)
	}
	perl, ok := by["Hummingbird/perl"]
	if !ok || len(perl.Ranges) != 1 || perl.Ranges[0].Events[1].Fixed != "5.42.2-524.hum1" {
		t.Errorf("Hummingbird/perl = %+v, want a fixed range at 5.42.2-524.hum1", perl.Ranges)
	}
	handlers, ok := by["Hummingbird/perl-Attribute-Handlers"]
	if !ok || len(handlers.Ranges) != 1 || handlers.Ranges[0].Events[1].Fixed != "1.03-524.hum1" {
		t.Errorf("Hummingbird/perl-Attribute-Handlers = %+v, want a fixed range at 1.03-524.hum1", handlers.Ranges)
	}
	// The stream label itself must never surface as a package name -- that
	// would be the pre-D98 mainline path misreading it as an NEVRA.
	if _, ok := by["Hummingbird/perl-main"]; ok {
		t.Error("stored a finding against \"perl-main\", which is the stream label, not a real package")
	}
}

// TestConvert_HummingbirdBareNamePurl_WontFix covers two D98 facts at once
// with one real fixture, trimmed from cve-2026-8723.json: 11 of 544 measured
// Hummingbird purls carry no version at all (D47's "affected at every
// version" convention, read here off a purl rather than a bare NEVRA
// string), and the underscore platform spelling ("red_hat_hardened_images")
// resolves exactly like the space-separated one, because ecosystemFor keys
// on the CPE, not the label.
func TestConvert_HummingbirdBareNamePurl_WontFix(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2026-8723",
		map[string]string{"red_hat_hardened_images": "cpe:/a:redhat:hummingbird:1"},
		map[string]string{
			"nodejs25.src": "pkg:rpm/redhat/nodejs25?arch=src",
		},
		nil,
		[]string{"red_hat_hardened_images:nodejs25.src"},
		[]map[string]any{
			{"category": "no_fix_planned", "product_ids": []string{"red_hat_hardened_images:nodejs25.src"}},
		})

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a Hummingbird package")
	}
	a, ok := affectedByName(adv)["Hummingbird/nodejs25"]
	if !ok {
		t.Fatalf("no Hummingbird/nodejs25 entry, got: %+v", adv.Affected)
	}
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 1 || a.Ranges[0].Events[0].Introduced != "0" {
		t.Fatalf("nodejs25 ranges = %+v, want one introduced-0 event and no fixed event", a.Ranges)
	}
	if a.Ranges[0].Events[0].Fixed != "" {
		t.Error("nodejs25 carries a fixed version; the bare purl says there is none")
	}
	if a.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("FixState = %q, want %q (no_fix_planned)", a.Ranges[0].FixState, advisory.FixStateWontFix)
	}
}

// TestConvert_HummingbirdRemediationNoneAvailable is the other D52 state,
// checked against Hummingbird's own path the same way
// TestConvert_RemediationNoneAvailable checks it against mainline's.
func TestConvert_HummingbirdRemediationNoneAvailable(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2026-9001",
		map[string]string{"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1"},
		map[string]string{
			"cups-main@x86_64": "pkg:rpm/redhat/cups@2.4.11-3.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
		},
		nil,
		[]string{"Red Hat Hardened Images:cups-main@x86_64"},
		[]map[string]any{
			{"category": "none_available", "product_ids": []string{"Red Hat Hardened Images:cups-main@x86_64"}},
		})

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a Hummingbird package")
	}
	a, ok := affectedByName(adv)["Hummingbird/cups"]
	if !ok {
		t.Fatalf("no Hummingbird/cups entry, got: %+v", adv.Affected)
	}
	if a.Ranges[0].FixState != advisory.FixStateNotFixed {
		t.Errorf("FixState = %q, want %q (none_available)", a.Ranges[0].FixState, advisory.FixStateNotFixed)
	}
}

// TestConvert_HummingbirdBothPlatformSpellingsResolve pins the adversarial
// shape measured live IN A SINGLE DOCUMENT (cve-2026-8723.json declares both
// "red_hat_hardened_images" and "Red Hat Hardened Images" as sibling
// product_name nodes carrying the identical CPE): a scan must never depend
// on which spelling a given document happened to use, because ecosystemFor
// keys on the CPE alone. Each spelling here names a DIFFERENT real package,
// so a row silently failing to resolve is distinguishable from one that
// merely collided with the other.
func TestConvert_HummingbirdBothPlatformSpellingsResolve(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2026-9002",
		map[string]string{
			"red_hat_hardened_images": "cpe:/a:redhat:hummingbird:1",
			"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1",
		},
		map[string]string{
			"nodejs25.src":     "pkg:rpm/redhat/nodejs25?arch=src",
			"cups-main@x86_64": "pkg:rpm/redhat/cups@2.4.11-3.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
		},
		[]string{"Red Hat Hardened Images:cups-main@x86_64"},
		[]string{"red_hat_hardened_images:nodejs25.src"},
		nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming Hummingbird packages under both platform spellings")
	}
	by := affectedByName(adv)
	if _, ok := by["Hummingbird/nodejs25"]; !ok {
		t.Errorf("the underscore spelling did not resolve: %+v", adv.Affected)
	}
	if _, ok := by["Hummingbird/cups"]; !ok {
		t.Errorf("the space-separated spelling did not resolve: %+v", adv.Affected)
	}
	if st.SkippedNoCPE != 0 || st.SkippedNonRHEL != 0 {
		t.Errorf("SkippedNoCPE=%d SkippedNonRHEL=%d, want 0/0 -- both spellings share the same CPE",
			st.SkippedNoCPE, st.SkippedNonRHEL)
	}
}

// TestConvert_MainlineAndHummingbirdSameCVE is D98's proof of the D90 hazard:
// a CVE affecting both RHEL mainline and Hummingbird must produce ONE record
// with affected entries under BOTH ecosystem keys, never two records with
// the same ID (which would be a last-writer-wins collision against the
// store's own by-id bucket). No new merge code makes this true -- one CSAF
// document is one CVE (convert's own doc comment), and both ecosystems'
// entries already land in the same document's product_status arrays, so
// they fall into the same adv.Affected slice for free. This test is what
// proves that stays true now that resolveProduct branches on eco: the
// mainline entry must be unaffected by the branch existing at all, alongside
// the Hummingbird one landing correctly.
func TestConvert_MainlineAndHummingbirdSameCVE(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2026-9003",
		map[string]string{
			"BaseOS-9":                "cpe:/o:redhat:enterprise_linux:9::baseos",
			"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1",
		},
		map[string]string{
			"openssh-main@x86_64": "pkg:rpm/redhat/openssh@9.9p2-3.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
		},
		[]string{
			"BaseOS-9:openssh-0:8.7p1-38.el9_4.1.x86_64",
			"Red Hat Hardened Images:openssh-main@x86_64",
		},
		nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming mainline and Hummingbird packages")
	}
	// D90: exactly one record for this CVE.
	if adv.ID != "REDHAT-CVE-2026-9003" {
		t.Errorf("ID = %q, want a single REDHAT-CVE-2026-9003 record", adv.ID)
	}
	by := affectedByName(adv)
	if len(by) != 2 {
		t.Fatalf("produced %d affected entries, want 2 (one per ecosystem): %+v", len(by), adv.Affected)
	}
	mainline, ok := by["Red Hat:9/openssh"]
	if !ok || len(mainline.Ranges) != 1 || mainline.Ranges[0].Events[1].Fixed != "0:8.7p1-38.el9_4.1" {
		t.Errorf("Red Hat:9/openssh = %+v, want a fixed range at 0:8.7p1-38.el9_4.1", mainline.Ranges)
	}
	hummingbird, ok := by["Hummingbird/openssh"]
	if !ok || len(hummingbird.Ranges) != 1 || hummingbird.Ranges[0].Events[1].Fixed != "9.9p2-3.hum1" {
		t.Errorf("Hummingbird/openssh = %+v, want a fixed range at 9.9p2-3.hum1", hummingbird.Ranges)
	}
}

// TestHummingbirdPackageOf is the unit-level table for the helper the tests
// above already drive through convert(). Fixture purls are real, sampled
// from the archive; the rejected shapes are real too (measured live: an OCI
// purl names a container image, and there is no measured malformed purl
// shape on the archive at all -- unlike SUSE's csaf.go, which measured 28
// stray leaves, D98's own measurement found 0 of 544 sampled purls failing
// to parse).
func TestHummingbirdPackageOf(t *testing.T) {
	for _, tc := range []struct {
		purl          string
		name, version string
		ok            bool
	}{
		{"pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
			"freetype", "2.14.3-1.2.hum1", true},
		{"pkg:rpm/redhat/perl-Attribute-Handlers@1.03-524.hum1?arch=noarch&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
			"perl-Attribute-Handlers", "1.03-524.hum1", true},
		// D47's bare-name convention, read off a purl with no "@" at all.
		{"pkg:rpm/redhat/nodejs25?arch=src", "nodejs25", "", true},
		{"pkg:rpm/redhat/opentofu1.10?arch=src", "opentofu1.10", "", true},
		// Not an rpm at all -- an OCI image reference.
		{"pkg:oci/opentofu?repository_url=registry.redhat.io/hi/opentofu", "", "", false},
		// Not Hummingbird's namespace.
		{"pkg:rpm/suse/xz@5.6.2-1.1", "", "", false},
		{"", "", "", false},
		// QA round 5: the FRONT anchor. A real redhat purl with anything
		// before it must not match -- dropping the ^ on hummingbirdPurlRE
		// survived the table until this row (every other reject fails because
		// it lacks the substring entirely, not because of anchoring).
		{"junk pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?arch=x86_64", "", "", false},
	} {
		name, version, ok := hummingbirdPackageOf(tc.purl)
		if name != tc.name || version != tc.version || ok != tc.ok {
			t.Errorf("hummingbirdPackageOf(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.purl, name, version, ok, tc.name, tc.version, tc.ok)
		}
	}
}

// TestEcosystemAgreesWithCataloger_Hummingbird is D98's byte-for-byte
// cross-check, the same discipline D77's TestKeyAgreesWithCataloger holds
// for SLES's fold: distro.go (internal/pkgmeta) derives "Hummingbird" from
// /etc/os-release alone, this package derives it from the CPE, and the two
// are computed by completely independent code. A mismatch is silent -- both
// sides would still produce a plausible-looking string, and only a scan
// finding nothing stored under one of them would ever reveal the drift.
func TestEcosystemAgreesWithCataloger_Hummingbird(t *testing.T) {
	catalogerKey, err := (pkgmeta.Distro{ID: "hummingbird", VersionID: "20251124"}).Ecosystem()
	if err != nil {
		t.Fatalf("pkgmeta.Distro.Ecosystem() = %v, want a resolved key", err)
	}
	providerKey, ok := ecosystemFor("cpe:/a:redhat:hummingbird:1")
	if !ok {
		t.Fatal("ecosystemFor refused the real, live Hummingbird CPE")
	}
	if catalogerKey != providerKey {
		t.Errorf("cataloger key %q != provider key %q -- a SCAN would look up one string "+
			"and the DATABASE would hold the other, reporting clean with no error at all",
			catalogerKey, providerKey)
	}
	if _, ok := version.For(catalogerKey); !ok {
		t.Errorf("version.For(%q) has no comparer -- the matcher could never evaluate a "+
			"Hummingbird package even if the lookup found something", catalogerKey)
	}
}

// TestConvert_HummingbirdMissingPurlIsCountedNotSilent is the QA-round-5
// close for the SkippedNoPurl counter (D98). resolveProduct returning
// skipNoPurl is unit-tested directly, but that path bypasses convert's own
// stats entirely, so dropping the `st.SkippedNoPurl++` inside convert's add
// closure left every test green. Here a product_status names a Hummingbird
// component whose id has NO matching purl leaf in the product tree: it must
// produce no affected entry AND register in the count, not vanish silently.
func TestConvert_HummingbirdMissingPurlIsCountedNotSilent(t *testing.T) {
	d := buildHummingbirdDoc(t, "CVE-2099-40001",
		map[string]string{"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1"},
		// One resolvable purl leaf...
		map[string]string{
			"freetype-main@x86_64": "pkg:rpm/redhat/freetype@2.14.3-1.2.hum1?arch=x86_64&distro=hummingbird-20251124&repository_id=public-hummingbird-x86_64-rpms",
		},
		// ...but product_status names TWO components, the second with no leaf.
		[]string{
			"Red Hat Hardened Images:freetype-main@x86_64",
			"Red Hat Hardened Images:ghost-main@x86_64",
		},
		nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped a document naming a resolvable Hummingbird package")
	}
	if _, present := affectedByName(adv)["Hummingbird/ghost-main"]; present {
		t.Error("the purl-less component produced an affected entry; it should have been skipped")
	}
	if st.SkippedNoPurl != 1 {
		t.Errorf("SkippedNoPurl = %d, want 1 — a component with no purl leaf must be counted, not silently dropped", st.SkippedNoPurl)
	}
}
