package suse

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/kun9497/assay/internal/pkgmeta"
)

func cmsDocument(t *testing.T, cve, pkg string, platforms, components, knownAffected, referenceURLs []string, vendorFix bool) *document {
	t.Helper()
	packages := map[string]string{}
	var recommended []string
	for i, platform := range platforms {
		if i >= len(components) {
			continue // this platform has only a bare status
		}
		build := pkg + "-" + components[i]
		packages[build] = "pkg:rpm/suse/" + pkg + "@" + components[i]
		recommended = append(recommended, platform+":"+build)
	}
	var remediations []map[string]any
	if vendorFix {
		remediations = []map[string]any{{"category": "vendor_fix", "product_ids": recommended}}
	}
	d := buildDoc(t, cve, platforms, packages, recommended, knownAffected, remediations)
	var refs []map[string]string
	for _, u := range referenceURLs {
		refs = append(refs, map[string]string{"category": "external", "url": u})
	}
	raw, err := json.Marshal(map[string]any{"document": map[string]any{"references": refs}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestCMSCompatibilityUpdateKeepsFirstSecurityFix(t *testing.T) {
	const platform = "SUSE Linux Enterprise Server 15 SP6-LTSS"
	const fixed = "3.1.4-150600.5.53.1"
	const recommended = "3.1.4-150600.5.70.1"
	refs := []string{
		"https://lists.suse.com/pipermail/sle-updates/2026-June/047322.html",
		"https://www.suse.com/support/update/announcement/2026/suse-ru-20265150-1/",
	}
	d := cmsDocument(t, "CVE-2026-34182", "libopenssl3", []string{platform}, []string{recommended}, nil, refs, true)
	a, ok := convert(d, &stats{})
	if !ok {
		t.Fatal("dropped the OpenSSL advisory")
	}
	var packages []pkgmeta.Package
	want := map[string]string{}
	for _, eco := range []string{"SLES:15.SP6", "openSUSE Leap:15.6"} {
		for installed, fix := range map[string]string{
			"3.1.4-150600.5.52.1": fixed, fixed: "", "3.1.4-150600.5.60.1": "", recommended: "",
		} {
			packages = append(packages, pkgmeta.Package{Name: "libopenssl3", Version: installed, Ecosystem: eco})
			want[eco+"/libopenssl3@"+installed] = fix
		}
	}
	if got := verdictsOf(t, a, packages...); !reflect.DeepEqual(got, want) {
		t.Fatalf("verdicts = %v, want %v", got, want)
	}
}

func TestCMSCompatibilityUpdateScope(t *testing.T) {
	const cve = "CVE-2026-34182"
	const ltss = "SUSE Linux Enterprise Server 15 SP6-LTSS"
	const leap = "openSUSE Leap 15.6"
	const earlier = "3.1.4-150600.5.53.1"
	const compat = "3.1.4-150600.5.70.1"
	const intermediate = "3.1.4-150600.5.60.1"
	const later = "3.1.4-150600.5.71.1"
	const secURL = "https://lists.suse.com/pipermail/sle-updates/2026-June/047322.html"
	const ruURL = "https://www.suse.com/support/update/announcement/2026/suse-ru-20265150-1/"
	refs := []string{secURL, ruURL}
	for _, tc := range []struct {
		name, cve       string
		platforms, evrs []string
		bare, refs      []string
		vendorFix       bool
		want            []string // fixed EVRs; empty string denotes a no-fix range
	}{
		{"unrelated CVE", "CVE-2026-34180", []string{ltss}, []string{compat}, nil, refs, true, []string{compat}},
		{"missing security notice", cve, []string{ltss}, []string{compat}, nil, []string{ruURL}, true, []string{compat}},
		{"missing compatibility notice", cve, []string{ltss}, []string{compat}, nil, []string{secURL}, true, []string{compat}},
		{"no vendor fix", cve, []string{ltss}, []string{compat}, nil, refs, false, []string{compat}},
		{"historical mixed state", cve, []string{ltss}, []string{earlier}, []string{ltss + ":libopenssl3"}, refs, true, []string{earlier, ""}},
		{"reopened", cve, []string{ltss}, []string{compat}, []string{ltss + ":libopenssl3"}, refs, true, []string{compat, ""}},
		{"reopened build", cve, []string{ltss}, []string{compat}, []string{ltss + ":libopenssl3-" + compat}, refs, true, []string{compat}},
		{"reopened build without leaf", cve, []string{ltss}, []string{compat}, []string{ltss + ":libopenssl3-" + intermediate}, refs, true, []string{compat}},
		{"other package without leaf", cve, []string{ltss}, []string{compat}, []string{ltss + ":libopenssl3-32bit-" + intermediate}, refs, true, []string{earlier}},
		{"malformed build without leaf", cve, []string{ltss}, []string{compat}, []string{ltss + ":libopenssl3-alpha-150600.5.60.1"}, refs, true, []string{earlier}},
		{"later security build", cve, []string{ltss}, []string{later}, nil, refs, true, []string{later}},
		{"both fixed builds", cve, []string{ltss, ltss}, []string{compat, later}, nil, refs, true, []string{compat, later}},
		{"unverified platform", cve, []string{"SUSE Linux Enterprise Module for Containers 15 SP6"}, []string{compat}, nil, refs, true, []string{compat}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := cmsDocument(t, tc.cve, "libopenssl3", tc.platforms, tc.evrs, tc.bare, tc.refs, tc.vendorFix)
			a, ok := convert(d, &stats{})
			if !ok {
				t.Fatal("dropped advisory")
			}
			entry, ok := affectedByName(a)["SLES:15.SP6/libopenssl3"]
			if !ok {
				t.Fatal("missing SLES:15.SP6/libopenssl3")
			}
			var got []string
			for _, r := range entry.Ranges {
				got = append(got, r.Events[len(r.Events)-1].Fixed)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("fixed bounds = %v, want %v", got, tc.want)
			}
		})
	}
	// A new native no-fix beside the SLE compatibility build keeps D128's
	// original verdict on Leap instead of importing the old security build.
	d := cmsDocument(t, cve, "libopenssl3", []string{ltss, leap}, []string{compat}, []string{leap + ":libopenssl3"}, refs, true)
	a, _ := convert(d, &stats{})
	entry := affectedByName(a)["openSUSE Leap:15.6/libopenssl3"]
	if len(entry.Ranges) != 1 || len(entry.Ranges[0].Events) != 2 || entry.Ranges[0].Events[1].Fixed != compat {
		t.Fatalf("reopened Leap range = %+v, want the original D128 fix %s", entry, compat)
	}
	for _, category := range []string{"no_fix_planned", "none_available"} {
		t.Run(category+" on Leap build without leaf", func(t *testing.T) {
			d := cmsDocument(t, cve, "libopenssl3", []string{ltss, leap}, []string{compat}, nil, refs, true)
			v := &d.Vulnerabilities[0]
			r := v.Remediations[0]
			r.Category = category
			r.ProductIDs = []string{leap + ":libopenssl3-" + intermediate}
			v.Remediations = append(v.Remediations, r)
			a, _ := convert(d, &stats{})
			pkg := pkgmeta.Package{Name: "libopenssl3", Version: intermediate, Ecosystem: "openSUSE Leap:15.6"}
			got := verdictsOf(t, a, pkg)
			if got["openSUSE Leap:15.6/libopenssl3@"+intermediate] != compat {
				t.Fatalf("verdicts = %v, want the original D128 fix %s", got, compat)
			}
		})
	}
}

func TestCMSUpdatesAreScopedToTheDocumentedProducts(t *testing.T) {
	for _, tc := range []struct {
		platform, key, pkg string
		su, ru             string
		recommended, want  string
	}{
		{"SUSE Linux Enterprise Server 15 SP4-LTSS", "SLES:15.SP4", "openssl-3",
			"sle-updates/2026-July/048426.html", "5018", "3.0.8-150400.4.104.1", "3.0.8-150400.4.90.1"},
		{"SUSE Linux Enterprise Server 15 SP5-LTSS", "SLES:15.SP5", "libopenssl3",
			"sle-updates/2026-July/048260.html", "5148", "3.0.8-150500.5.83.1", "3.0.8-150500.5.69.1"},
		{"SUSE Linux Enterprise Module for Basesystem 15 SP7", "SLES:15.SP7", "libopenssl-3-fips-provider-32bit",
			"sle-security-updates/2026-August/028617.html", "5149", "3.5.0-150700.5.56.1", "3.5.0-150700.5.45.2"},
		{"SUSE Linux Enterprise Server 15 SP7", "SLES:15.SP7", "unlisted-openssl-rpm",
			"sle-security-updates/2026-August/028617.html", "5149", "3.5.0-150700.5.56.1", "3.5.0-150700.5.56.1"},
	} {
		t.Run(tc.key+"/"+tc.pkg, func(t *testing.T) {
			refs := []string{"https://lists.suse.com/pipermail/" + tc.su,
				"https://www.suse.com/support/update/announcement/2026/suse-ru-2026" + tc.ru + "-1/"}
			d := cmsDocument(t, "CVE-2026-34182", tc.pkg, []string{tc.platform}, []string{tc.recommended}, nil, refs, true)
			a, ok := convert(d, &stats{})
			if !ok {
				t.Fatal("dropped advisory")
			}
			entry := affectedByName(a)[tc.key+"/"+tc.pkg]
			if len(entry.Ranges) != 1 || len(entry.Ranges[0].Events) != 2 || entry.Ranges[0].Events[1].Fixed != tc.want {
				t.Errorf("converted range = %+v, want fixed at %s", entry.Ranges, tc.want)
			}
		})
	}
}
