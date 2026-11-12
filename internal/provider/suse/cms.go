package suse

import (
	"slices"
	"strings"
)

// For CVE-2026-34182 these four security updates shipped the OpenSSL CMS
// fix. The later recommended updates added an optional compatibility setting
// for that fix. CSAF VEX revision 32 points at the later builds. Use the
// security boundary only for the products and RPMs in both announcements.
type cmsUpdate struct {
	securityURL, compatibilityURL string
	firstFix, recommended         string
	platforms, packages           []string
}

var cmsUpdates = []cmsUpdate{
	{
		securityURL:      "https://lists.suse.com/pipermail/sle-updates/2026-July/048426.html",
		compatibilityURL: "https://www.suse.com/support/update/announcement/2026/suse-ru-20265018-1/",
		firstFix:         "3.0.8-150400.4.90.1", recommended: "3.0.8-150400.4.104.1",
		platforms: []string{"SUSE Linux Enterprise Server 15 SP4-LTSS", "openSUSE Leap 15.4"},
		packages:  []string{"libopenssl-3-devel", "libopenssl3", "openssl-3"},
	},
	{
		securityURL:      "https://lists.suse.com/pipermail/sle-updates/2026-July/048260.html",
		compatibilityURL: "https://www.suse.com/support/update/announcement/2026/suse-ru-20265148-1/",
		firstFix:         "3.0.8-150500.5.69.1", recommended: "3.0.8-150500.5.83.1",
		platforms: []string{"SUSE Linux Enterprise Server 15 SP5-LTSS", "openSUSE Leap 15.5"},
		packages:  []string{"libopenssl-3-devel", "libopenssl3", "openssl-3"},
	},
	{
		securityURL:      "https://lists.suse.com/pipermail/sle-updates/2026-June/047322.html",
		compatibilityURL: "https://www.suse.com/support/update/announcement/2026/suse-ru-20265150-1/",
		firstFix:         "3.1.4-150600.5.53.1", recommended: "3.1.4-150600.5.70.1",
		platforms: []string{"SUSE Linux Enterprise Server 15 SP6-LTSS", "openSUSE Leap 15.6"},
		packages:  []string{"libopenssl-3-devel", "libopenssl-3-fips-provider", "libopenssl-3-fips-provider-32bit", "libopenssl3", "libopenssl3-32bit", "openssl-3"},
	},
	{
		securityURL:      "https://lists.suse.com/pipermail/sle-security-updates/2026-August/028617.html",
		compatibilityURL: "https://www.suse.com/support/update/announcement/2026/suse-ru-20265149-1/",
		firstFix:         "3.5.0-150700.5.45.2", recommended: "3.5.0-150700.5.56.1",
		platforms: []string{"SUSE Linux Enterprise Server 15 SP7", "SUSE Linux Enterprise Module for Basesystem 15 SP7"},
		packages:  []string{"libopenssl-3-devel", "libopenssl-3-fips-provider", "libopenssl-3-fips-provider-32bit", "libopenssl3", "libopenssl3-32bit", "openssl-3"},
	},
}

func applyCMSFixBoundaries(d *document, folded map[string]string, packages map[string]packageInfo,
	fixed map[productKey]map[string]bool, unfixed map[productKey]bool, splitBuild map[productKey]map[string]bool) {
	if len(d.Vulnerabilities) != 1 || d.Vulnerabilities[0].CVE != "CVE-2026-34182" {
		return
	}
	references := map[string]bool{}
	for _, ref := range d.Document.References {
		references[ref.URL] = true
	}
	byPlatform := map[string]cmsUpdate{}
	for _, update := range cmsUpdates {
		if references[update.securityURL] && references[update.compatibilityURL] {
			for _, platform := range update.platforms {
				byPlatform[platform] = update
			}
		}
	}
	v := &d.Vulnerabilities[0]
	// Keep explicit no-fix evidence even if D91 or D149 would otherwise
	// shadow the raw product once multiple platforms fold to the same key.
	reopened := map[productKey]bool{}
	noteReopened := func(id string) {
		platform, pkg, _ := strings.Cut(id, ":")
		reopened[productKey{eco: folded[platform], pkg: pkg}] = true
		if p := packages[pkg]; p.version != "" && pkg == p.name+"-"+p.version {
			reopened[productKey{eco: folded[platform], pkg: p.name}] = true
		} else if name, _, ok := splitNEVR(pkg); ok {
			// A build-shaped status can lack a usable package leaf. Its RPM
			// name only vetoes this correction for the matching product. D126
			// and D159 still choose how to store the original status.
			reopened[productKey{eco: folded[platform], pkg: name}] = true
		}
	}
	for _, id := range v.ProductStatus.KnownAffected {
		noteReopened(id)
	}
	vendorFix := map[string]bool{}
	for _, r := range v.Remediations {
		for _, id := range r.ProductIDs {
			switch r.Category {
			case "vendor_fix":
				vendorFix[id] = true
			case remedyNoFixPlanned, remedyNoneAvailable:
				noteReopened(id)
			}
		}
	}
	candidates := map[productKey]cmsUpdate{}
	other := map[productKey]bool{}
	for _, id := range v.ProductStatus.Recommended {
		platform, component, _ := strings.Cut(id, ":")
		p := packages[component]
		k := productKey{eco: folded[platform], pkg: p.name}
		update, ok := byPlatform[platform]
		if !ok || !vendorFix[id] || p.version != update.recommended ||
			component != p.name+"-"+update.recommended || !slices.Contains(update.packages, p.name) {
			other[k] = true
			continue
		}
		candidates[k] = update
	}
	for k, update := range candidates {
		versions := fixed[k]
		if other[k] || len(versions) != 1 || !versions[update.recommended] ||
			unfixed[k] || reopened[k] || len(splitBuild[k]) != 0 {
			continue
		}
		// D128 can replace a native Leap no-fix with the SLE bounds. Preserve
		// that verdict when the document explicitly reopens the Leap package.
		if leap, ok := leapMirrorKey(k.eco); ok {
			twin := productKey{eco: leap, pkg: k.pkg}
			if unfixed[twin] || reopened[twin] {
				continue
			}
		}
		delete(versions, update.recommended)
		versions[update.firstFix] = true
	}
}
