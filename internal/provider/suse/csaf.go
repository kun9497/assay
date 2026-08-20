// This file holds the CSAF document shape and the D77-specific parsing this
// provider needs on top of redhat's shared shape (D47's product-tree walk,
// D52's remediation-category split): SUSE's own product tree, the per-module
// key fold, and the package name/version split.
//
// The product tree itself has a different shape from Red Hat's. Red Hat's
// product_status entries spell "platform:component-EVR" directly, with the
// platform's CPE living on a branch and the component parsed by splitting
// hyphens and colons (splitContext, splitNEVRA). SUSE's feed instead gives
// every package a purl at the leaf ("pkg:rpm/suse/xz@5.6.2-1.1?..."), so the
// name/version split is read structurally rather than guessed from a string
// that would otherwise be ambiguous -- "liblzma5-x86-64-v3-5.8.1-160000.2.2"
// has no reliable hyphen boundary of its own. Measured across the whole
// 2026-08-19 archive: 100% of 657,984 sampled leaf purls match this shape
// and reconstruct their own product_id exactly; the tiny remainder (28 of
// 657,984, all pre-2014 java-1_7_0-openjdk entries) are counted and skipped
// rather than parsed out of the raw id.
//
// SUSE also has no module/flatpak "::" context to split off first the way
// Red Hat's splitContext does (D47's own hazard): every product_status
// entry sampled (8,525 of them, live 2026-08-19) carries EXACTLY one colon,
// so a plain strings.Cut on the first colon is the whole split.
package suse

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// document is the subset of one CSAF VEX document this provider reads.
//
// Deliberately narrow for the same memory reason redhat.document is: the
// full corpus is 63,784 documents and this provider never holds more than
// one at a time, un-parsed relationships and known_not_affected included.
// SUSE's product_tree.relationships is not read at all -- every fact this
// provider needs (which platform, which package, which version) is already
// on the flat branch list and does not require walking the relationship
// table Red Hat's shape has to.
type document struct {
	Document struct {
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
		Title string `json:"title"`
	} `json:"document"`
	ProductTree struct {
		Branches []branch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE           string `json:"cve"`
		ProductStatus struct {
			// Recommended is SUSE's spelling of "fixed" -- verified against
			// the live feed (cve-2024-3094.json): every id here is also named
			// by a remediations[category=="vendor_fix"] entry, and every id
			// always carries a specific version, never a bare package name.
			// SUSE does not use CSAF's "fixed" bucket at all (measured across
			// the whole archive: 12,788,194 recommended entries against 18
			// stray "fixed"-keyed ones, almost certainly hand-authored typos
			// in pre-2005 documents that this parser silently does not read,
			// the same way a misspelled JSON key always is).
			Recommended []string `json:"recommended"`
			// KnownAffected is D48's shape: a package SUSE says is affected
			// with nothing named for the caller to upgrade to. 7,072,476
			// entries measured across the whole archive -- this is not a
			// rare case, it is the majority of what this feed says.
			KnownAffected []string `json:"known_affected"`
			// known_not_affected, first_affected, last_affected and
			// under_investigation are read by nothing here, mirroring
			// redhat.document's own known_not_affected omission: nothing
			// downstream can use a not-affected or under-investigation claim,
			// and first/last_affected describe a range this store's
			// introduced-at-0 shape does not need.
		} `json:"product_status"`
		// Remediations is what makes D52's distinction possible here too:
		// product_status says a package is affected, only this says whether
		// SUSE intends to do anything about it.
		Remediations []struct {
			Category   string   `json:"category"`
			ProductIDs []string `json:"product_ids"`
		} `json:"remediations"`
		Scores []struct {
			CVSSv3 struct {
				VectorString string `json:"vectorString"`
			} `json:"cvss_v3"`
			CVSSv4 struct {
				VectorString string `json:"vectorString"`
			} `json:"cvss_v4"`
		} `json:"scores"`
	} `json:"vulnerabilities"`
}

// branch is one product_tree node. Category distinguishes a PLATFORM
// ("product_name": "SUSE Linux Enterprise Server 15 SP6", "openSUSE Leap
// 15.6", "openSUSE Tumbleweed") from a PACKAGE ("product_version": both the
// bare "xz" and the version-specific "xz-5.6.2-1.1" are this category on
// SUSE's tree, unlike a platform's own children on Red Hat's). Both carry a
// product_identification_helper.cpe on SUSE's feed -- verified live, e.g.
// the bare "xz" node carries "cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*" -- so,
// unlike redhat.branch, the CPE is never read here: collecting it the way
// redhat.collectCPE does would just as happily collect a PACKAGE's CPE as a
// platform's, and Category is what actually distinguishes them.
type branch struct {
	Category string   `json:"category"`
	Branches []branch `json:"branches"`
	Product  *struct {
		ProductID string `json:"product_id"`
		Helper    struct {
			Purl string `json:"purl"`
		} `json:"product_identification_helper"`
	} `json:"product"`
}

// tumbleweedName is the one product name this feed carries that must never
// resolve a key: rolling, no stable release axis (D77).
const tumbleweedName = "openSUSE Tumbleweed"

var (
	// bareSP matches SLES's bare mainline product name below major 16:
	// "SUSE Linux Enterprise Server 15" (the pre-SP1 release, no suffix at
	// all) or "... 15 SP6". Anchored, so a suffixed variant never matches --
	// LTSS, BCL, ESPOS, Teradata, "for SAP Applications"/"applications" (both
	// case variants are excluded the same way, since neither matches "Server
	// (\d+)"), "for Raspberry Pi", "Business Critical Linux" are all
	// different support channels or different products, the same hazard
	// D47's anchored mainlineCPE excludes for Red Hat's EUS/AUS/TUS/E4S.
	bareSP = regexp.MustCompile(`^SUSE Linux Enterprise Server (\d+)(?: SP(\d+))?$`)
	// bareDotted matches SLES 16 and up, which the feed spells "16.0"/"16.1"
	// with no "SPn" wording at all -- sampled from the live CSAF archive,
	// 2026-08-19 (cpe:/o:suse:sles:16:16.0:server on the "16.0" node); no
	// 16.x image has been pulled to verify os-release independently, unlike
	// 15.6's bci-base pull.
	bareDotted = regexp.MustCompile(`^SUSE Linux Enterprise Server (\d+)\.(\d+)$`)
	// moduleSP matches a per-module product name below major 16, the shape
	// that spreads one SLES release's mainline fixes over roughly twenty
	// products: "SUSE Linux Enterprise Module for Basesystem 15 SP6". Every
	// module name in the whole 2026-08-19 archive uses this "N SPm" shape;
	// none has yet used SLES 16's dotted one (measured: 16.0/16.1 carry
	// "High Availability Extension" and "for SAP applications" module-shaped
	// names, but no "Module for X 16.0" at all), so a hypothetical one is
	// COUNTED as unfoldable rather than guessed at until observed -- the
	// same trade redhat.isModule's doc comment names for a guard that fires
	// zero times on the current archive.
	moduleSP = regexp.MustCompile(`^SUSE Linux Enterprise Module for [A-Za-z0-9 ]+ (\d+)(?: SP(\d+))?$`)
	// leapName matches openSUSE Leap's product name, already the exact key
	// shape (D6's release qualifier is the whole VERSION_ID; no fold, unlike
	// SLES's module spread).
	leapName = regexp.MustCompile(`^openSUSE Leap (\d+\.\d+)$`)
	// purlRE splits a product_version leaf's purl into name and version.
	// Unlike the OSV bucket's purls (measured malformed, D77 research: every
	// one missing the '?' before its qualifiers), CSAF's are well-formed --
	// measured 100% across 657,984 sampled leaves.
	purlRE = regexp.MustCompile(`^pkg:rpm/suse/([^@]+)@([^?]*)`)
)

// foldKey folds one CSAF platform product name into this project's SLES or
// openSUSE Leap key, or reports false for a name no pattern recognizes --
// COUNTED and skipped by the caller (collectPlatforms), never guessed (D77).
//
// Measured against the whole 2026-08-19 CSAF VEX archive (63,784 documents,
// 8.14M platform-node occurrences): this folds 30 distinct keys (SLES 11
// through 16.1, openSUSE Leap 15.0 through 16.0) covering 738,191
// occurrences, and correctly refuses 808 distinct product names covering the
// other 7,404,889 -- SAP ("for SAP Applications"/"applications", both case
// variants seen live), HPC, Micro, Manager, Enterprise Storage, Teradata,
// Real Time Module, "Public Cloud Module for SUSE Linux Enterprise" (a
// DIFFERENT, older product from SLES's own "Module for Public Cloud"),
// Liberty Linux, every LTSS/BCL/ESPOS-suffixed mainline release, and
// Tumbleweed among them -- none of which shares SLES's or Leap's package set
// for the affected release.
func foldKey(name string) (string, bool) {
	if name == tumbleweedName {
		return "", false
	}
	if m := bareSP.FindStringSubmatch(name); m != nil {
		major := m[1]
		if n, err := strconv.Atoi(major); err != nil || n >= 16 {
			// SLES 16 and up never use "SPn" wording (bareDotted below is
			// what matches them); a bare "Server 16" with no minor and no SP
			// is a shape this feed has never published.
			return "", false
		}
		return slesKey(major, m[2]), true
	}
	if m := bareDotted.FindStringSubmatch(name); m != nil {
		return "SLES:" + m[1] + "." + m[2], true
	}
	if m := moduleSP.FindStringSubmatch(name); m != nil {
		return slesKey(m[1], m[2]), true
	}
	if m := leapName.FindStringSubmatch(name); m != nil {
		return "openSUSE Leap:" + m[1], true
	}
	return "", false
}

// slesKey builds "SLES:15.SP6", or "SLES:15" when sp is empty or "0" -- the
// same drop pkgmeta.Distro.Ecosystem applies to a VERSION_ID minor of "0",
// so both sides of D77's cataloger/provider split land on the identical
// string for SLES's pre-SP1 releases. This is THE point tested hardest
// (TestKeyAgreesWithCataloger): a mismatch here is silent, because a key
// nothing was ever stored under and a key that was never derived both
// report the same way -- not evaluated, never wrong-but-confident.
func slesKey(major, sp string) string {
	if sp == "" || sp == "0" {
		return "SLES:" + major
	}
	return "SLES:" + major + ".SP" + sp
}

// packageOf splits a CSAF product_version leaf's purl into a package name
// and version, or reports false. See the package doc comment for the
// measured reliability of this shape.
func packageOf(purl string) (name, version string, ok bool) {
	m := purlRE.FindStringSubmatch(purl)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

type packageInfo struct{ name, version string }

// collectPlatforms walks the product tree's "product_name" nodes -- SLES's
// and openSUSE Leap's own platforms and modules, one node per release or
// per-module product -- folding each into this project's key and counting
// the ones no pattern recognizes. declared holds every platform NAME seen
// regardless of whether it folded, which is what lets resolveProduct tell
// "this platform is real but this feed's key fold does not recognize it"
// (st.PlatformsUnfoldable) apart from "this id names no platform this
// document ever declared" (st.SkippedUnknownPlatform) -- the same split
// redhat.go's skipNonRHEL/skipNoCPE make for the identical reason.
func collectPlatforms(bs []branch, st *stats) (folded map[string]string, declared map[string]bool) {
	folded = map[string]string{}
	declared = map[string]bool{}
	var walk func([]branch)
	walk = func(bs []branch) {
		for i := range bs {
			b := &bs[i]
			if b.Category == "product_name" && b.Product != nil {
				name := b.Product.ProductID
				declared[name] = true
				if name == tumbleweedName {
					st.PlatformsTumbleweed++
				} else if key, ok := foldKey(name); ok {
					folded[name] = key
				} else {
					st.PlatformsUnfoldable++
				}
			}
			walk(b.Branches)
		}
	}
	walk(bs)
	return folded, declared
}

// collectPackages walks the product tree's "product_version" nodes -- every
// package name and package-version SUSE declared in this document,
// platform-independent -- reading each one's structured name/version off its
// purl (packageOf). A leaf with no readable purl is counted and left out of
// the map, so any product_status entry that names it is a counted skip
// rather than a guess built from the raw id string.
func collectPackages(bs []branch, st *stats) map[string]packageInfo {
	out := map[string]packageInfo{}
	var walk func([]branch)
	walk = func(bs []branch) {
		for i := range bs {
			b := &bs[i]
			if b.Category == "product_version" && b.Product != nil {
				name, version, ok := packageOf(b.Product.Helper.Purl)
				if !ok {
					st.SkippedNoPurl++
				} else {
					out[b.Product.ProductID] = packageInfo{name: name, version: version}
				}
			}
			walk(b.Branches)
		}
	}
	walk(bs)
	return out
}

// productKey is what one CSAF product id collapses to: the store's ecosystem
// and the package name inside it.
type productKey struct{ eco, pkg string }

// skipReason names why a product id yields no key. Split as finely as
// redhat.skipReason for the identical reason: a reader watching the progress
// line needs to tell "this feed's shape moved" (skipNoColon, an id with the
// wrong number of colons -- zero across 8,525 entries sampled live) apart
// from "this platform is a real product this fold does not cover"
// (skipUnfoldablePlatform, the expected, disclosed majority) apart from
// "this package's purl could not be read" (skipUnknownPackage).
type skipReason int

const (
	skipNone skipReason = iota
	skipNoColon
	skipEmptyComponent
	skipTumbleweedRef
	skipUnknownPlatform
	skipUnfoldablePlatform
	skipUnknownPackage
)

// resolveProduct turns "platform:component" into a key and a version.
//
// Exactly one colon separates the two on every entry this feed has been
// measured to publish (0 of 8,525 sampled carried zero or more than one), so
// there is no module/flatpak context to split off first the way Red Hat's
// splitContext has to before splitNEVRA runs -- D47's ordering hazard does
// not exist on this feed.
func resolveProduct(id string, folded map[string]string, declared map[string]bool,
	packages map[string]packageInfo) (productKey, string, skipReason) {

	plat, comp, ok := strings.Cut(id, ":")
	if !ok {
		return productKey{}, "", skipNoColon
	}
	if comp == "" {
		return productKey{}, "", skipEmptyComponent
	}
	if plat == tumbleweedName {
		return productKey{}, "", skipTumbleweedRef
	}
	key, ok := folded[plat]
	if !ok {
		if declared[plat] {
			return productKey{}, "", skipUnfoldablePlatform
		}
		return productKey{}, "", skipUnknownPlatform
	}
	pkg, ok := packages[comp]
	if !ok {
		return productKey{}, "", skipUnknownPackage
	}
	return productKey{eco: key, pkg: pkg.name}, pkg.version, skipNone
}

// The one remediation category SUSE's own feed has been measured to use for
// "no fix" (D52). Both of redhat.go's two are still read here -- see
// fixStateFor's doc comment for why none_available stays even though it
// currently fires zero times.
const (
	remedyNoFixPlanned  = "no_fix_planned"
	remedyNoneAvailable = "none_available"
)

// fixStateFor picks one state from the categories that named a package.
// Identical tie-break to redhat.fixStateFor (D52): no_fix_planned wins over
// none_available when a package carries both, because calling a package
// "won't fix" when a fix later arrives is a false alarm dismissed on the
// next scan, while calling it "no fix yet" when none is ever coming leaves a
// reader waiting on a fix that will never exist.
//
// Measured across the whole 2026-08-19 archive: SUSE's own remediation
// vocabulary never uses none_available -- every one of the 4,312 no-fix
// remediation objects is no_fix_planned, and 44,474 are vendor_fix. The
// none_available branch is unreached on this feed today and stays for the
// same reason redhat.isModule's zero-firing guard stays: a feed that started
// using the other spelling must be handled by data already flowing through
// this code, not rediscovered the hard way. TestFixStateFor and
// TestConvert_RemediationNoneAvailable exercise it directly.
func fixStateFor(cats map[string]bool, st *stats) advisory.FixState {
	never, pending := cats[remedyNoFixPlanned], cats[remedyNoneAvailable]
	if never && pending {
		st.UnfixableBothReasons++
	}
	switch {
	case never:
		st.UnfixableWontFix++
		return advisory.FixStateWontFix
	case pending:
		st.UnfixableNotFixed++
		return advisory.FixStateNotFixed
	default:
		st.UnfixableUnstated++
		return advisory.FixStateUnknown
	}
}

// stats counts what one conversion pass discarded, so a sync can report it.
// Mirrors redhat.stats field for field where the two providers share a
// concept, with SUSE-specific counters (Platforms*, SkippedNoPurl,
// Skipped*Colon/Component/Package) replacing Red Hat's module/context/CPE
// ones -- the two feeds discard along different lines and a single shared
// counter would hide which detection is doing the work, the same reasoning
// redhat.stats gives for keeping SkippedModule and SkippedModuleContext
// apart.
type stats struct {
	Documents  int
	Advisories int
	Affected   int
	Unfixable  int // affected entries with no fixed version at all

	// The D52 split of Unfixable, identical in meaning to redhat.stats'.
	UnfixableWontFix     int
	UnfixableNotFixed    int
	UnfixableUnstated    int
	UnfixableBothReasons int

	// PlatformsUnfoldable and PlatformsTumbleweed are counted once per
	// PRODUCT-NAME NODE (not per affected entry), because that is where
	// foldKey's decision is made -- see collectPlatforms.
	PlatformsUnfoldable int
	PlatformsTumbleweed int

	// The rest are counted once per product_status / remediation ENTRY,
	// mirroring redhat.stats' own per-entry granularity.
	SkippedNoColon            int
	SkippedEmptyComponent     int
	SkippedTumbleweedRef      int
	SkippedUnknownPlatform    int
	SkippedUnfoldablePlatform int
	SkippedUnknownPackage     int
	SkippedNoPurl             int
	SkippedNoCVE              int
	SkippedBadDoc             int

	// The delta pass (delta.go), identical in meaning to redhat.stats'.
	DeltaListed     int
	DeltaFetched    int
	DeltaGone       int
	DeltaAdvisories int
	DeltaRetried    int
	DeltaRescued    int
}

// convert turns one CSAF document into at most one advisory. One document is
// one CVE (measured: 0 of 63,784 documents in the whole archive carry more
// than one vulnerabilities[] entry), so the whole document collapses to a
// single record the same way redhat.convert's does, and D25's grouping works
// unchanged: the record's own ID is the CVE.
func convert(d *document, st *stats) (advisory.Advisory, bool) {
	st.Documents++

	folded, declared := collectPlatforms(d.ProductTree.Branches, st)
	packages := collectPackages(d.ProductTree.Branches, st)

	cve := d.Document.Tracking.ID
	if len(d.Vulnerabilities) > 0 && d.Vulnerabilities[0].CVE != "" {
		cve = d.Vulnerabilities[0].CVE
	}
	if !strings.HasPrefix(cve, "CVE-") {
		st.SkippedNoCVE++
		return advisory.Advisory{}, false
	}

	fixed := map[productKey]map[string]bool{}
	unfixed := map[productKey]bool{}
	remedy := map[productKey]map[string]bool{}
	order := []productKey{}
	seen := map[productKey]bool{}
	note := func(k productKey) {
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}

	add := func(id string, isFixed bool) {
		k, version, why := resolveProduct(id, folded, declared, packages)
		switch why {
		case skipNoColon:
			st.SkippedNoColon++
			return
		case skipEmptyComponent:
			st.SkippedEmptyComponent++
			return
		case skipTumbleweedRef:
			st.SkippedTumbleweedRef++
			return
		case skipUnknownPlatform:
			st.SkippedUnknownPlatform++
			return
		case skipUnfoldablePlatform:
			st.SkippedUnfoldablePlatform++
			return
		case skipUnknownPackage:
			st.SkippedUnknownPackage++
			return
		}
		note(k)
		if isFixed && version != "" {
			if fixed[k] == nil {
				fixed[k] = map[string]bool{}
			}
			fixed[k][version] = true
			return
		}
		// Either an explicit known_affected, or a recommended entry with no
		// version to compare against -- which says the same thing and must
		// not be dropped as malformed (mirrors redhat.convert's identical
		// fallback).
		unfixed[k] = true
	}

	var sev []advisory.Severity
	for i := range d.Vulnerabilities {
		v := &d.Vulnerabilities[i]
		for _, id := range v.ProductStatus.Recommended {
			add(id, true)
		}
		for _, id := range v.ProductStatus.KnownAffected {
			add(id, false)
		}
		for _, r := range v.Remediations {
			if r.Category != remedyNoFixPlanned && r.Category != remedyNoneAvailable {
				continue
			}
			for _, id := range r.ProductIDs {
				// Skips are not counted here, for the reason resolveProduct's
				// doc comment gives: a remediation naming a product this
				// store does not hold is not a discard, it is a statement
				// about something never stored.
				k, _, why := resolveProduct(id, folded, declared, packages)
				if why != skipNone {
					continue
				}
				if remedy[k] == nil {
					remedy[k] = map[string]bool{}
				}
				remedy[k][r.Category] = true
			}
		}
		for _, s := range v.Scores {
			if s.CVSSv4.VectorString != "" {
				sev = append(sev, advisory.Severity{Type: "CVSS_V4", Score: s.CVSSv4.VectorString})
			}
			if s.CVSSv3.VectorString != "" {
				sev = append(sev, advisory.Severity{Type: "CVSS_V3", Score: s.CVSSv3.VectorString})
			}
		}
	}
	if len(order) == 0 {
		return advisory.Advisory{}, false
	}

	adv := advisory.Advisory{
		ID:       cve,
		Database: "SUSE",
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  d.Document.Title,
		Severity: dedupeSeverity(sev),
		Upstream: []string{cve},
	}
	for _, k := range order {
		a := advisory.Affected{Ecosystem: k.eco, Name: k.pkg}
		if vs := fixed[k]; len(vs) > 0 {
			for _, v := range sortedKeys(vs) {
				a.Ranges = append(a.Ranges, advisory.Range{
					Type:   advisory.RangeEcosystem,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: v}},
				})
			}
		}
		if unfixed[k] {
			// D48/D52, reused unchanged: an introduced event with NO fixed
			// event is how OSV spells "affected at every version", which is
			// exactly what a bare known_affected entry says.
			a.Ranges = append(a.Ranges, advisory.Range{
				Type:     advisory.RangeEcosystem,
				Events:   []advisory.Event{{Introduced: "0"}},
				FixState: fixStateFor(remedy[k], st),
			})
			st.Unfixable++
		}
		adv.Affected = append(adv.Affected, a)
		st.Affected++
	}
	st.Advisories++
	return adv, true
}

func dedupeSeverity(in []advisory.Severity) []advisory.Severity {
	if len(in) == 0 {
		return nil
	}
	seen := map[advisory.Severity]bool{}
	var out []advisory.Severity
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// sortedKeys keeps emitted ranges (and, via the caller in suse.go, the
// covered-ecosystems list) in a stable order. Two builds of the same input
// must produce the same database, or `db push` layers a delta that is
// mostly noise.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
