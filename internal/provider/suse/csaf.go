// This file holds the CSAF document shape and the D77-specific parsing this
// provider needs on top of redhat's shared shape (D47's product-tree walk,
// D52's remediation-category split): SUSE's own product tree, the per-module
// key fold, and the package name/version split.
//
// The product tree itself has a different shape from Red Hat's. Red Hat's
// product_status entries spell "platform:component-EVR" directly, with the
// platform's CPE living on a branch and the component parsed by splitting
// hyphens and colons (splitContext, splitNEVRA). SUSE's feed instead gives
// every package a purl at the leaf ("pkg:rpm/suse/xz@5.6.2-1.1?..."), so a
// BUILD's name/version split is read structurally rather than guessed from
// a string that would otherwise be ambiguous -- "liblzma5-x86-64-v3-5.8.1-160000.2.2"
// has no reliable hyphen boundary of its own. Measured across the whole
// 2026-08-19 archive: 100% of 657,984 sampled leaf purls match this shape
// and reconstruct their own product_id exactly; the tiny remainder (28 of
// 657,984, all pre-2014 java-1_7_0-openjdk entries) are counted and skipped
// rather than parsed out of the raw id. "Reconstruct exactly" was read as
// "split correctly" until D126: it holds just as well for a BARE product
// whose purl SUSE cut from the product_id at the wrong hyphen
// ("libwmf-0_2-7" -> libwmf@0_2-7), which is why a bare id is now named by
// its product_id and only a recommended build by its purl (resolveProduct).
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
			// CurrentDate is the revision's own date. Read only to order two
			// copies of one document (the delta's against the archive's) --
			// never as a freshness statement, which is the archive's
			// Last-Modified (D12).
			CurrentDate string `json:"current_release_date"`
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
			// KnownNotAffected is read for one consumer only: D108's Leap
			// mirror. Nothing is stored from it -- the store has no shape for
			// "not affected" and must not grow one (D1) -- but a native Leap
			// entry here is SUSE's own verdict on the package, and the mirror
			// must not overwrite it with a derived one (D125). Before D125
			// this bucket was unread, on the premise that nothing downstream
			// could use it; the mirror pass added in D108 was the consumer
			// that premise missed. first_affected, last_affected and
			// under_investigation stay unread, as in redhat.document: they
			// describe ranges this store's introduced-at-0 shape does not
			// need.
			KnownNotAffected []string `json:"known_not_affected"`
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
	// ltssSP matches ONLY the plain "-LTSS" support channel on SLES's bare
	// mainline product name -- "SUSE Linux Enterprise Server 15 SP6-LTSS",
	// "... 12-LTSS" -- and folds it to the SAME key its bare/module twin
	// would (D91). This is the one shape in the whole LTSS family this
	// project stores data under at all: LTSS EVRs continue mainline
	// numbering with no version marker of their own (150600.4.28.1 ->
	// 4.40.1 -> 4.46.1), so there is no separate key to give it, and once
	// SLES 15 SP6 went EOL (2025-12-31) its post-EOL fixes exist ONLY under
	// this product name -- a scanner that keeps refusing it reports every
	// one of them as "no fix available" on an image that is, in fact,
	// patched. Anchored exactly like bareSP, with one literal segment
	// added ("-LTSS$"), so nothing AFTER "-LTSS" survives the match:
	// "-LTSS-TERADATA", "-LTSS Extended Security" and every HPC/OpenStack/
	// Teradata-prefixed LTSS name in the census below still fall through to
	// refusal, because none of them ships the SLES package set this
	// project's SLES key promises to describe. See collectPlatforms and
	// convert's mainline-wins pass for what happens when a document
	// carries BOTH a bare/module entry and this one for the same package.
	ltssSP = regexp.MustCompile(`^SUSE Linux Enterprise Server (\d+)(?: SP(\d+))?-LTSS$`)
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
// 8.14M platform-node occurrences), before D91: this folded 30 distinct keys
// (SLES 11 through 16.1, openSUSE Leap 15.0 through 16.0) covering 738,191
// occurrences, and refused 808 distinct product names covering the other
// 7,404,889 -- SAP ("for SAP Applications"/"applications", both case variants
// seen live), HPC, Micro, Manager, Enterprise Storage, Teradata, Real Time
// Module, "Public Cloud Module for SUSE Linux Enterprise" (a DIFFERENT, older
// product from SLES's own "Module for Public Cloud"), Liberty Linux, every
// LTSS/BCL/ESPOS-suffixed mainline release, and Tumbleweed among them.
//
// D91 (2026-08-25) narrowed that refusal by exactly one shape: the plain
// "-LTSS" suffix on SLES's bare mainline product name (ltssSP) now folds to
// the SAME key its bare/module twin would, because SLES 15 SP6 going EOL
// (2025-12-31, under LTSS to 2028-12-31) means its post-EOL fixes exist ONLY
// under that product name in the archive -- refusing it, as this function did
// before D91, reported every one of them as "no fix available" on a patched
// image. A fresh, anchored count against a 2026-08-25 archive snapshot
// (64,231 documents) found 203,614 platform-node occurrences across the 17
// distinct plain-Server-LTSS names this shape actually covers (SLES 11 SP1
// through 15 SP6, plus the bare pre-SP1 12 and 15 releases) -- the other 12
// of the 29 LTSS-family names measured (Teradata- and HPC-prefixed, "-LTSS
// Extended Security", "-LTSS-TERADATA", OpenStack's "-LTSS") still refuse,
// because none of them ships SLES's package set for the release either. A
// non-anchored version of this same count over-matches by 12,958 -- it lets
// "...12 SP3-LTSS-TERADATA" and "...15 SP2-LTSS-TERADATA" through on the
// bare-SP prefix they happen to share, the exact hazard the trailing "$"
// exists to close. Every other exclusion this comment already named -- SAP,
// HPC, Micro, Manager, Storage, Teradata, Real Time Module, the
// reversed-order Public Cloud Module, Liberty Linux, Tumbleweed -- is
// unaffected by D91 and still refuses.
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
	if m := ltssSP.FindStringSubmatch(name); m != nil {
		major := m[1]
		if n, err := strconv.Atoi(major); err != nil || n >= 16 {
			// No SLES 16+ "-LTSS" name has been observed on the live feed
			// (mirrors bareSP's identical guard immediately above); a
			// hypothetical one is refused rather than guessed at.
			return "", false
		}
		return slesKey(major, m[2]), true
	}
	return "", false
}

// isLTSSOrigin reports whether a platform NAME (the part of a
// "platform:component" product id before the colon) is the plain-Server LTSS
// shape foldKey also folds. It is the only LTSS-family shape that ever
// shares a folded key with another platform's entries, which is what makes
// convert's mainline-wins tie-break (D91) necessary in the first place --
// every other LTSS-family name is refused by foldKey and never reaches a
// point where this distinction matters.
func isLTSSOrigin(name string) bool {
	return ltssSP.MatchString(name)
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

// leapReleases is the set of openSUSE Leap releases the archive actually
// publishes: 15.0-15.6 and 16.0 at the 2026-09-14 census (D108 M1), 16.1
// since the 2026-10-21 census (3,165 documents name "openSUSE Leap 16.1",
// native entries known_affected/known_not_affected only -- a release still
// being built on the 160100 codestream, which is the gap-fill case). The
// mirror (leapMirrorKey) emits ONLY to a release in this set, so an SLE
// codestream with no corresponding Leap release -- SLE 15 SP7, whose Leap
// jumped straight to 16.0 -- never fabricates a phantom "openSUSE Leap:15.7"
// key nothing scans as. Same "refuse unknown shapes, never guess" discipline
// foldKey's anchored patterns enforce. Revisit when the census shows a new
// Leap release (16.2 next); a Leap image keyed to a release absent here
// under-reporting is the trace.
var leapReleases = map[string]bool{
	"openSUSE Leap:15.0": true,
	"openSUSE Leap:15.1": true,
	"openSUSE Leap:15.2": true,
	"openSUSE Leap:15.3": true,
	"openSUSE Leap:15.4": true,
	"openSUSE Leap:15.5": true,
	"openSUSE Leap:15.6": true,
	"openSUSE Leap:16.0": true,
	"openSUSE Leap:16.1": true,
}

// leapMirrorKey maps a folded SLE key to the openSUSE Leap key built from the
// same codestream (D108): SLES:15 -> Leap:15.0 (SP0/GA), SLES:15.SP{n} ->
// Leap:15.{n}, SLES:16.{m} -> Leap:16.{m}. Reports ok=false when the key is
// not a mirrorable SLES Server release, or when the resulting Leap release is
// not one the feed publishes (leapReleases). openSUSE Leap 15.x is binary-built
// from SLE 15 SPx on the shared 150600 codestream with the same EVR numbering,
// which is what makes the resulting key answer a Leap query for a shared
// package soundly and lets the rpm comparer judge it (no new Comparer, D9).
func leapMirrorKey(sleKey string) (string, bool) {
	var leap string
	switch {
	case sleKey == "SLES:15":
		leap = "openSUSE Leap:15.0"
	case strings.HasPrefix(sleKey, "SLES:15.SP"):
		leap = "openSUSE Leap:15." + strings.TrimPrefix(sleKey, "SLES:15.SP")
	case strings.HasPrefix(sleKey, "SLES:16."):
		leap = "openSUSE Leap:16." + strings.TrimPrefix(sleKey, "SLES:16.")
	default:
		return "", false
	}
	if !leapReleases[leap] {
		return "", false
	}
	return leap, true
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
//
// bare says which bucket the id came from, and the bucket decides the name
// (D126). A known_affected, known_not_affected or no-fix remediation id names
// a BARE product, whose product_id IS the rpm package name; a recommended id
// names a shipped build, whose purl carries the name and the fix version.
// The purl of a bare product is not trusted for the name because SUSE's
// generator cuts it FROM the product_id at the first hyphen-digit boundary:
// "libwmf-0_2-7" carries pkg:rpm/suse/libwmf@0_2-7, "libglib-2_0-0" carries
// pkg:rpm/suse/libglib@2_0-0, so 11,753 of the 726,722 distinct
// document-and-package status ids in the 2026-10-19 archive (404 products)
// were keyed under a name no installed rpm has -- 39,215 entries in 2,794
// documents, 31,494 of them the package's only entry. The bucket is the
// only exception-free signal measured: 0 of those status ids names a build
// and 0 of 4,396,450 recommended ids names a bare product, whereas every
// syntactic rule on the version string either keeps one mis-split
// (typelib-1_0-Vte-2.91) or loses 577 real builds
// (cdparanoia-IIIalpha9.8-691.22). The leaf must still exist with a readable
// purl: an id naming no leaf, or a leaf with no purl (the java-1_7_0-openjdk
// gap), stays a counted skip rather than a name guessed from the raw id.
// st counts the renames only; skips are the caller's to count, for the
// reason the remediation loop gives. The bare branch's "" version is by
// construction: no bare caller reads it (store ignores the version when
// isFixed is false, the other two discard it), so returning pkg.version
// instead is an equivalent mutation (verified 2026-10-21) -- the literal
// states what a bare id carries, it does not decide anything.
func resolveProduct(id string, bare bool, folded map[string]string, declared map[string]bool,
	packages map[string]packageInfo, st *stats) (productKey, string, skipReason) {

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
	if bare {
		if pkg.name != comp {
			st.BareNamedByProductID++
		}
		return productKey{eco: key, pkg: comp}, "", skipNone
	}
	if pkg.version == "" {
		// D131: the generator failed to split this build's purl at all --
		// the whole NEVR is the purl's name and the version is empty. The
		// bucket says it is a build (0 of 4,396,450 recommended ids name a
		// bare product, D126), so the product_id is "name-ver-rel" by rpm's
		// rule and is split here; stored as the purl spelt it, the entry
		// sat unfixed under a name no installed rpm has, reaching nothing.
		// Two guards keep the split to the measured shape: the purl's name
		// must be the product_id verbatim (the generator copied it whole
		// rather than cutting it somewhere else), and the product_id must
		// read as a build (splitNEVR). An id failing either keeps exactly
		// the pre-D131 behaviour below -- unfixed under the purl's name,
		// never dropped -- and is counted, so a future shape is a visible
		// no-fix entry rather than a name cut at the wrong hyphen.
		if name, verrel, ok := splitNEVR(comp); ok && pkg.name == comp {
			st.RecommendedNamedByNEVRSplit++
			return productKey{eco: key, pkg: name}, verrel, skipNone
		}
		st.RecommendedEmptyVersionKept++
	}
	return productKey{eco: key, pkg: pkg.name}, pkg.version, skipNone
}

// splitNEVR reads a product_id as rpm does -- the release is everything
// after the last hyphen, the version everything after the one before it,
// the name the rest -- and reports false unless the result READS as a build:
// a non-empty name, a version that starts with a digit, and a release that
// contains a dot. The two shape checks are what keep a bare product name
// that happens to carry two hyphens from being cut: "typelib-1_0-Vte" and
// "libwmf-0_2-7" (D126's measured bare shapes) both fail on the release,
// "cdparanoia-IIIalpha9.8-691.22" on the version. SUSE's own well-formed
// splits were measured for the same two shapes across the whole 2026-10-19
// archive before the checks were chosen (see D131); neither check refuses
// any of the 16,736 ids the rule exists for.
func splitNEVR(id string) (name, verrel string, ok bool) {
	rel := strings.LastIndex(id, "-")
	if rel < 0 {
		return "", "", false
	}
	ver := strings.LastIndex(id[:rel], "-")
	if ver <= 0 {
		return "", "", false
	}
	name, version, release := id[:ver], id[ver+1:rel], id[rel+1:]
	if version == "" || version[0] < '0' || version[0] > '9' || !strings.Contains(release, ".") {
		return "", "", false
	}
	return name, version + "-" + release, true
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
// fixStateOf is fixStateFor without the counting: the state a no-fix range
// carries for these remediation categories. D149's leapView builds the
// range a Leap pass sees without emitting it, so it must not count it.
func fixStateOf(cats map[string]bool) advisory.FixState {
	switch {
	case cats[remedyNoFixPlanned]:
		return advisory.FixStateWontFix
	case cats[remedyNoneAvailable]:
		return advisory.FixStateNotFixed
	default:
		return advisory.FixStateUnknown
	}
}

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

// uncountFixState reverses fixStateFor's count for a no-fix range that is
// not emitted after all (D128 replaced it with the SLE twin's fix), so the
// D52 split still sums to Unfixable. Beside fixStateFor so the two cannot
// drift: the same categories, the same branches, the opposite sign. It
// reports whether the range carried a stated reason at all.
func uncountFixState(cats map[string]bool, st *stats) (hadReason bool) {
	never, pending := cats[remedyNoFixPlanned], cats[remedyNoneAvailable]
	if never && pending {
		st.UnfixableBothReasons--
	}
	switch {
	case never:
		st.UnfixableWontFix--
	case pending:
		st.UnfixableNotFixed--
	default:
		st.UnfixableUnstated--
	}
	return never || pending
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

	// SkippedLTSSShadowedByMainline is D91's tie-break firing: a document
	// carries BOTH a bare/module (mainline) product_status entry AND an
	// LTSS one for the SAME folded key and package, and the LTSS one is
	// the one dropped -- counted once per product_status entry shadowed,
	// the same per-entry granularity as the Skipped* group above. It is
	// the common case (11,955 same-document bare+LTSS pairs measured
	// across the whole archive); the SP6 post-EOL fixes this slice exists
	// for are the OPPOSITE case -- no mainline entry to shadow them, so
	// they are kept and never touch this counter at all.
	SkippedLTSSShadowedByMainline int
	// LTSSFixReplacedMainlineNoFix is D149's exception to that tie-break:
	// the mainline entry for the key was only a known_affected (no fix) --
	// the EOL'd product SUSE keeps beside its LTSS twin after general
	// support ends -- and the LTSS entry carries a fix, so the fix is kept
	// in place of "affected at every version". Per LTSS entry kept, like
	// SkippedLTSSShadowedByMainline, which it is carved out of.
	LTSSFixReplacedMainlineNoFix int
	// LTSSFixReplacedWithReason is the subset of keys whose replaced no-fix
	// entry carried a stated fix-state reason (no_fix_planned on the EOL'd
	// product, usually) that the replacement dropped, as D128 counts its
	// own.
	LTSSFixReplacedWithReason int

	// MirroredToLeap and SkippedLeapNativeWins are D108's mirror pass firing.
	// MirroredToLeap counts affected entries emitted onto an openSUSE Leap key
	// from a folded SLE codestream key (the aging-out gap this slice fills, as
	// SUSE drops Leap product entries when it regenerates a document while the
	// SLE codestream stays maintained). SkippedLeapNativeWins counts the
	// gap-fill tie-break declining to mirror because the document already
	// carries a native Leap entry for that package -- native wins, so no
	// installed-package finding is ever hidden. Same per-entry granularity as
	// the Skipped* group above. Neither touches Affected/Unfixable: a mirror is
	// a derived duplicate of an entry those already counted.
	MirroredToLeap        int
	SkippedLeapNativeWins int
	// SkippedLeapNotAffected is D125's refinement of the same tie-break: the
	// document names the package under a native Leap known_not_affected
	// entry, so SUSE has already judged it and the mirror declines rather
	// than contradict that verdict with an SLE-derived one. Per entry, like
	// SkippedLeapNativeWins.
	SkippedLeapNotAffected int
	// LeapNoFixReplacedBySLEFix is D128's refinement of native-wins: the
	// native Leap entry was a bare known_affected (no fix) while its
	// same-codestream SLE twin is fixed at V, so the Leap key carries SLE's
	// fixed range (disclosed as CrossMappedFrom) in place of "affected at
	// every version". Per entry, like SkippedLeapNativeWins, which it is
	// carved out of.
	LeapNoFixReplacedBySLEFix int
	// LeapNoFixReplacedWithReason is the subset of those whose native
	// no-fix range carried a stated fix-state reason (no_fix_planned ->
	// won't fix, none_available -> not fixed yet) that the replacement
	// dropped, and with it the --fail-on-unfixable gate's view of the
	// package. 0 of 704 on the 2026-10-19 archive; counted so the day it
	// happens is visible rather than silent.
	LeapNoFixReplacedWithReason int

	// BareNamedByProductID is D126's rule doing visible work: a
	// known_affected / known_not_affected / no-fix remediation id whose
	// leaf purl split the product_id into a different name
	// ("libwmf-0_2-7" -> pkg:rpm/suse/libwmf@0_2-7), named by the
	// product_id instead. Per id, like the Skipped* group, before D91's
	// LTSS shadowing: 70,463 across the 2026-10-19 archive (69,697 status
	// ids, 766 remediation ids), which are 11,753 distinct document-and-
	// package pairs -- the survey's unit, not this counter's. A jump or a
	// collapse against that baseline is the trace that SUSE's generator
	// changed.
	BareNamedByProductID int

	// RecommendedNamedByNEVRSplit is D131's rule doing visible work: a
	// recommended id whose leaf purl carried the whole build as its NAME
	// with an empty version ("pkg:rpm/suse/kernel-coco-6.4.0-15061.9.coco15sp6.1@"),
	// named and versioned by splitting its product_id by rpm's rule instead
	// of being stored unfixed under a name no installed rpm has. Per id.
	// 16,736 across the 2026-10-19 archive on folding keys, every one the
	// Confidential Computing Technical Preview module's kernel-coco family
	// (and 168 qemu builds) on SLES:15.SP6; the 91,704 more on Liberty,
	// Teradata, HPC and Micro platforms never reach this counter because
	// foldKey refuses those platforms first. A jump is the generator
	// failing on a new product; a collapse is SUSE having fixed it.
	RecommendedNamedByNEVRSplit int
	// RecommendedEmptyVersionKept is the rule declining: a recommended id
	// whose purl carried no version but which did not read as a build, or
	// whose purl name was not the product_id verbatim, stored as before
	// D131 -- unfixed under the purl's name. 0 on the 2026-10-19 archive;
	// the day it is not is the day the generator produced a third shape.
	RecommendedEmptyVersionKept int
	// SkippedLeapMirrorSplitBuild counts SLE entries with no native Leap
	// twin that D108 did NOT mirror because every range they carried was a
	// D131 split build's. Such a build's release numbering is its own
	// module's (15061.N.coco15sp6.1 for the Confidential Computing
	// Technical Preview), not the codestream's 150600.N that Leap shares,
	// so a Leap build compared against it would read as fixed by a number
	// from a different lineage. 16,568 on the 2026-10-19 archive, the
	// kernel-coco family, which no Leap release ships. An SLE entry that
	// also carries a codestream fix mirrors those ranges alone (the 168
	// qemu/ovmf builds, whose Leap twins are native anyway). An entry WITH
	// a native twin is counted native-wins, not here, even when D128
	// declines to lend for the same reason: native-wins is why it was not
	// mirrored, and the Leap counters partition the mirrorable entries.
	SkippedLeapMirrorSplitBuild int

	// ArchiveSuperseded counts archive documents skipped because the delta
	// pass, which runs first since D129, fetched a copy of the same document
	// at least as new as the archive's -- whatever that copy converted to.
	// Only a FETCHED copy supersedes: a listed-but-gone document (DeltaGone)
	// keeps its archive copy, so a transient 404 never drops a live advisory.
	ArchiveSuperseded int
	// ArchiveNewerThanDelta counts archive documents the delta had fetched
	// a copy of whose archive copy is the NEWER revision by
	// current_release_date. The archive copy is emitted after the delta's,
	// so the newer one is the record that stands. Since the archive is
	// downloaded before the delta runs (D135) this needs an individual
	// document served staler than the archive it sits beside -- a cache in
	// front of the feed -- so a non-zero count is worth a look.
	ArchiveNewerThanDelta int

	// The delta pass (delta.go), identical in meaning to redhat.stats'.
	DeltaListed     int
	DeltaFetched    int
	DeltaGone       int
	DeltaAdvisories int
	DeltaRetried    int
	DeltaRescued    int
}

// cveOf is the identity one document has: its vulnerability's CVE, else the
// tracking id. convert keys the record on it, and D129's delta pass keys the
// set of superseded archive documents on it too -- the spelling of a file
// name is not shared between changes.csv and the archive, the document's own
// id is.
func cveOf(d *document) string {
	if len(d.Vulnerabilities) > 0 && d.Vulnerabilities[0].CVE != "" {
		return d.Vulnerabilities[0].CVE
	}
	return d.Document.Tracking.ID
}

// convert turns one CSAF document into at most one advisory. One document is
// one CVE (measured: 0 of 63,784 documents in the whole archive carry more
// than one vulnerabilities[] entry), so the whole document collapses to a
// single record the same way redhat.convert's does. D25's grouping works
// through the CVE carried in Aliases (see the ID field below), not through
// the record's own ID: that ID is now SUSE-prefixed, so this record and Red
// Hat's for the same CVE join by sharing an identifier rather than by having
// the same one.
func convert(d *document, st *stats) (advisory.Advisory, bool) {
	st.Documents++

	folded, declared := collectPlatforms(d.ProductTree.Branches, st)
	packages := collectPackages(d.ProductTree.Branches, st)

	cve := cveOf(d)
	if !strings.HasPrefix(cve, "CVE-") {
		st.SkippedNoCVE++
		return advisory.Advisory{}, false
	}

	fixed := map[productKey]map[string]bool{}
	unfixed := map[productKey]bool{}
	remedy := map[productKey]map[string]bool{}
	order := []productKey{}
	seen := map[productKey]bool{}
	// mainline marks every key a BARE or MODULE (non-LTSS) product_status
	// entry covered in THIS document -- D91's tie-break line. Always fully
	// populated for one vulnerability's recommended+known_affected arrays
	// before any LTSS entry for the same vulnerability is resolved against
	// it (see the pendingLTSS loop below), so array order within either
	// array never matters: a mainline entry appearing after its LTSS twin
	// in the JSON still wins.
	mainline := map[productKey]bool{}
	// mainlineFixed marks the keys a mainline entry gave a fixed version.
	// D149: an LTSS fix is shadowed only by one of these; a mainline
	// entry that says only "affected, no fix" yields to it instead.
	mainlineFixed := map[productKey]bool{}
	// ltssOverNoFix marks the keys D149 gave an LTSS fix in place of a
	// mainline no-fix entry, so the stated reason that entry carried can
	// be counted once the remediations are read.
	ltssOverNoFix := map[productKey]bool{}
	// leapNotAffected marks every openSUSE Leap key a known_not_affected
	// entry names (D125). Nothing is stored from it; it only tells the D108
	// mirror pass below that SUSE has already judged the package on that
	// Leap release, so an SLE-derived entry must not be emitted over the
	// verdict. Keyed like native: per release and package, whether the id
	// was the bare package or a shipped build.
	leapNotAffected := map[productKey]bool{}
	// splitBuild marks, per key, the fixed versions D131 derived by splitting
	// a product_id (resolveProduct). Read by the D108 mirror and D128 passes
	// only: such a version carries a module's own release numbering
	// (15061.N.coco15sp6.1), not the codestream's, so it never crosses to a
	// Leap key -- a Leap build compared against it would read as fixed by a
	// number from a different lineage. On the SLE key itself it is stored
	// like any fix: that is the module's own package on the release that
	// ships it.
	splitBuild := map[productKey]map[string]bool{}
	note := func(k productKey) {
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	store := func(k productKey, version string, isFixed bool) {
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
	// countSkip records the counter for a resolveProduct refusal and reports
	// whether the id resolved at all. Shared by the mainline and LTSS
	// resolution below so one id is counted exactly once, however many
	// passes look at it.
	countSkip := func(why skipReason) bool {
		switch why {
		case skipNoColon:
			st.SkippedNoColon++
		case skipEmptyComponent:
			st.SkippedEmptyComponent++
		case skipTumbleweedRef:
			st.SkippedTumbleweedRef++
		case skipUnknownPlatform:
			st.SkippedUnknownPlatform++
		case skipUnfoldablePlatform:
			st.SkippedUnfoldablePlatform++
		case skipUnknownPackage:
			st.SkippedUnknownPackage++
		default:
			return true
		}
		return false
	}

	type ltssEntry struct {
		key     productKey
		version string
		isFixed bool
	}

	var sev []advisory.Severity
	for i := range d.Vulnerabilities {
		v := &d.Vulnerabilities[i]

		// D91: every recommended/known_affected id is resolved exactly
		// once. A bare/module (mainline) platform stores immediately, same
		// as before this slice. An LTSS platform's id is buffered instead,
		// because whether it survives depends on whether a mainline entry
		// for the SAME key turns up anywhere else in this vulnerability's
		// arrays -- knowable only once both loops below finish.
		var pendingLTSS []ltssEntry
		for _, id := range v.ProductStatus.Recommended {
			plat, comp, _ := strings.Cut(id, ":")
			k, version, why := resolveProduct(id, false, folded, declared, packages, st)
			if !countSkip(why) {
				continue
			}
			// D131: a version the leaf did not carry came from splitting the
			// product_id -- a build from a module with its own release
			// numbering. Remembered per key so the Leap passes below can tell
			// its range from a codestream fix. `version != "" &&` is intent,
			// not behaviour: a kept empty-version id would record "" here and
			// withoutSplitBuilds ignores "" through its own `e.Fixed != ""`,
			// so dropping either clause alone is an equivalent mutation
			// (verified 2026-10-21); only dropping both is a defect.
			if version != "" && packages[comp].version == "" {
				if splitBuild[k] == nil {
					splitBuild[k] = map[string]bool{}
				}
				splitBuild[k][version] = true
			}
			if isLTSSOrigin(plat) {
				pendingLTSS = append(pendingLTSS, ltssEntry{k, version, true})
				continue
			}
			store(k, version, true)
			mainline[k] = true
			if version != "" {
				mainlineFixed[k] = true
			}
		}
		for _, id := range v.ProductStatus.KnownAffected {
			plat, _, _ := strings.Cut(id, ":")
			k, version, why := resolveProduct(id, true, folded, declared, packages, st)
			if !countSkip(why) {
				continue
			}
			if isLTSSOrigin(plat) {
				pendingLTSS = append(pendingLTSS, ltssEntry{k, version, false})
				continue
			}
			store(k, version, false)
			mainline[k] = true
		}
		// Resolve every buffered LTSS entry now that this vulnerability's
		// mainline coverage is final: shadowed (a mainline entry already
		// covers the key -- drop the LTSS twin, counted) or kept (no
		// mainline entry ever named this key -- the SP6 post-EOL case this
		// slice exists for, stored exactly like a mainline entry would
		// be).
		for _, p := range pendingLTSS {
			if mainline[p.key] {
				// D149: after general support ends SUSE keeps the EOL'd
				// product in known_affected beside the LTSS fix. A mainline
				// entry with no fix of its own does not shadow that fix; the
				// fix replaces it, or the "affected at every version" range
				// would still match the fixed LTSS build. LTSS versions
				// continue mainline numbering (D91), so the comparison holds.
				if p.isFixed && p.version != "" && !mainlineFixed[p.key] {
					delete(unfixed, p.key)
					store(p.key, p.version, true)
					ltssOverNoFix[p.key] = true
					st.LTSSFixReplacedMainlineNoFix++
					continue
				}
				st.SkippedLTSSShadowedByMainline++
				continue
			}
			store(p.key, p.version, p.isFixed)
		}

		for _, id := range v.ProductStatus.KnownNotAffected {
			// Not counted on refusal, for the remediation loop's reason
			// below: nothing from this bucket is ever stored, so an id that
			// does not resolve is not a discard. Only a Leap key matters --
			// an SLE not-affected entry has no consumer here, and a Leap one
			// is read only by the mirror pass. The Leap guard is intent, not
			// behaviour: dropping it is an equivalent mutation (verified
			// 2026-10-21), because the mirror pass looks up Leap keys only
			// and an SLE key in this map is never read.
			k, _, why := resolveProduct(id, true, folded, declared, packages, st)
			if why != skipNone || !strings.HasPrefix(k.eco, "openSUSE Leap:") {
				continue
			}
			leapNotAffected[k] = true
		}

		for _, r := range v.Remediations {
			if r.Category != remedyNoFixPlanned && r.Category != remedyNoneAvailable {
				continue
			}
			for _, id := range r.ProductIDs {
				// Skips are not counted here, for the reason resolveProduct's
				// doc comment gives: a remediation naming a product this
				// store does not hold is not a discard, it is a statement
				// about something never stored. An LTSS remediation for a
				// key mainline already covers is the identical statement
				// about the SAME shadow the product_status loop above
				// already dropped -- explaining a discard is not itself a
				// second one.
				plat, _, _ := strings.Cut(id, ":")
				// bare: a no-fix remediation names the bare product -- the
				// component the known_affected loop resolved (230,566 of
				// 541,090 measured name a component the same vulnerability's
				// status buckets name, 5,400 of them the identical id on the
				// same platform; 0 name a build), so it must take the same
				// name or the reason never attaches (D126).
				k, _, why := resolveProduct(id, true, folded, declared, packages, st)
				if why != skipNone {
					continue
				}
				if isLTSSOrigin(plat) && mainline[k] {
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
		// D90: prefixed, mirroring redhat.convert's identical change and for
		// the identical reason -- before this, ID was the bare CVE on both
		// this provider and Red Hat's (D47), and the store's by-id bucket is
		// last-writer-wins on ID, so a full multi-provider build had one
		// vendor's record silently clobber the other's for every CVE both
		// name. Aliases carries the bare CVE instead of Upstream: D25
		// grouping (matcher.identifiers) reads ID+Aliases, not Upstream, so
		// this is what keeps this record and Red Hat's for one CVE joining
		// into a single finding, and annotate()'s HasPrefix(id, "CVE-") walk
		// over Identifiers (built from Aliases too) still finds the bare CVE
		// for NVD/EPSS/KEV/KISA joins.
		ID:       "SUSE-" + cve,
		Database: "SUSE",
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  d.Document.Title,
		Severity: dedupeSeverity(sev),
		Aliases:  []string{cve},
	}
	for _, k := range order {
		// The category test is intent, not behaviour: remedy holds only these two
		// categories (the remediation loop skips the rest), so dropping it is an
		// equivalent mutation (verified 2026-10-27).
		if ltssOverNoFix[k] && (remedy[k][remedyNoFixPlanned] || remedy[k][remedyNoneAvailable]) {
			st.LTSSFixReplacedWithReason++
		}
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

	// D108: mirror each folded SLE codestream entry onto the openSUSE Leap key
	// built from the same 150600 codestream, gap-fill -- only where this
	// document produced no native Leap entry for that package. Native wins, so
	// no installed-package finding is ever hidden; the aging-out case (SUSE
	// dropping a document's Leap product entries on regeneration) has no native
	// entry, so the mirror fills it. See leapMirrorKey / leapReleases. Built
	// from adv.Affected (already assembled above) so it sees the fully folded,
	// D91-shadowed result rather than re-resolving product ids.
	// native maps each Leap key's package to its entry's index in adv.Affected:
	// D108 needs only presence, D128 below rewrites the entry in place.
	native := map[productKey]int{}
	for i := range adv.Affected {
		if a := &adv.Affected[i]; strings.HasPrefix(a.Ecosystem, "openSUSE Leap:") {
			native[productKey{eco: a.Ecosystem, pkg: a.Name}] = i
		}
	}
	// leapView is the SLE entry as the Leap passes below see it. For a key
	// D149 gave an LTSS fix in place of a mainline no-fix, that is the entry
	// as it was before D149: the no-fix range alone (every LTSS entry was
	// shadowed then, and the mainline side named no fix). D149 is an SLE-key
	// change only. Leap never ships an LTSS build, so crossing one would
	// advertise a fix Leap cannot install, and would lift D125's decline
	// over SUSE's own Leap known_not_affected -- a new false positive on
	// every Leap image with the package (branch review wf_18101bb4-1e1).
	leapView := func(a *advisory.Affected) (ranges []advisory.Range, noFix bool) {
		k := productKey{eco: a.Ecosystem, pkg: a.Name}
		if ltssOverNoFix[k] {
			return []advisory.Range{{
				Type:     advisory.RangeEcosystem,
				Events:   []advisory.Event{{Introduced: "0"}},
				FixState: fixStateOf(remedy[k]),
			}}, true
		}
		return a.Ranges, unfixed[k]
	}
	var mirrors []advisory.Affected
	for i := range adv.Affected {
		a := &adv.Affected[i]
		leap, ok := leapMirrorKey(a.Ecosystem)
		if !ok {
			continue
		}
		sleRanges, sleNoFix := leapView(a)
		if ni, ok := native[productKey{eco: leap, pkg: a.Name}]; ok {
			// D128: native-wins yields in exactly one shape -- the native Leap
			// entry is a bare known_affected (no fix, nothing else) while this
			// SLE twin on the same codestream is fixed at V. Then the Leap key
			// carries SLE's fixed ranges, disclosed as CrossMappedFrom, in
			// place of "affected at every version": an image at or past V is
			// clean, where native-wins reported it affected with no fix
			// (cve-2026-18374's glibc on Leap 16.1, whose repo ships the very
			// build SLE calls fixed -- 25 such entries across 11 packages on
			// 16.1 alone), and an older image is affected with the fix version
			// named. Both no-fix, or a native entry with a fix of its own, stay
			// native (D108): the first has nothing to offer, the second is
			// Leap's own patch state. Only the fixed ranges cross: an SLE entry
			// that is both fixed and bare-affected -- all 10 of Leap 16.0's
			// cases and 12 of 16.1's 25 are that mixed shape -- would otherwise
			// bring the no-fix range back under a CrossMappedFrom label. A
			// native range with a stated reason (won't fix) is replaced too --
			// the verdict is about the installed build -- and the drop counted.
			//
			// `unfixed[nk] &&` is intent, not behaviour: an entry exists only
			// through store(), which records a fixed version or sets unfixed,
			// so len(fixed[nk]) == 0 already implies unfixed[nk]; dropping the
			// clause is an equivalent mutation (verified 2026-10-21).
			nk, sk := productKey{eco: leap, pkg: a.Name}, productKey{eco: a.Ecosystem, pkg: a.Name}
			// D131: only codestream fixes cross; a split build's range is
			// dropped here before the fixed-range test, so an SLE twin whose
			// ONLY fix is such a build offers nothing and native wins as if
			// it carried no fix at all -- counted as native-wins below, which
			// IS why the entry was not mirrored, so the Leap counters stay a
			// partition of the mirrorable entries (SkippedLeapMirrorSplitBuild
			// is the no-native path's alone; D131's review found the first
			// draft counting such an entry under both).
			crossable := fixedRangesOf(withoutSplitBuilds(sleRanges, splitBuild[sk]))
			if unfixed[nk] && len(fixed[nk]) == 0 && len(crossable) > 0 {
				nat := &adv.Affected[ni]
				nat.Ranges = crossable
				nat.CrossMappedFrom = a.Ecosystem
				// The no-fix range it replaced is gone with it: out of the
				// total AND out of the D52 split fixStateFor put it in, or the
				// progress line's split exceeds its total.
				st.Unfixable--
				if uncountFixState(remedy[nk], st) {
					st.LeapNoFixReplacedWithReason++
				}
				st.LeapNoFixReplacedBySLEFix++
				continue
			}
			st.SkippedLeapNativeWins++
			continue
		}
		// D125: SUSE's own "not affected" for this package on this Leap
		// release is a verdict, not an absence -- but only against an
		// "affected at every version" mirror. cve-2025-61144 (2026-10-21)
		// lists libtiff6 as known_affected with no fix on SLE 15 SP6 and
		// known_not_affected on Leap 15.6; before this check the mirror
		// emitted the no-fix range over it, a false positive on every Leap
		// image with libtiff6 installed. A FIXED source still mirrors: SUSE
		// writes the bare id into known_not_affected for "Already fixed" and
		// "Released" too (the shipped build goes to recommended), so a Leap
		// not-affected beside an SLE fixed@V agrees with the mirror -- a
		// build at or past V gets no finding either way, and the mirror is
		// the only range that flags an older one. 4,363 of the 4,463
		// overlaps in the archive are that fixed shape; the 100 no-fix ones
		// are what this declines. Checked after native-wins so a key the
		// document lists as both affected and not affected keeps its native
		// affected entry and is counted there.
		if sleNoFix && leapNotAffected[productKey{eco: leap, pkg: a.Name}] {
			st.SkippedLeapNotAffected++
			continue
		}
		// D131: a split build's range never crosses (see splitBuild). An
		// entry with nothing else to offer is not mirrored at all and
		// counted; one that also carries a codestream fix or a no-fix range
		// mirrors those alone.
		rs := withoutSplitBuilds(sleRanges, splitBuild[productKey{eco: a.Ecosystem, pkg: a.Name}])
		if len(rs) == 0 {
			st.SkippedLeapMirrorSplitBuild++
			continue
		}
		// Ranges is aliased, not copied: the store treats every emitted
		// advisory as immutable, and nothing mutates a range after convert
		// returns. ModuleStream carries over so a modular SLE entry mirrors as
		// a modular Leap entry.
		mirrors = append(mirrors, advisory.Affected{
			Ecosystem:       leap,
			Name:            a.Name,
			Ranges:          rs,
			ModuleStream:    a.ModuleStream,
			CrossMappedFrom: a.Ecosystem,
		})
		st.MirroredToLeap++
	}
	adv.Affected = append(adv.Affected, mirrors...)

	st.Advisories++
	return adv, true
}

// withoutSplitBuilds returns rs less every range whose fixed event is one of
// the versions D131 derived by splitting a product_id (splitBuild[key]). The
// input is returned as is when there is nothing to drop, which is every key
// but the 16,736 measured, so the mirror still aliases the SLE entry's own
// slice in the common case; a filtered result is a fresh slice.
func withoutSplitBuilds(rs []advisory.Range, split map[string]bool) []advisory.Range {
	if len(split) == 0 {
		return rs
	}
	out := make([]advisory.Range, 0, len(rs))
	for _, r := range rs {
		keep := true
		for _, e := range r.Events {
			if e.Fixed != "" && split[e.Fixed] {
				keep = false
			}
		}
		if keep {
			out = append(out, r)
		}
	}
	return out
}

// fixedRangesOf returns the ranges that carry a fixed event, copied down to
// their events: the native entry D128 rewrites must not share a backing
// array with the SLE entry it took them from. (Nothing mutates a range after
// convert returns, which is also why the D108 mirror aliases whole Ranges;
// the copy here costs nothing and keeps the two entries independent by
// construction.) The break is intent, not behaviour: every range this
// provider builds carries at most one fixed event, so dropping it is an
// equivalent mutation (verified 2026-10-21).
func fixedRangesOf(rs []advisory.Range) []advisory.Range {
	var out []advisory.Range
	for _, r := range rs {
		for _, e := range r.Events {
			if e.Fixed != "" {
				c := r
				c.Events = append([]advisory.Event(nil), r.Events...)
				out = append(out, c)
				break
			}
		}
	}
	return out
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
