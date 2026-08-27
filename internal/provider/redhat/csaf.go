// Package redhat ingests Red Hat's CSAF VEX feed.
//
// It exists because the OSV Red Hat export cannot say the thing that matters
// most about a RHEL system. That export is errata-only: every one of its
// 588,150 affected entries carries a fixed version, so "affected, will not
// fix" has no representation at all. Measured over the whole VEX archive,
// 21,938 CVEs name a mainline-RHEL RPM as `known_affected` with no fix —
// against 16,845 that name one as fixed. Two thirds of what Red Hat publishes
// about its own packages is invisible through OSV, and a scanner built on OSV
// alone reports all of it clean (D43).
//
// This is also the second test of D1's claim that owning the schema is what
// makes a non-OSV provider possible. It holds: CSAF's "affected with no fix"
// is an OSV range with an `introduced` event and no `fixed` one, which the
// store already understands and the matcher already evaluates. Nothing in the
// schema changed to accept it.
package redhat

import (
	"regexp"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// document is the subset of one CSAF VEX document this provider reads.
//
// It is deliberately narrow, and that is a memory decision rather than a
// stylistic one. The archive holds 67,261 documents totalling 17.1 GB and the
// largest single one is 94 MB; encoding/json skips fields absent from the
// target struct without allocating, so the two biggest parts of a real
// document never materialize:
//
//   - product_tree.relationships — 2.8 MB of CVE-2024-6387's 4.7 MB, and
//     unnecessary, because a product_status entry already spells
//     "platform:component" and the platform's CPE comes from the branches.
//   - product_status.known_not_affected — 4,476,026 entries archive-wide
//     against 1,482,890 known_affected. Nothing downstream can use a
//     not-affected claim: this store records what IS affected, and a finding
//     is never suppressed by its absence.
type document struct {
	Document struct {
		Tracking struct {
			ID           string `json:"id"`
			CurrentDate  string `json:"current_release_date"`
			InitialDate  string `json:"initial_release_date"`
			Distribution string `json:"-"`
		} `json:"tracking"`
		Title string `json:"title"`
	} `json:"document"`
	ProductTree struct {
		Branches []branch `json:"branches"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE           string `json:"cve"`
		ProductStatus struct {
			Fixed         []string `json:"fixed"`
			KnownAffected []string `json:"known_affected"`
		} `json:"product_status"`
		// Remediations is what makes D52's distinction possible. product_status
		// says a package is affected; only this says whether Red Hat intends to
		// do anything about it. The product ids are the same "platform:component"
		// strings product_status uses, resolved through the same product_tree.
		Remediations []struct {
			Category   string   `json:"category"`
			ProductIDs []string `json:"product_ids"`
			// GroupIDs names a product_tree.product_groups entry instead of
			// listing products. CSAF allows it; Red Hat does not use it — 0 of
			// 63,152 documents in the 2026-08-09 archive carry one, and 0 carry
			// a product_groups block to resolve it against. It is read only to
			// be COUNTED (stats.RemediationGrouped), so that a feed which
			// started using it would show up as a number climbing off zero
			// rather than as fix states quietly going unstated. Expanding it
			// against no data to test with would be the worse trade.
			GroupIDs []string `json:"group_ids"`
		} `json:"remediations"`
		Scores []struct {
			CVSSv3 struct {
				VectorString string `json:"vectorString"`
			} `json:"cvss_v3"`
			CVSSv4 struct {
				VectorString string `json:"vectorString"`
			} `json:"cvss_v4"`
		} `json:"scores"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
	} `json:"vulnerabilities"`
}

type branch struct {
	Branches []branch `json:"branches"`
	Product  *struct {
		ProductID string `json:"product_id"`
		Helper    struct {
			CPE string `json:"cpe"`
			// Purl is read only for Hummingbird content (D98). Mainline RHEL
			// leaf nodes carry one too on the live 2026-08-27 archive (e.g.
			// "pkg:rpm/redhat/freetype-devel", no version at all — the
			// mainline EVR lives in the "platform:component-EVR" string, not
			// here), but mainline's resolveProduct path never reads this
			// field: it still parses that compound string directly
			// (splitContext/splitNEVRA), so an unused mainline purl changes
			// nothing on that path.
			Purl string `json:"purl"`
		} `json:"product_identification_helper"`
	} `json:"product"`
}

// mainlineCPE matches the only product family this provider ingests (D47):
// mainline Red Hat Enterprise Linux, at any repository below it.
//
// The archive carries 462 distinct CPE shapes and 903 exact keys, across
// rhel_eus, rhel_aus, rhel_tus, rhel_e4s, per-minor variants, and unrelated
// products that merely share the namespace (`cpe:/a:redhat:openstack:10::el7`,
// `cpe:/a:redhat:jboss_enterprise_application_platform:6`). A prefix match on
// "redhat" pulls all of those in.
//
// Mainline-only is not a simplification, it is the only key a scan can derive.
// The support channel a CPE encodes is a SUBSCRIPTION attribute with no
// filesystem representation: /etc/os-release says 9.8 and cannot say whether
// the host is on EUS. Restricting to mainline drops the fixed-version
// ambiguity from 25.1% of (CVE, package, major) groups to 6.1%.
var mainlineCPE = regexp.MustCompile(`^cpe:/[oa]:redhat:enterprise_linux:(\d+)(?:\.\d+)?(?:::.*)?$`)

// hummingbirdCPE matches Project Hummingbird, Red Hat's minimal hardened
// container line (D98). Every document sampled from the 2026-08-27 archive
// carries exactly one shape, "cpe:/a:redhat:hummingbird:1" — measured across
// 125 confirmed Hummingbird-scoped documents (of ~1,200-1,400 estimated in
// the full ~49,462-document archive) — but the trailing digit is matched
// rather than pinned to "1" on the same reasoning mainlineCPE anchors on a
// captured major: if Red Hat ever bumps it, this project's own key stays the
// bare "Hummingbird" sentinel regardless (D98 — Hummingbird is rolling, and
// that digit is not a release axis this project keys on, the same way
// Arch's rolling BUILD_ID carries no version D97 reads).
var hummingbirdCPE = regexp.MustCompile(`^cpe:/a:redhat:hummingbird:\d+$`)

// hummingbirdEcosystem is the store key ecosystemFor returns for a
// Hummingbird-scoped product (D98). It must byte-for-byte match what
// pkgmeta.Distro.Ecosystem's "hummingbird" case returns — release-less
// ("Hummingbird", not "Hummingbird:1" or "Hummingbird:20251124") because
// Hummingbird ships one rolling stream: the CPE's trailing "1" is a CPE
// versioning artifact and the purl's "distro=hummingbird-20251124"
// qualifier (surfaced as os-release VERSION_ID too) is a dated build
// snapshot that changes every rebuild, not a release. Keying on either would
// fragment one rolling stream into phantom per-snapshot releases — the same
// reasoning D92 gives for MinimOS's frozen VERSION_ID, and the shape
// grype's own vunnel already assigns Hummingbird ({Alias: "hummingbird",
// Rolling: true}). TestEcosystemAgreesWithCataloger_Hummingbird
// cross-checks this constant against pkgmeta directly, the same discipline
// D77's TestKeyAgreesWithCataloger holds for SLES's fold.
const hummingbirdEcosystem = "Hummingbird"

// arches are stripped from a product ID's component half. A `fixed` entry is a
// full NEVRA with an architecture (`openssh-0:8.7p1-38.el9_4.1.x86_64`) and
// appears once per architecture; the inventory does not record one, so keeping
// it would store the same advisory four or five times over.
var arches = []string{
	".x86_64", ".aarch64", ".ppc64le", ".s390x", ".ppc64", ".i686",
	".noarch", ".src", ".i386", ".ia64", ".ppc", ".s390", ".armv7hl",
}

func stripArch(s string) string {
	for _, a := range arches {
		if t, ok := strings.CutSuffix(s, a); ok {
			return t
		}
	}
	return s
}

// splitContext separates a product component from the module or flatpak
// context it is scoped to. Red Hat marks those with "::":
//
//	python3-lxml::inkscape:flatpak   -> ("python3-lxml", "inkscape:flatpak")
//	Judy.src::mariadb:10.3           -> ("Judy.src",     "mariadb:10.3")
//	openssh-0:8.7p1-38.el9_4.1.x86_64 -> (unchanged,      "")
//
// It MUST run before splitNEVRA, and that ordering is the whole of this
// function. The context contains a colon, and splitNEVRA reads the first colon
// as the epoch separator — so on a bare `known_affected` name, which carries no
// epoch of its own, the context's colon is the first one and the name is
// truncated at the hyphen before it:
//
//	python3-lxml::inkscape:flatpak   -> name "python3"   (a real, different package)
//	389-ds-base::389-directory-server:1.4 -> name "389-ds"
//	ant-antlr::ant:1.10              -> name "ant"
//
// Measured over the whole archive: 453,164 of 6,315,078 mainline product
// entries (7.18%) carry a context, and parsing them without splitting it off
// first produced 786 distinct wrong package names across 828 CVEs. A
// differential run against grype on a real ubi9 image is what found it — one
// false positive there, `python3` carrying CVE-2022-2309, which belongs to
// python3-lxml inside an inkscape flatpak.
func splitContext(s string) (component, context string) {
	if i := strings.Index(s, "::"); i >= 0 {
		return s[:i], s[i+2:]
	}
	return s, ""
}

// splitNEVRA separates a product component into a package name and an EVR.
//
// The two shapes mean different things, and the difference is the whole point
// of this provider:
//
//	openssh-askpass-0:8.7p1-12.el9_0.1   -> ("openssh-askpass", "0:8.7p1-12.el9_0.1")
//	mailman                              -> ("mailman", "")
//
// A `fixed` entry always carries a version. A `known_affected` entry carries a
// BARE NAME, because Red Hat is saying the package is affected at every
// version it ships and there is nothing to upgrade to. An empty EVR is
// therefore not missing data — it is the statement.
//
// The name ends at the last hyphen BEFORE the epoch colon. Splitting on the
// first hyphen would turn "openssh-askpass" into "openssh", which is a real
// package with a different version.
func splitNEVRA(s string) (name, evr string) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return s, ""
	}
	j := strings.LastIndexByte(s[:i], '-')
	if j < 0 {
		return s, ""
	}
	return s[:j], s[j+1:]
}

// isModule reports whether an EVR belongs to a modular build.
//
// Called only when resolveProduct found no "::" context (D80): a module
// build named WITH a context carries the stream that context supplies and is
// stored, streamed, same as any other entry. This function exists for what
// is left over — a module-tagged EVR whose product id carries no context at
// all, so nothing says which stream it belongs to. 19.1% of mainline groups
// are module-tagged, and `nodejs:18` and `nodejs:20` are indistinguishable
// from the version alone. ('CVE-2021-20291', 'buildah', '8') is the real
// archive row that showed why guessing is wrong either way: two streams of
// container-tools resolve to two different fixed versions, taking the higher
// is a systematic false positive against a host on the lower stream, and
// taking the lower is a false negative against a host on the higher one. D80
// resolved that exact row by attaching the context's stream instead — both
// streams are stored, separately, each judged only against a host installed
// from it — so this guard is only what fires on a build with neither an EVR
// stream marker's context nor any other way to say which stream it is.
//
// Red Hat writes `module+el`; AlmaLinux writes `module_el`. Both are matched
// so the rule does not quietly stop applying if this provider ever reads an
// Alma feed.
//
// **It fires zero times on the current archive**, and that is recorded rather
// than left to be rediscovered as a suspicious no-op. Every module-built
// product id measured also carries a `::` context, so resolveProduct's
// context branch reaches all of them first and stores them with a stream
// instead. The check stays because the two detections are independent — a
// feed could name a module build without a context, and AlmaLinux's
// `module_el` spelling exists in a feed this provider does not read yet —
// and because a guard that is cheap and occasionally right is worth more
// than one deleted on the strength of a single archive. TestIsModule and
// TestConvert exercise it directly, so it is unreached rather than untested.
func isModule(evr string) bool {
	return strings.Contains(evr, "module+el") || strings.Contains(evr, "module_el")
}

// ecosystemFor maps a platform CPE to the store's ecosystem key, or reports
// false for a product this provider does not ingest.
//
// Hummingbird is checked first (D98): its CPE never matches mainlineCPE's
// "enterprise_linux" name, so the order between the two checks does not
// matter for correctness today, but checking the narrower, single-purpose
// pattern first keeps this function reading as "what IS this platform"
// rather than "what is this platform NOT", the same order resolveProduct's
// own doc comment already keeps between its checks.
func ecosystemFor(cpe string) (string, bool) {
	if hummingbirdCPE.MatchString(cpe) {
		return hummingbirdEcosystem, true
	}
	m := mainlineCPE.FindStringSubmatch(cpe)
	if m == nil {
		return "", false
	}
	return "Red Hat:" + m[1], true
}

// collectCPE walks the product_tree's branches, mapping each platform product
// ID to its CPE.
func collectCPE(bs []branch, out map[string]string) {
	for i := range bs {
		if p := bs[i].Product; p != nil && p.Helper.CPE != "" {
			out[p.ProductID] = p.Helper.CPE
		}
		collectCPE(bs[i].Branches, out)
	}
}

// hummingbirdPurlRE splits a Hummingbird leaf's purl into a package name and
// version, copy-adapted from SUSE's identical-shaped purlRE (D77's proven
// pattern, internal/provider/suse/csaf.go) rather than reused from splitNEVRA
// — Hummingbird's product id is a STREAM LABEL ("perl-main@x86_64"), not an
// NEVRA, and fans out to more than one real package under one label
// ("perl-main@noarch" resolves to perl-Attribute-Handlers, not perl), so the
// only place the real name and version live is here.
//
// Unlike SUSE's purls, a Hummingbird purl's version half is OPTIONAL: 533 of
// 544 sampled carry one ("pkg:rpm/redhat/perl@5.42.2-524.hum1?arch=..."), but
// 11 are bare names with no "@" at all
// ("pkg:rpm/redhat/opentofu1.10?arch=src") — D47's "affected at every
// version" convention, read here as SUSE's own packageOf reads a bare
// component: an empty version is the statement, not missing data. The
// version group is therefore optional in the pattern rather than assumed
// present the way SUSE's purlRE (fed only by "recommended"/fixed entries,
// always versioned) can assume.
var hummingbirdPurlRE = regexp.MustCompile(`^pkg:rpm/redhat/([^@?]+)(?:@([^?]*))?`)

// packageInfo is one Hummingbird leaf's package name and version, read off
// its purl rather than guessed from the product id string (SUSE's
// packageInfo, copy-adapted).
type packageInfo struct{ name, version string }

// hummingbirdPackageOf splits a Hummingbird leaf's purl into a package name
// and version, or reports false — for a purl this provider does not read at
// all (measured live: "pkg:oci/opentofu?repository_url=..." names an OCI
// image, not an rpm, and nothing installed by rpm could ever match one) or
// for no purl at all.
func hummingbirdPackageOf(purl string) (name, version string, ok bool) {
	m := hummingbirdPurlRE.FindStringSubmatch(purl)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// collectHummingbirdPackages walks the WHOLE product tree's leaf nodes,
// mapping every product id whose purl reads as an installable Hummingbird rpm
// to its package name and version.
//
// Walked over the whole tree rather than restricted to the subtree under the
// Hummingbird platform branch, mirroring SUSE's collectPackages (D77): a
// document's product ids are unique within that one document regardless of
// which platform declares them, and mainline RHEL's own leaf nodes carry a
// purl too on the live 2026-08-27 archive but never one hummingbirdPackageOf
// accepts as an rpm with a "redhat" namespace AND a shape this map's callers
// ever look up under (mainline's product ids are the full "platform:NEVRA"
// compound the fixed/known_affected arrays name directly, not a bare
// product-tree leaf id) — so a mainline leaf populating this map is inert,
// never reached by a lookup a Hummingbird-scoped resolveProduct call makes.
func collectHummingbirdPackages(bs []branch, out map[string]packageInfo) {
	for i := range bs {
		if p := bs[i].Product; p != nil && p.Helper.Purl != "" {
			if name, version, ok := hummingbirdPackageOf(p.Helper.Purl); ok {
				out[p.ProductID] = packageInfo{name: name, version: version}
			}
		}
		collectHummingbirdPackages(bs[i].Branches, out)
	}
}

// productKey is what one CSAF product id collapses to: the store's ecosystem,
// the package name inside it, and the module stream if any (D80). Two streams
// of one module — "nodejs:18" and "nodejs:20" — are two keys, not one: they
// fix on independent timelines, and merging them would be the same unsound
// comparison D47 refused when the release string alone was all there was to
// go on. stream is "" for an ordinary, non-modular entry.
type productKey struct{ eco, pkg, stream string }

// skipReason names why a product id yields no key.
//
// It is RETURNED rather than counted at the point of failure because the two
// callers want different things from the same parse. A product_status entry is
// inventory and every discard is disclosed (stats exists for that). A
// remediation naming a product outside the mainline slice is not a discard at
// all — it is a statement about something this store never held — and counting
// those in the same totals would roughly triple every skip line for no gain.
type skipReason int

const (
	skipNone skipReason = iota
	skipWholeProduct
	skipBadProduct
	skipImage
	skipNoCPE
	skipNonRHEL
	skipFlatpak
	skipModuleContext
	skipModule
	// skipNoPurl is Hummingbird-specific (D98): the component half of a
	// "platform:component" id resolved to a real Hummingbird platform but no
	// leaf in the product tree carries a purl this provider reads for it —
	// either the id names no leaf at all, or the leaf's purl is not an
	// installable rpm ("pkg:oci/..." names a container image, not a
	// package). Distinguished from skipBadProduct because the mainline
	// shape that reason names (an unparsable NEVRA string) cannot occur
	// here: Hummingbird's component is never parsed as a string at all.
	skipNoPurl
)

// resolveProduct turns "platform:component" into a key and an EVR.
//
// The order of the checks is load-bearing and matches the order the failures
// occur in the data: separator, emptiness, image digest, platform CPE,
// mainline filter, context (flatpak vs. module vs. malformed), the name/EVR
// split, then the context-less module guard. splitContext MUST stay ahead of
// splitNEVRA for the reason splitContext documents.
//
// D80 reversed what a "::" context does here. It used to mean an unconditional
// drop (skipModuleContext, unconditionally): the scan could not know which
// module stream was enabled, so matching the bare name would risk a false
// positive against a different stream's fix. The context turns out to BE the
// stream name Red Hat left out of the release string — rpmdb's
// RPMTAG_MODULARITYLABEL carries the same "name:stream" shape (D80's cataloger
// half) — so an entry that carries one is now kept, with the stream attached,
// rather than dropped for lacking exactly the information it names.
//
// D98 branches once eco is known: a Hummingbird component is a STREAM LABEL
// ("perl-main@x86_64"), never an NEVRA, so splitContext/splitNEVRA — written
// for Red Hat's "name-EPOCH:VERSION-RELEASE.ARCH" compound string — would
// either misparse it or silently invent a package name that happens to share
// a prefix, the exact D80 hazard splitContext's own doc comment names. The
// purl-based lookup this project already trusts for that shape (SUSE's
// packageOf, D77) reads the real name and version instead, so Hummingbird
// never reaches splitContext, isModule or splitNEVRA at all.
func resolveProduct(id string, cpe map[string]string, hummingbirdPkgs map[string]packageInfo) (productKey, string, skipReason) {
	plat, comp, ok := strings.Cut(id, ":")
	if !ok {
		// No separator means the entry names a whole product and no package.
		// See stats.SkippedWholeProduct.
		return productKey{}, "", skipWholeProduct
	}
	if comp == "" {
		return productKey{}, "", skipBadProduct
	}
	if strings.Contains(comp, "@sha256:") {
		// A container image, identified by digest rather than by version.
		// Nothing in the RPM inventory can match one.
		return productKey{}, "", skipImage
	}
	c, ok := cpe[plat]
	if !ok {
		return productKey{}, "", skipNoCPE
	}
	eco, ok := ecosystemFor(c)
	if !ok {
		return productKey{}, "", skipNonRHEL
	}
	if eco == hummingbirdEcosystem {
		pkg, ok := hummingbirdPkgs[comp]
		if !ok {
			return productKey{}, "", skipNoPurl
		}
		return productKey{eco: eco, pkg: pkg.name}, pkg.version, skipNone
	}
	comp, context := splitContext(comp)
	var stream string
	if context != "" {
		if strings.HasSuffix(context, ":flatpak") {
			// Flatpak content is not a module and is not in the rpmdb at all
			// (D47): nothing installed can ever carry it, so treating
			// "flatpak" as a stream name would invite a join against a
			// package that was never really modular. Measured 4,999 on the
			// 2026-08-19 archive, all known_affected.
			return productKey{}, "", skipFlatpak
		}
		name, rest, cut := strings.Cut(context, ":")
		if !cut || name == "" || rest == "" {
			// Every context in the 2026-08-19 archive parses as exactly
			// "name:stream" — one colon, both halves non-empty — across all
			// 463,701 module-scoped and 4,999 flatpak-scoped entries
			// measured. This is the guard for a feed that stops being that
			// shape, not a path real data takes today.
			return productKey{}, "", skipModuleContext
		}
		stream = name + ":" + rest
	}
	name, evr := splitNEVRA(stripArch(comp))
	if name == "" {
		return productKey{}, "", skipBadProduct
	}
	if stream == "" && isModule(evr) {
		// D80's load-bearing zero, carried over unchanged from the rule
		// isModule's own comment documents: a module-tagged build with no
		// "::" context cannot say which stream it belongs to, so it is
		// dropped rather than guessed at, and the guard stays even though
		// every module build measured also carried a context (isModule's
		// comment explains why a cheap, occasionally-right guard survives a
		// zero count).
		return productKey{}, "", skipModule
	}
	return productKey{eco, name, stream}, evr, skipNone
}

// The two CSAF remediation categories that say why a package has no fix.
//
// The feed uses four of the spec's six. `vendor_fix` and `workaround` are read
// and ignored on purpose: neither answers the question. A `vendor_fix` sitting
// on a package that ALSO has no fix is the point-release collapse D47 already
// documents — fixed on one channel, not on another, both folding into one
// major — and a `workaround` is a second axis entirely, present alongside every
// other category. Measured over the 2026-08-09 archive: of the 1,282,093
// mainline (CVE, ecosystem, package) tuples with no fixed version, every single
// one is named by no_fix_planned or none_available. Not one is left with only
// vendor_fix or workaround to go on, which is why stats.UnfixableUnstated
// reading zero is the expected result rather than a suspicious one.
const (
	remedyNoFixPlanned  = "no_fix_planned"
	remedyNoneAvailable = "none_available"
)

// fixStateFor picks one state from the categories that named a package.
//
// no_fix_planned wins when a package carries both, and the tie is broken
// deliberately rather than by whichever was read first (the discipline D25 sets
// for severity). The two errors are not symmetric: calling a package
// "won't fix" when a fix later arrives is a false alarm the reader dismisses on
// the next scan, while calling it "no fix yet" when none is ever coming leaves
// them waiting on a fix that does not exist — the quiet failure this provider
// exists to prevent.
//
// The blast radius is small either way. 179 of the 1,282,093 unfixable tuples
// in the 2026-08-09 archive carry both categories — 0.014% — and every one
// sampled was kernel-rt on RHEL 9, a package that ships many parallel
// point-release variants and is not present in a container image at all. The
// count is disclosed so that a feed which started disagreeing with itself in
// bulk would be visible rather than silently resolved 179 times over.
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
		// Red Hat said the package is affected and gave no reason for there
		// being no fix. Left unstated rather than guessed at (D17's rule for
		// absent severity, applied to absent intent).
		st.UnfixableUnstated++
		return advisory.FixStateUnknown
	}
}

// keepModule records one product_status entry stored with a module stream
// (D80): the raw count ModuleKept reports, and the stream itself for the
// distinct-stream count String() derives from it.
func (s *stats) keepModule(stream string) {
	s.ModuleKept++
	if s.moduleStreams == nil {
		s.moduleStreams = map[string]bool{}
	}
	s.moduleStreams[stream] = true
}

// stats counts what one conversion pass discarded, so a sync can report it.
// A provider that silently drops two thirds of its input is indistinguishable
// from one that is broken.
type stats struct {
	Documents  int
	Advisories int
	Affected   int
	Unfixable  int // affected entries with no fixed version at all
	// The D52 split of Unfixable. The three are disjoint and sum to it, so a
	// drift between them and the total is a bug rather than a rounding.
	UnfixableWontFix  int // Red Hat said no fix is planned
	UnfixableNotFixed int // Red Hat said none is available yet
	// UnfixableUnstated is affected with no fix and no reason given. Zero on
	// every archive measured; a non-zero one means the feed changed shape and
	// the reasons stopped arriving, which is worth seeing rather than reading
	// as "nothing to report".
	UnfixableUnstated int
	// UnfixableBothReasons overlaps UnfixableWontFix — it counts the packages
	// Red Hat tagged both ways, which fixStateFor resolves toward wont-fix.
	UnfixableBothReasons int
	// RemediationGrouped counts remediations that name a product_groups entry
	// instead of listing products. Zero on every archive measured; see the
	// GroupIDs field for why it is counted rather than expanded.
	RemediationGrouped int
	// ModuleKept counts product_status entries scoped to a module stream and
	// STORED with one (D80) — the reversal of what a "::" context used to mean
	// here. Counted once per raw product id, the same granularity as every
	// other counter below, so it lines up with the archive measurement
	// (463,701 module-scoped entries, of which the flatpak share is counted
	// separately below).
	ModuleKept int
	// moduleStreams is the set of distinct "name:stream" values ModuleKept
	// entries carried, read only through its length (see String()). Cheap to
	// keep: RHEL's modules number in the low thousands across the whole
	// archive, not the millions ModuleKept counts.
	moduleStreams map[string]bool
	// SkippedModule is a module-TAGGED build (its EVR carries "module+el" or
	// "module_el") with NO "::" context to say which stream it belongs to —
	// D80's load-bearing zero, carried over unchanged from the rule isModule
	// documents. Measured zero on every archive: every module build the feed
	// has ever carried also carried a context.
	SkippedModule int
	// SkippedFlatpak is an entry scoped by "::" to a flatpak rather than a
	// module (D80): flatpak content is not in the rpmdb at all, so treating
	// "flatpak" as a stream name would invite a join no installed package
	// could ever satisfy. Measured 4,999 on the 2026-08-19 archive, all
	// known_affected.
	SkippedFlatpak int
	// SkippedModuleContext is a "::" context that is neither a flatpak nor the
	// measured "name:stream" shape — no colon, or an empty half. Zero on every
	// archive measured (100% of contexts parse cleanly); kept as a guard
	// against a feed that stops being that shape, the same discipline
	// isModule's zero and SkippedModule's zero both document.
	SkippedModuleContext int
	SkippedNonRHEL       int
	SkippedNoCPE         int
	SkippedNoCVE         int
	SkippedImage         int
	// SkippedWholeProduct is an entry that names a PRODUCT and no package at
	// all — "Red Hat Linux 6.2", "Red Hat Enterprise Linux AS (Advanced
	// Server) version 2.1", "Red Hat Powertools 7.0". Red Hat used that form
	// for its pre-2005 releases, and nothing in an RPM inventory can match a
	// claim with no package name in it.
	//
	// It is a category rather than a failure, and finding that out is why the
	// counters below are split. A first run folded these in with genuinely
	// unreadable input and reported "9,430 unreadable" — which was alarming,
	// wrong, and would have been believed.
	SkippedWholeProduct int
	// SkippedBadProduct is an entry this provider genuinely could not read:
	// a separator with nothing after it, or nothing left of the name once the
	// architecture and version came off. Measured over the whole archive this
	// is zero, and it staying zero is what the guard in the real-archive run
	// checks.
	SkippedBadProduct int
	SkippedBadDoc     int
	// SkippedNoPurl is D98's Hummingbird-specific discard: a component that
	// resolved to the Hummingbird ecosystem but named no leaf this provider
	// reads a package out of — either the id names no product-tree leaf at
	// all, or the leaf's purl is not an installable rpm ("pkg:oci/..."
	// content). Counted separately from SkippedBadProduct because the two
	// name genuinely different failures: SkippedBadProduct is a string this
	// provider could not parse, and Hummingbird's component is never parsed
	// as a string.
	SkippedNoPurl int
	// The delta pass (delta.go). Counted apart from the archive's numbers
	// because they answer different questions: the archive's say what the
	// snapshot held, these say how far behind it was.
	DeltaListed     int // documents changes.csv named as newer than the archive
	DeltaFetched    int // of those, how many were still published
	DeltaGone       int // and how many had been withdrawn between the two files
	DeltaAdvisories int // how many of the fetched ones yielded a record
	// DeltaRetried is extra attempts made; DeltaRescued is documents that
	// succeeded only because of one (D58). Both are printed because they
	// answer different questions: the first is how flaky the fetch was,
	// the second is how many builds the retry saved. A run with retries and
	// no rescues means the retry is buying nothing and the failures are
	// permanent after all.
	DeltaRetried int
	DeltaRescued int
}

// convert turns one CSAF document into at most one advisory.
//
// One document is one CVE, so the whole document collapses to a single record
// with one Affected entry per (ecosystem, package). D25's grouping works
// through the CVE carried in Aliases (see the ID field below), not through
// the record's own ID: that ID is now REDHAT-prefixed, so two records for one
// CVE join by sharing an identifier rather than by having the same one.
func convert(d *document, st *stats) (advisory.Advisory, bool) {
	st.Documents++

	cpe := map[string]string{}
	collectCPE(d.ProductTree.Branches, cpe)
	// D98: read unconditionally, not gated on whether this document mentions
	// Hummingbird at all. The overwhelming majority of documents carry no
	// Hummingbird content and this walk finds nothing to add, at the cost of
	// one cheap tree walk alongside collectCPE's own — the same trade every
	// other per-document map here already makes.
	hummingbirdPkgs := map[string]packageInfo{}
	collectHummingbirdPackages(d.ProductTree.Branches, hummingbirdPkgs)

	cve := d.Document.Tracking.ID
	if len(d.Vulnerabilities) > 0 && d.Vulnerabilities[0].CVE != "" {
		cve = d.Vulnerabilities[0].CVE
	}
	if !strings.HasPrefix(cve, "CVE-") {
		// Red Hat tracks a few pre-CVE issues under their own IDs. They carry
		// no identifier any other source shares, so a finding from one could
		// never be grouped or checked.
		st.SkippedNoCVE++
		return advisory.Advisory{}, false
	}

	// fixedFor accumulates the fixed versions seen per (ecosystem, package),
	// and affected records the ones with no fix. A package can appear in both
	// — fixed on one minor release and unfixed on another — and both belong in
	// the record.
	fixed := map[productKey]map[string]bool{}
	unfixed := map[productKey]bool{}
	// remedy records which reasons Red Hat gave, per package, for a fix not
	// existing. Filled from the remediation lists, which are a separate section
	// of the document from product_status and join to it by product id.
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
		k, evr, why := resolveProduct(id, cpe, hummingbirdPkgs)
		switch why {
		case skipWholeProduct:
			st.SkippedWholeProduct++
			return
		case skipBadProduct:
			st.SkippedBadProduct++
			return
		case skipImage:
			st.SkippedImage++
			return
		case skipNoCPE:
			st.SkippedNoCPE++
			return
		case skipNonRHEL:
			st.SkippedNonRHEL++
			return
		case skipFlatpak:
			st.SkippedFlatpak++
			return
		case skipModuleContext:
			st.SkippedModuleContext++
			return
		case skipModule:
			st.SkippedModule++
			return
		case skipNoPurl:
			st.SkippedNoPurl++
			return
		}
		note(k)
		if k.stream != "" {
			st.keepModule(k.stream)
		}
		if isFixed && evr != "" {
			if fixed[k] == nil {
				fixed[k] = map[string]bool{}
			}
			fixed[k][evr] = true
			return
		}
		// Either an explicit known_affected, or a fixed entry with no version
		// to compare against — which says the same thing and must not be
		// dropped as malformed.
		unfixed[k] = true
	}

	var sev []advisory.Severity
	for i := range d.Vulnerabilities {
		v := &d.Vulnerabilities[i]
		for _, id := range v.ProductStatus.Fixed {
			add(id, true)
		}
		for _, id := range v.ProductStatus.KnownAffected {
			add(id, false)
		}
		for _, r := range v.Remediations {
			if len(r.GroupIDs) > 0 {
				st.RemediationGrouped++
			}
			// A filter for memory, not for correctness, and a mutation of it
			// survives the whole test table: fixStateFor reads only the two
			// keys it names, so letting vendor_fix and workaround into the map
			// changes no answer. What it changes is the map's size on a feed
			// where those two are 74% of all remediation objects (114,155 of
			// 154,795). Recorded here rather than left to read as an untested
			// branch forever.
			if r.Category != remedyNoFixPlanned && r.Category != remedyNoneAvailable {
				continue
			}
			for _, id := range r.ProductIDs {
				// Skips are not counted here; resolveProduct's doc comment says
				// why. A remediation naming a product this store does not hold
				// is not a discard.
				//
				// D80 also fixed what this join could reach: a remediation
				// naming a module-scoped product id used to resolve to
				// skipModuleContext unconditionally, so `why != skipNone`
				// dropped it here too — silently, because this loop does not
				// count skips. Now that resolveProduct returns skipNone (and
				// the stream, inside k) for a module-scoped id, the same
				// no_fix_planned/none_available reason reaches a module
				// package's range exactly as it already did for an ordinary
				// one.
				k, _, why := resolveProduct(id, cpe, hummingbirdPkgs)
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
		// D90: prefixed, following DEBIAN-CVE-*/UBUNTU-CVE-*/ALPINE-CVE-*'s
		// convention. Before this, ID was the bare CVE, and so was SUSE's
		// (D77) — the store's by-id bucket is last-writer-wins on ID, so a
		// full multi-provider build had one vendor's record silently clobber
		// the other's for every CVE both name (measured: ubi9 lost 91% of its
		// Red Hat tuples). Aliases carries the bare CVE instead of Upstream:
		// D25 grouping (matcher.identifiers) reads ID+Aliases, not Upstream,
		// so this is what keeps Red Hat's and SUSE's records for one CVE
		// joining into a single finding, and annotate()'s
		// HasPrefix(id, "CVE-") walk over Identifiers (built from Aliases
		// too) still finds the bare CVE for NVD/EPSS/KEV/KISA joins.
		ID:       "REDHAT-" + cve,
		Database: "REDHAT",
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  d.Document.Title,
		Severity: dedupeSeverity(sev),
		Aliases:  []string{cve},
	}
	for _, k := range order {
		// ModuleStream carries D80's stream, or "" for an ordinary entry —
		// productKey.stream is already in the shape Affected.ModuleStream
		// documents ("name:stream"), so no further translation happens here.
		a := advisory.Affected{Ecosystem: k.eco, Name: k.pkg, ModuleStream: k.stream}
		if vs := fixed[k]; len(vs) > 0 {
			for _, v := range sortedKeys(vs) {
				a.Ranges = append(a.Ranges, advisory.Range{
					Type:   advisory.RangeEcosystem,
					Events: []advisory.Event{{Introduced: "0"}, {Fixed: v}},
				})
			}
		}
		if unfixed[k] {
			// D48. An introduced event with NO fixed event is how OSV spells
			// "affected at every version", and it is exactly what Red Hat is
			// saying. It is not a range the ingestion should repair or drop:
			// 1,292,054 of the 1,995,138 mainline records this feed yields are
			// this shape, and they are the whole reason the provider exists.
			//
			// The state rides on this range and not on the Affected entry
			// because the same package can be fixed on one release and
			// permanently affected on another — both ranges are emitted here,
			// side by side, and only the range knows which it is (D52).
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

// sortedKeys keeps the emitted ranges in a stable order. Two builds of the
// same input must produce the same database, or `db push` layers a delta that
// is mostly noise.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Plain lexical order: this is a set of version strings whose only job is
	// to be deterministic, and ordering them with the RPM comparer would make
	// ingestion depend on a comparer that D43 has not registered yet.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
