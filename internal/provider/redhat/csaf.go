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
// These are dropped rather than stored, and the count is disclosed. 19.1% of
// mainline groups are module-tagged and modules cause 69% of the fixed-version
// ambiguity that survives the mainline filter, because the release string
// records the platform build and a context hash but NOT the stream name:
// `nodejs:18` and `nodejs:20` are indistinguishable from the version alone.
// ('CVE-2021-20291', 'buildah', '8') resolves to two fixed versions from two
// streams of container-tools — taking the higher is a systematic false
// positive and taking the lower is a false negative, so neither is stored.
//
// Red Hat writes `module+el`; AlmaLinux writes `module_el`. Both are matched
// so the rule does not quietly stop applying if this provider ever reads an
// Alma feed.
//
// **It fires zero times on the current archive**, and that is recorded rather
// than left to be rediscovered as a suspicious no-op. Every module-built
// product id in the 2026-08-05 archive also carries a `::` context, so
// splitContext catches all of them first: the counts moved from 431,985
// module builds and 0 contexts to 0 and 453,164 when that check was added.
// The check stays because the two detections are independent — a feed could
// name a module build without a context, and AlmaLinux's `module_el` spelling
// exists in a feed this provider does not read yet — and because a guard that
// is cheap and occasionally right is worth more than one deleted on the
// strength of a single archive. TestIsModule and TestConvert exercise it
// directly, so it is unreached rather than untested.
func isModule(evr string) bool {
	return strings.Contains(evr, "module+el") || strings.Contains(evr, "module_el")
}

// ecosystemFor maps a platform CPE to the store's ecosystem key, or reports
// false for a product this provider does not ingest.
func ecosystemFor(cpe string) (string, bool) {
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

// stats counts what one conversion pass discarded, so a sync can report it.
// A provider that silently drops two thirds of its input is indistinguishable
// from one that is broken.
type stats struct {
	Documents     int
	Advisories    int
	Affected      int
	Unfixable     int // affected entries with no fixed version at all
	SkippedModule int
	// SkippedModuleContext is an entry scoped to a module or flatpak by a "::"
	// suffix. Counted apart from SkippedModule because the two are found
	// differently — one by the release string, one by the product id — and a
	// single counter would hide which detection was doing the work.
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
	// The delta pass (delta.go). Counted apart from the archive's numbers
	// because they answer different questions: the archive's say what the
	// snapshot held, these say how far behind it was.
	DeltaListed     int // documents changes.csv named as newer than the archive
	DeltaFetched    int // of those, how many were still published
	DeltaGone       int // and how many had been withdrawn between the two files
	DeltaAdvisories int // how many of the fetched ones yielded a record
}

// convert turns one CSAF document into at most one advisory.
//
// One document is one CVE, so the whole document collapses to a single record
// with one Affected entry per (ecosystem, package). That is what lets D25's
// grouping work unchanged: the record's own ID is the CVE, so it joins to
// every other database's record for the same vulnerability without an alias
// lookup.
func convert(d *document, st *stats) (advisory.Advisory, bool) {
	st.Documents++

	cpe := map[string]string{}
	collectCPE(d.ProductTree.Branches, cpe)

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
	type key struct{ eco, pkg string }
	fixed := map[key]map[string]bool{}
	unfixed := map[key]bool{}
	order := []key{}
	seen := map[key]bool{}
	note := func(k key) {
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}

	add := func(id string, isFixed bool) {
		plat, comp, ok := strings.Cut(id, ":")
		if !ok {
			// No separator means the entry names a whole product and no
			// package. See stats.SkippedWholeProduct.
			st.SkippedWholeProduct++
			return
		}
		if comp == "" {
			st.SkippedBadProduct++
			return
		}
		if strings.Contains(comp, "@sha256:") {
			// A container image, identified by digest rather than by version.
			// Nothing in the RPM inventory can match one.
			st.SkippedImage++
			return
		}
		c, ok := cpe[plat]
		if !ok {
			st.SkippedNoCPE++
			return
		}
		eco, ok := ecosystemFor(c)
		if !ok {
			st.SkippedNonRHEL++
			return
		}
		comp, context := splitContext(comp)
		if context != "" {
			// Module- and flatpak-scoped, and dropped for D47's reason: the
			// scan cannot know which module streams are enabled, and a flatpak's
			// contents are not in the rpmdb at all. Matching the bare name
			// regardless of stream would be a false positive against a host
			// running a different one, which is the same trade D47 refused for
			// module FIXED versions.
			st.SkippedModuleContext++
			return
		}
		name, evr := splitNEVRA(stripArch(comp))
		if name == "" {
			st.SkippedBadProduct++
			return
		}
		if isModule(evr) {
			st.SkippedModule++
			return
		}
		k := key{eco, name}
		note(k)
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
		Database: "REDHAT",
		Source:   SourceName,
		Kind:     advisory.KindVulnerability,
		Summary:  d.Document.Title,
		Severity: dedupeSeverity(sev),
		// The record's own ID is the CVE, so Upstream carries it too rather
		// than being left empty: D3's join reads `aliases` and `upstream`, and
		// a reader grepping for the CVE in either should find it.
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
			// D48. An introduced event with NO fixed event is how OSV spells
			// "affected at every version", and it is exactly what Red Hat is
			// saying. It is not a range the ingestion should repair or drop:
			// 1,292,054 of the 1,995,138 mainline records this feed yields are
			// this shape, and they are the whole reason the provider exists.
			a.Ranges = append(a.Ranges, advisory.Range{
				Type:   advisory.RangeEcosystem,
				Events: []advisory.Event{{Introduced: "0"}},
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
