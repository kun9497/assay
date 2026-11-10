// Package cyclonedx turns a CycloneDX SBOM into the normalized inventory.
//
// This is a Cataloger like any other: later slices add image and binary
// catalogers that produce the same pkgmeta.Target, so nothing downstream
// changes when they arrive.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/pkgmeta"
)

// Stats records what the cataloger could not use. Reported rather than
// discarded: a package silently dropped here is indistinguishable from a
// package with no vulnerabilities.
type Stats struct {
	Components                  int
	Cataloged                   int
	SkippedNoPURL               int
	SkippedNoVersion            int
	SkippedUnsupportedEcosystem int
	// SerialNumber (CycloneDX) and DocumentNamespace (SPDX) are the SBOM's
	// own identity as its producer wrote it, carried for the scan's
	// provenance record (D120). Not counts: every other cataloger leaves both
	// empty, and nothing sums them.
	SerialNumber      string
	DocumentNamespace string
}

type bom struct {
	BOMFormat    string      `json:"bomFormat"`
	SerialNumber string      `json:"serialNumber"`
	Metadata     metadata    `json:"metadata"`
	Components   []component `json:"components"`
}

// metadata carries the document's subject: metadata.component is the slot
// CycloneDX reserves for the thing the SBOM is about. For an image SBOM that
// is the image (syft: a purl-less container); for a library's own SBOM it is
// the library, and a generator may nest the inventory under it
// (metadata.component.components) instead of, or as well as, bom.components.
type metadata struct {
	Component *component `json:"component"`
}

type component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	// CycloneDX lets a component carry its own components array. Reading only
	// the top level would make those packages invisible — not skipped, but
	// absent from every counter, which is worse than a counted skip because
	// nothing in the report hints they existed.
	Components []component `json:"components"`
	Properties []property  `json:"properties"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func Parse(r io.Reader) (pkgmeta.Target, Stats, error) {
	var doc bom
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("decode CycloneDX: %w", err)
	}
	if doc.BOMFormat != "CycloneDX" {
		return pkgmeta.Target{}, Stats{}, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BOMFormat)
	}

	var (
		target pkgmeta.Target
		stats  Stats
	)
	// syft emits the distro as a component of type "operating-system", not on
	// metadata.component — and the real fixture puts it last (components[16] of
	// 17), after the packages that need its release. So the whole document is
	// read for the distro in a first pass, before packages are cataloged in a
	// second: a single forward pass would catalog every apk package unkeyed.
	//
	// QA 2026-11-10: the operating-system component is read where it sits.
	// A distro package is keyed by the OS declared beside it -- among its own
	// siblings -- or, failing one, by the nearest unambiguous one above it,
	// so an OS component nested with its packages under metadata.component
	// keys them (Alpine and busybox moved under the subject read 0 findings,
	// not evaluated, exit 2), and one branch's OS never keys another
	// branch's packages. See osContext.
	top := contextFor(doc.Components, osContext{})
	target.Distro = documentDistro(doc, top)

	catalog(doc.Components, top, &target, &stats)
	if doc.Metadata.Component != nil {
		catalogSubject(*doc.Metadata.Component, top, &target, &stats)
	}
	stats.SerialNumber = doc.SerialNumber
	return target, stats, nil
}

// catalogSubject reads metadata.component after bom.components (QA
// 2026-11-02, "CycloneDX subject"). Until then the reader walked
// bom.components only, so a vulnerable library written as the document's
// subject -- lodash 4.17.20 as metadata.component, the shape a library's own
// SBOM takes -- or nested under the subject was never cataloged: not
// scanned, not counted, in no skip bucket, exit 0 under --fail-on low
// --fail-on-incomplete=target. The subject is excluded only by what it IS,
// the rule #230 set for SPDX's DESCRIBES (spdx.pseudoPackageShape): a
// document-root shape -- no purl (syft's container), a pkg:oci purl (Red
// Hat's image), a purl without a version (a product named without a build)
// -- is dropped uncounted exactly as before, so the one syft fixture still
// counts four components; anything else the subject is gets whatever a
// top-level twin would have got, a candidate or a counted skip.
//
// The subject's own nested components are the inventory when a generator
// writes it there, so they are cataloged like top-level components -- every
// skip counted, no pseudo-package rule -- and the same walk applies to their
// children.
//
// Dedupe: a generator that names the root package in its own inventory lists
// one package twice, as subject and as component. Cataloging the subject
// tree second, a package bom.components already yielded is dropped
// uncounted here, so the report says one package and one finding, not two
// -- and the dropped listing's evidence (its locations, a source identity
// only it carried) is folded onto the kept one, so the report still shows
// every place the document listed the package. The dedupe is the subject
// tree against bom.components and nothing else: two top-level listings, or
// two listings both nested under the subject, were never read as one
// package and stay two, so where a generator put its inventory does not
// change how many packages it holds.
func catalogSubject(subject component, ctx osContext, target *pkgmeta.Target, stats *Stats) {
	// The dedupe base is fixed before the subject tree adds anything to
	// target.Packages: everything bom.components yielded, and only that.
	base := len(target.Packages)
	// The subject is keyed in the document's top-level context, as its
	// top-level twin would be; its children in theirs (contextFor).
	scratchTarget := pkgmeta.Target{}
	var scratchStats Stats
	catalogOne(subject, ctx, &scratchTarget, &scratchStats)
	// The len check is defensive only: every root shape pseudoSubjectShape
	// accepts already implies catalogOne appended no package (no purl and a
	// pkg:oci purl both skip before a package is built -- "oci" is not an
	// ecosystem -- and SkippedNoVersion == 1 returns before one is built).
	// Dropping it changes nothing; it states the intent that a subject which
	// yielded a package is never treated as the root.
	if len(scratchTarget.Packages) == 0 && pseudoSubjectShape(subject, scratchStats) {
		// The document's own root: not a package, not counted, as the
		// operating-system component is not.
	} else {
		mergeDeduped(scratchTarget, scratchStats, base, target, stats)
	}
	catalogDeduped(subject.Components, childContext(subject, ctx), base, target, stats)
}

// catalogDeduped is catalog for the subject's nested components: the same
// depth-first walk, one scratch per component so a duplicate of a package
// bom.components already yielded can be dropped without its counter. base
// is how many packages bom.components yielded; see catalogSubject.
func catalogDeduped(components []component, ctx osContext, base int, target *pkgmeta.Target, stats *Stats) {
	for _, c := range components {
		scratchTarget := pkgmeta.Target{}
		var scratchStats Stats
		catalogOne(c, ctx, &scratchTarget, &scratchStats)
		mergeDeduped(scratchTarget, scratchStats, base, target, stats)
		catalogDeduped(c.Components, childContext(c, ctx), base, target, stats)
	}
}

// mergeDeduped folds one component's scratch result into the inventory.
// catalogOne yields at most one package per component, so a scratch holding
// a package that target.Packages[:base] -- what bom.components yielded --
// already carries is that component's second listing: dropped with its
// counters, because a second Components++ would say the document held two
// packages where it held one listed twice, but its evidence is kept on the
// package already there. A scratch with no package is a counted skip and
// merges as it is.
func mergeDeduped(scratchTarget pkgmeta.Target, scratchStats Stats, base int, target *pkgmeta.Target, stats *Stats) {
	for _, p := range scratchTarget.Packages {
		if i := indexOfPackage(target.Packages[:base], p); i >= 0 {
			keepEvidence(&target.Packages[i], p)
			return
		}
	}
	target.Packages = append(target.Packages, scratchTarget.Packages...)
	stats.Components += scratchStats.Components
	stats.Cataloged += scratchStats.Cataloged
	stats.SkippedNoPURL += scratchStats.SkippedNoPURL
	stats.SkippedNoVersion += scratchStats.SkippedNoVersion
	stats.SkippedUnsupportedEcosystem += scratchStats.SkippedUnsupportedEcosystem
}

// indexOfPackage is the position in pkgs of the package p is a second
// listing of, or -1. The identity is the one the matcher judges: type, name,
// version and ecosystem key. It is deliberately NOT the purl string: a
// package's type, name and ecosystem are functions of its purl, but its
// version is not -- a purl with no @version takes component.version
// (catalogOne, pkgmeta.ResolveDistroPURL) -- so an equal purl can name two
// versions, and deduping on it dropped a vulnerable subject because
// bom.components carried the same bare purl at the fixed version. A
// qualifier-only difference (syft's per-document package-id, two install
// paths) is the same package, which the field comparison says and a
// verbatim purl comparison would not.
func indexOfPackage(pkgs []pkgmeta.Package, p pkgmeta.Package) int {
	for i, q := range pkgs {
		if q.Type == p.Type && q.Name == p.Name && q.Version == p.Version && q.Ecosystem == p.Ecosystem {
			return i
		}
	}
	// D166: an OS nested under the subject keys the subject's listing of a
	// package, while its top-level twin, with no OS beside it, stays
	// unkeyed. They are still one package listed twice -- and the keyed one
	// is the one that can be judged (PR #270 review: two packages, one of
	// them a spurious not-evaluated, exit 2 under the strict gate). Only a
	// unique twin is that package: an unkeyed listing beside busybox keyed
	// to Alpine 3.19 AND busybox keyed to 3.20 belongs to neither provably,
	// and merging it into the first one attached its install path to that
	// release's findings -- the other release's when the document listed
	// them the other way round (PR #270 review). It stays its own package,
	// unkeyed and reported not evaluated.
	match := -1
	for i, q := range pkgs {
		if q.Type == p.Type && q.Name == p.Name && q.Version == p.Version && (q.Ecosystem == "" || p.Ecosystem == "") {
			if match >= 0 {
				return -1
			}
			match = i
		}
	}
	return match
}

// keepEvidence folds a dropped second listing onto the kept package: every
// location the document gave the package is evidence (D10), and a source
// identity (D8), SRPM name or module stream the kept listing lacks is taken
// from the dropped one -- a deb purl with ?upstream= on one listing and not
// the other must still be judged on its source. What the kept listing
// already states is never overwritten.
func keepEvidence(kept *pkgmeta.Package, dropped pkgmeta.Package) {
	// The keyed listing's key wins over an unkeyed twin's (indexOfPackage).
	if kept.Ecosystem == "" && dropped.Ecosystem != "" {
		kept.Ecosystem = dropped.Ecosystem
	}
	for _, loc := range dropped.Locations {
		if !hasLocation(kept.Locations, loc) {
			kept.Locations = append(kept.Locations, loc)
		}
	}
	if kept.Source == nil {
		kept.Source = dropped.Source
	}
	if kept.Upstream == "" {
		kept.Upstream = dropped.Upstream
	}
	if kept.ModuleStream == "" {
		kept.ModuleStream = dropped.ModuleStream
	}
}

func hasLocation(locs []pkgmeta.Location, loc pkgmeta.Location) bool {
	for _, l := range locs {
		if l == loc {
			return true
		}
	}
	return false
}

// pseudoSubjectShape mirrors spdx.pseudoPackageShape for a subject that
// yielded no package: no purl at all (syft's container, every image SBOM
// syft writes), a pkg:oci purl (Red Hat's container), or a parsed purl
// without a version (a product named without a build -- catalogOne counts
// that under SkippedNoVersion, and only that). A malformed purl is none of
// these and stays a counted SkippedNoPURL, as a top-level twin's would be.
func pseudoSubjectShape(subject component, scratch Stats) bool {
	if subject.PURL == "" {
		return true
	}
	if parsed, err := pkgmeta.ParsePURL(subject.PURL); err == nil && parsed.Type == "oci" {
		return true
	}
	return scratch.SkippedNoVersion == 1
}

// catalog walks components depth-first so nested ones are seen. Every path out
// of catalogOne increments exactly one counter, which is what lets the report's
// summary account for every component the document contained.
func catalog(components []component, ctx osContext, target *pkgmeta.Target, stats *Stats) {
	for _, c := range components {
		catalogOne(c, ctx, target, stats)
		catalog(c.Components, childContext(c, ctx), target, stats)
	}
}

func catalogOne(c component, ctx osContext, target *pkgmeta.Target, stats *Stats) {
	if c.Type == "operating-system" {
		// Described the target in the first pass (D7); it is not a package to
		// scan, and counting it here would inflate the component total.
		return
	}
	if c.Type == "file" {
		// Modern syft emits thousands of purl-less "file" components per
		// image — content-scanned files, not packages (6,161 of 6,306
		// top-level components measured on a real rockylinux:9 syft 1.51.0
		// SBOM). Counting them as SkippedNoPURL used to inflate Components
		// enough on its own to trip --fail-on-incomplete=target on a scan
		// that was otherwise complete. Excluded here the same way the
		// operating-system component is above: not counted anywhere, rather
		// than adding a Stats field for a bucket nothing needs to gate on —
		// the least new machinery, and consistent with the one exclusion
		// this file already had.
		return
	}
	stats.Components++
	if c.PURL == "" {
		stats.SkippedNoPURL++
		return
	}
	p, err := pkgmeta.ParsePURL(c.PURL)
	if err != nil {
		stats.SkippedNoPURL++
		return
	}

	var (
		eco          string
		version      string
		source       *pkgmeta.SourcePackage
		upstream     string
		moduleStream string
	)
	switch p.Type {
	case "apk", "rpm", "deb", "alpm":
		// D83/D84/D97. The shared core (internal/pkgmeta/distropurl.go): ecosystem
		// resolution from the target's distro with a per-purl "distro"
		// qualifier fallback (and, for rpm, a further repository_id
		// fallback), epoch prefixing, upstream->Source, the gpg-pubkey
		// filter, and rpmmod->ModuleStream. SPDX calls the identical
		// function, which is the point: CycloneDX and SPDX cannot judge one
		// installed package two different ways.
		res := pkgmeta.ResolveDistroPURL(p, c.Version, ctx.ecosystem, ctx.distro != nil)
		if res.Skip {
			// gpg-pubkey (a keyring entry, not an installed package) or an
			// arch=src SRPM (D84). Routed into the existing "unsupported
			// ecosystem" bucket rather than a new Stats field — the least new
			// machinery, and it is, like an unsupported purl type, a
			// component this cataloger deliberately never turns into a
			// package.
			stats.SkippedUnsupportedEcosystem++
			return
		}
		eco = res.Ecosystem
		version = res.Version
		source = res.Source
		upstream = res.Upstream
		moduleStream = res.ModuleStream
	default:
		var ok bool
		eco, ok = pkgmeta.EcosystemForPURLType(p.Type)
		if !ok {
			stats.SkippedUnsupportedEcosystem++
			return
		}
		version = p.Version
		if version == "" {
			version = c.Version
		}
		if p.Type == "gem" {
			version = pkgmeta.InstalledGemVersion(version, p.Qualifiers["platform"])
		}
	}
	if version == "" {
		// Nothing for a comparer to place inside a range. Counting it as
		// cataloged would claim the package was evaluated when it was not.
		stats.SkippedNoVersion++
		return
	}

	// apk, rpm, deb and alpm purls carry the distro name as their namespace
	// (pkg:apk/alpine/..., pkg:rpm/rhel/..., pkg:alpm/arch/...), which is not
	// part of the package identity: OSV's/Arch's own advisories name the
	// bare package ("openssl", not "alpine/openssl"; "libelf", not
	// "arch/libelf"), and the rpm namespace itself is not even stable —
	// syft 0.84.1 writes "rhel", syft 1.51.0 writes "redhat", for the same
	// distro. Prefixing either into the name here would make every distro
	// lookup miss its advisory, or miss it only on some SBOMs.
	name := p.Name
	if p.Namespace != "" && p.Type != "apk" && p.Type != "rpm" && p.Type != "deb" && p.Type != "alpm" {
		// The purl spec always separates namespace and name with "/"
		// (pkg:maven/group/artifact), but OSV's Maven advisories name the
		// package "group:artifact" — measured 12,457/12,457 live records.
		// Joining with "/" here would build a name OSV never publishes and
		// every Maven package would silently miss its advisory.
		sep := "/"
		if p.Type == "maven" {
			sep = ":"
		}
		name = p.Namespace + sep + p.Name
	}

	loc := pkgmeta.Location{Path: "sbom"}
	if path := propValue(c, "syft:location:0:path"); path != "" {
		loc.Path = path
	}
	if layer := propValue(c, "syft:location:0:layerID"); layer != "" {
		loc.LayerDigest = layer
	}

	pkg := pkgmeta.Package{
		Name:         name,
		Version:      version,
		Type:         p.Type,
		Ecosystem:    eco,
		PURL:         c.PURL,
		Locations:    []pkgmeta.Location{loc},
		Source:       source,
		Upstream:     upstream,
		ModuleStream: moduleStream,
	}
	switch p.Type {
	case "deb":
		// syft writes dpkg's source version twice: in the purl's upstream
		// qualifier ("name@version") and as the syft:metadata:sourceVersion
		// property. The purl is read first (the shared core), and the
		// property fills the version only when the purl named the source
		// without one -- a producer that writes the bare name in the purl
		// but still carries syft's property. The purl's own version is
		// never overwritten: the two agree when both exist, and the purl is
		// the statement SPDX readers see too.
		if pkg.Source != nil && pkg.Source.Version == "" {
			if v := propValue(c, "syft:metadata:sourceVersion"); v != "" {
				pkg.Source.Version = v
			}
		}
	case "apk":
		// syft reports the origin package name only via a CycloneDX property
		// (D8) — the shared core has no purl-qualifier equivalent to read
		// this from, so it is layered on here rather than in
		// pkgmeta.ResolveDistroPURL. Alpine binary packages carry their
		// source package's version, so leaving Version empty here is correct
		// rather than a gap: the binary's own version is the one the
		// comparer uses.
		if origin := propValue(c, "syft:metadata:originPackage"); origin != "" {
			pkg.Source = &pkgmeta.SourcePackage{Name: origin}
		}
	case "rpm":
		// D80. syft writes the module label as a CycloneDX property rather
		// than a purl qualifier (Red Hat's own SPDX documents do the
		// opposite — the shared core's "rpmmod" qualifier reading above), so
		// this is layered on the same way apk's origin property is: the
		// string-splitting itself is the moved, shared helper
		// (pkgmeta.ModuleStreamFromLabel), only the property read stays
		// here.
		if label := propValue(c, "syft:metadata:modularityLabel"); label != "" {
			if ms := pkgmeta.ModuleStreamFromLabel(label); ms != "" {
				pkg.ModuleStream = ms
			}
		}
	}
	target.Packages = append(target.Packages, pkg)
	stats.Cataloged++
}

// propValue returns the value of the first property named name, or "" if the
// component does not carry it. Every syft extension property read by this
// package goes through here so a missing one degrades to empty rather than a
// panic.
func propValue(c component, name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

// osContext is the operating system a distro package is keyed by: the one
// its branch of the document declares (contextFor). distro nil means none
// applies -- none declared on the way down, or two different ones side by
// side at some level above it, which leaves every package beneath that level
// without one (the branch declares two; inheriting from further up would
// key it to an OS the branch itself contradicts) -- and the package falls
// back to its purl's distro qualifier, or an rpm's repository_id (D83);
// with no qualifier either it is cataloged unkeyed and the matcher reports
// it not evaluated, with the reason, rather than keyed to a guess.
// ecosystem is distro's key, "" when its release does not resolve (the same
// fall-back: unkeyed, reported, never guessed).
type osContext struct {
	distro    *pkgmeta.Distro
	ecosystem string
}

// contextFor is the context of a list of sibling components: the one
// operating system declared among them, if they declare exactly one; the
// inherited context when they declare none; and no context when they
// declare two different ones, because a package beside both cannot be told
// which it belongs to. Two OS components that describe the same distro and
// release are one declaration.
func contextFor(siblings []component, inherited osContext) osContext {
	var found *pkgmeta.Distro
	for _, c := range siblings {
		d := distroOf(c)
		if d == nil {
			continue
		}
		if found == nil {
			found = d
			continue
		}
		if !sameDistro(found, d) {
			return osContext{}
		}
	}
	if found == nil {
		return inherited
	}
	ctx := osContext{distro: found}
	if eco, err := found.Ecosystem(); err == nil {
		ctx.ecosystem = eco
	}
	return ctx
}

// childContext is the context parent's own components are keyed in. An
// operating-system component with children declares the OS they belong to,
// as an OS among them would (PR #270 review: metadata.component as Alpine
// with busybox directly under it left busybox unkeyed, and keyed it to a
// Debian declared at the top when there was one -- 51 false findings); an
// OS declared among the children is nearer still and comes first
// (contextFor).
func childContext(parent component, inherited osContext) osContext {
	if d := distroOf(parent); d != nil {
		inherited = osContext{distro: d}
		if eco, err := d.Ecosystem(); err == nil {
			inherited.ecosystem = eco
		}
	}
	return contextFor(parent.Components, inherited)
}

// documentDistro is the Target's distro, the one the scan reports and its
// end-of-life and coverage lines read: the top-level context's when the
// document declares one there, else the one the subject itself declares --
// metadata.component as an operating system, or one OS among its own
// children, the shape a container SBOM nests its OS in. An OS declared only
// in some other branch keys that branch's packages and does not name the
// whole target (PR #270 review: the report must not name a distro its
// top-level packages were not judged against).
func documentDistro(doc bom, top osContext) *pkgmeta.Distro {
	if top.distro != nil {
		return top.distro
	}
	s := doc.Metadata.Component
	if s == nil {
		return nil
	}
	if d := distroOf(*s); d != nil {
		return d
	}
	return contextFor(s.Components, osContext{}).distro
}

// sameDistro reports whether two OS components declare one distro release:
// the same ecosystem key when both resolve to one (alpine 3.19.9 and 3.19.1
// are both Alpine:v3.19), else the same ID and VERSION_ID.
func sameDistro(a, b *pkgmeta.Distro) bool {
	ea, errA := a.Ecosystem()
	eb, errB := b.Ecosystem()
	if errA == nil && errB == nil {
		return ea == eb
	}
	return strings.EqualFold(a.ID, b.ID) && a.VersionID == b.VersionID
}

// distroOf reads one operating-system component, or nil for any other
// component or one that names no distro.
func distroOf(c component) *pkgmeta.Distro {
	if c.Type != "operating-system" {
		return nil
	}
	var d pkgmeta.Distro
	for _, p := range c.Properties {
		switch p.Name {
		case "syft:distro:id":
			d.ID = p.Value
		case "syft:distro:versionID":
			d.VersionID = p.Value
		case "syft:distro:prettyName":
			d.PrettyName = p.Value
		}
	}
	// Fall back to the component's own fields: the properties are a syft
	// extension, but name/version are spec and carry the same thing.
	if d.ID == "" {
		d.ID = c.Name
	}
	if d.VersionID == "" {
		d.VersionID = c.Version
	}
	if d.ID == "" {
		return nil
	}
	return &d
}
