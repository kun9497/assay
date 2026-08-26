package pkgmeta

import "strings"

// DistroPURLResult is the outcome of mapping an apk, rpm or deb purl onto a
// Package's distro-flavoured fields (D6/D7/D8, extended D83 for rpm/deb and
// D84 for apk and for Red Hat's own vendor qualifiers). It is the shared
// core CycloneDX and SPDX both call — Name, Type and PURL stay each format's
// own job (SPDX has no per-component version fallback or namespace/property
// story the way CycloneDX does), but the ecosystem-key resolution, the
// epoch, the source package and the module stream must never be judged two
// different ways for the same installed package.
type DistroPURLResult struct {
	Ecosystem string
	// Version is p.Version with the epoch prefixed when the purl carries a
	// non-zero "epoch" qualifier (rpm/deb only), falling back to
	// componentVersion when the purl carries no @version at all. Empty means
	// there was nothing to place inside a comparer's range.
	Version      string
	Source       *SourcePackage
	ModuleStream string
	// Skip is true for a purl that must never become a package at all:
	// gpg-pubkey, a keyring entry rather than an installed package (mirrors
	// rpmdb's isPubkey, header.go), or an arch=src SRPM riding alongside its
	// binaries in a Red Hat SBOM (D84) — cataloging either would double
	// count, or compare a source RPM's EVR against advisories written for
	// binary packages.
	Skip bool
}

// ResolveDistroPURL builds a Package's distro-flavoured fields from an apk,
// rpm or deb purl. Callers must only invoke this for those three purl types;
// every other ecosystem resolves through EcosystemForPURLType instead, which
// carries no release and needs none of what this function does.
//
// componentVersion is the caller's own fallback for a purl with no @version
// — CycloneDX's component.Version field. SPDX has no such fallback (D84:
// versionInfo is deliberately never read, because it lies three ways — RH
// container SBOMs omit the release, RH product SBOMs write ""/"UNKNOWN",
// syft includes the epoch the purl omits), so an SPDX caller always passes
// "".
//
// docEcosystem is the document-level distro's already-resolved ecosystem
// key, and hasDocDistro says whether the document carried a distro entity AT
// ALL — a CycloneDX operating-system component. SPDX never has one (D84: the
// format has no such entity), so an SPDX caller always passes hasDocDistro
// false and every package keys via its own purl qualifiers instead.
func ResolveDistroPURL(p PURL, componentVersion, docEcosystem string, hasDocDistro bool) DistroPURLResult {
	var res DistroPURLResult

	switch p.Type {
	case "rpm":
		if isPubkeyPURL(p) {
			res.Skip = true
			return res
		}
		if p.Qualifiers["arch"] == "src" {
			res.Skip = true
			return res
		}
		res.Ecosystem = ecosystemForRPM(p, docEcosystem, hasDocDistro)
		// D8/D83. The "upstream" qualifier is a source-RPM filename
		// ("audit-3.0.7-104.el9.src.rpm"), stripped back to the bare name by
		// the same core rpmdb's own cataloger uses.
		if upstream := p.Qualifiers["upstream"]; upstream != "" {
			if src := SourceRPMName(upstream); src != "" {
				res.Source = &SourcePackage{Name: src}
			}
		}
		// D84. Red Hat's own SPDX SBOMs write the module label directly as a
		// purl qualifier, in the identical colon-separated shape
		// RPMTAG_MODULARITYLABEL carries — CycloneDX instead reads the same
		// shape off a syft property (cyclonedx.go's own modularityLabel
		// handling), so this is a genuine alternate source for the one
		// caller that has it, not a duplicate of that path.
		if label := p.Qualifiers["rpmmod"]; label != "" {
			res.ModuleStream = ModuleStreamFromLabel(label)
		}
	case "deb":
		res.Ecosystem = ecosystemForQualifiedDistro(p, docEcosystem, hasDocDistro)
		// D8/D83. syft's "upstream" qualifier is "name" or "name@version"
		// (percent-encoded '@'); only the name half identifies the source
		// package.
		if upstream := p.Qualifiers["upstream"]; upstream != "" {
			srcName, _, _ := strings.Cut(upstream, "@")
			if srcName != "" {
				res.Source = &SourcePackage{Name: srcName}
			}
		}
	case "apk":
		// D84: apk now gets the same per-purl qualifier fallback rpm and deb
		// already had (D83). Before this, the apk branch keyed ONLY from the
		// document-level distro, so a document with no operating-system
		// component — every SPDX document, and any CycloneDX one from a tool
		// that does not emit syft's extension — left every apk package
		// unkeyed even when the purl itself carried a usable "distro"
		// qualifier.
		res.Ecosystem = ecosystemForQualifiedDistro(p, docEcosystem, hasDocDistro)
		// D8/D84. apk's "upstream" qualifier is the bare origin (source)
		// package name — measured on real syft purls:
		// pkg:apk/alpine/alpine-baselayout-data@...?upstream=alpine-baselayout.
		// Alpine advisories are keyed on SOURCE names (its OSV purls carry
		// ?arch=source), so a document that loses this loses the libssl3 →
		// openssl join: the D8 false negative, silent. CycloneDX callers may
		// overwrite this from syft:metadata:originPackage — the two agree
		// when both exist, and the property also carries a version.
		if upstream := p.Qualifiers["upstream"]; upstream != "" {
			srcName, _, _ := strings.Cut(upstream, "@")
			if srcName != "" {
				res.Source = &SourcePackage{Name: srcName}
			}
		}
	case "alpm":
		// D97. Arch Linux's pacman purl type. Ecosystem resolves the same
		// document-then-qualifier chain apk and deb use — an alpm purl's
		// "distro" qualifier is ALWAYS present when syft emits a purl at all
		// (its own packageURL bails to an empty purl string otherwise, so
		// there is no alpm purl with a document distro but no qualifier one
		// the way an apk purl can occasionally lack it), and it is always
		// "arch-rolling" (Distro.Ecosystem's "arch" case ignores VersionID
		// entirely, so distroFromQualifier's split VersionID half is never
		// even read).
		res.Ecosystem = ecosystemForQualifiedDistro(p, docEcosystem, hasDocDistro)
		// D8/D97. syft's alpm purl carries an "upstream" qualifier for
		// EVERY package, not only split ones (arch_package.go's own
		// packageURL sets it whenever BasePackage != "", and BASE is
		// present on every real record, even non-split ones where it
		// simply repeats NAME — measured against a real image, D97). Set
		// ONLY when it differs from the bare name, unlike apk's and deb's
		// unconditional read above: storing a self-referential Source
		// would make --explain's D8 wording ("matched via source package")
		// print for a package whose "source" is itself, the same
		// reasoning pacmandb.ParseDesc's own doc comment gives for the
		// image-scan path.
		if upstream := p.Qualifiers["upstream"]; upstream != "" && upstream != p.Name {
			res.Source = &SourcePackage{Name: upstream}
		}
	}

	version := p.Version
	if version == "" {
		version = componentVersion
	} else if p.Type == "rpm" || p.Type == "deb" {
		// The purl's own @version is version-release WITHOUT the epoch —
		// evr()'s shape (rpmdb/header.go) omits it the same way when zero —
		// and Qualifiers["epoch"] carries it separately, written only when
		// present and non-zero. Prepending it here, in that same condition,
		// is what makes the two sides comparable.
		if epoch, ok := p.Qualifiers["epoch"]; ok && epoch != "" && epoch != "0" {
			version = epoch + ":" + version
		}
	}
	res.Version = version
	return res
}

// isPubkeyPURL mirrors rpmdb's isPubkey (header.go): a gpg-pubkey row is a
// keyring entry, not an installed package, and the "arch" qualifier is what
// tells it apart from a hypothetical real package of that name — a real one
// always carries an architecture, syft's own gpg-pubkey purls never do.
func isPubkeyPURL(p PURL) bool {
	if p.Name != "gpg-pubkey" {
		return false
	}
	_, hasArch := p.Qualifiers["arch"]
	return !hasArch
}

// ecosystemForQualifiedDistro resolves the ecosystem key for an apk or deb
// purl: the document-level distro wins whenever the document carried one AT
// ALL — even one whose own Ecosystem() resolution failed, so one document
// cannot disagree with itself — falling back to the purl's own "distro"
// qualifier only when there was no document-level distro to consult. rpm
// layers a further, Red Hat-specific fallback on top (see ecosystemForRPM).
func ecosystemForQualifiedDistro(p PURL, docEcosystem string, hasDocDistro bool) string {
	if hasDocDistro {
		return docEcosystem
	}
	d, ok := distroFromQualifier(p.Qualifiers["distro"])
	if !ok {
		return ""
	}
	eco, err := d.Ecosystem()
	if err != nil {
		return ""
	}
	return eco
}

// ecosystemForRPM resolves an rpm purl's ecosystem key: the same
// document-distro-then-"distro"-qualifier chain every distro type gets, and
// then — only when neither of those produced a key — Red Hat's own
// repository_id qualifier (D84). Red Hat's SPDX SBOMs carry no "distro"
// qualifier at all, only repository_id, so this is the sole way those
// documents' rpm packages ever key.
//
// The repository_id fallback is tried only when the document carried no
// distro entity: the same "a document must not disagree with itself" rule
// ecosystemForQualifiedDistro applies to its own qualifier fallback.
func ecosystemForRPM(p PURL, docEcosystem string, hasDocDistro bool) string {
	if eco := ecosystemForQualifiedDistro(p, docEcosystem, hasDocDistro); eco != "" {
		return eco
	}
	if hasDocDistro {
		return ""
	}
	major, ok := rhelMajorFromRepositoryID(p.Qualifiers["repository_id"])
	if !ok {
		return ""
	}
	eco, err := Distro{ID: "rhel", VersionID: major}.Ecosystem()
	if err != nil {
		return ""
	}
	return eco
}

// rhelMajorFromRepositoryID reports the RHEL major version encoded in a
// repository_id purl qualifier value shaped "rhel-<major>-..." — Red Hat's
// own naming for its RPM repositories ("rhel-9-for-x86_64-baseos-rpms",
// "rhel-8-for-x86_64-appstream-source-rpms"). Only that exact shape is
// recognized (D84); a repository_id from a different vendor (or CentOS
// Stream, or one missing the "-<major>-" entirely) reports !ok rather than
// guessing — the same discipline distroFromQualifier already applies to the
// "distro" qualifier.
func rhelMajorFromRepositoryID(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, "rhel-")
	if !ok {
		return "", false
	}
	major, _, ok := strings.Cut(rest, "-")
	if !ok || major == "" || !allDigits(major) {
		return "", false
	}
	return major, true
}

// distroFromQualifier builds a Distro from a purl's "distro" qualifier. syft
// writes it "id-versionID" — "rhel-9.8", "amzn-2023", and "opensuse-leap-15.6"
// where the id itself is hyphenated — so it is split on the LAST hyphen
// rather than the first: everything before is the id, everything after is
// the release. A value with no hyphen (or one ending in a hyphen) has no
// release to split off and fails rather than building a Distro with an empty
// half. An empty qualifier (the common case: most purls carry no "distro" at
// all) fails the same way.
func distroFromQualifier(s string) (Distro, bool) {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 || i == len(s)-1 {
		return Distro{}, false
	}
	return Distro{ID: s[:i], VersionID: s[i+1:]}, true
}

// ModuleStreamFromLabel keeps only NAME:STREAM from a colon-separated RPM
// module label (D80) — RPMTAG_MODULARITYLABEL's own shape
// ("name:stream:version:context"), and Red Hat's SPDX "rpmmod" purl
// qualifier writes the identical shape (D84). Fewer than four fields, or an
// empty name or stream, returns "" rather than a guessed stream: the VERSION
// and CONTEXT fields differ between builds of ONE installed stream, so
// keying on them would split a stream into phantom streams (see
// Package.ModuleStream's own doc).
func ModuleStreamFromLabel(label string) string {
	parts := strings.SplitN(label, ":", 4)
	if len(parts) == 4 && parts[0] != "" && parts[1] != "" {
		return parts[0] + ":" + parts[1]
	}
	return ""
}
