package pkgmeta

import (
	"net/url"
	"sort"
	"strings"
)

// osPURLNamespace is the purl namespace syft writes for an image's OS
// packages, keyed by os-release ID (D121). Every row was measured against a
// syft v1.50.0 run on a real image of that distro (2026-10-13, the 25
// differential targets plus six more); a distro with no measured row gets no
// purl at all rather than a guessed or aliased one, because a purl in the
// wrong namespace would either match nothing (a silent gap a reader cannot
// see) or match a different vendor's statement (a false suppression).
//
// Rows not here, and why:
//   - chainguard, echo, bellsoft-hardened-containers: no image measured.
//     Every image under cgr.dev/chainguard reports ID=wolfi, so it is the
//     wolfi row that covers them.
//   - cleanstart: assay names it from an apk marker package because the
//     image ships no os-release (D101); syft, finding none, names the OS
//     "busybox" with the busybox version (pkg:apk/busybox/…?distro=
//     busybox-1.38.0). A cleanstart row would not be syft's spelling, and
//     copying syft's would describe the image as an OS it is not.
//
// Two rows are not the ID: Red Hat's Hummingbird is namespaced "redhat"
// like RHEL, and both openSUSE flavours "opensuse". The distro qualifier
// still carries the os-release ID in every case.
var osPURLNamespace = map[string]string{
	"alpine":              "alpine",
	"wolfi":               "wolfi",
	"minimos":             "minimos",
	"alpaquita":           "alpaquita",
	"debian":              "debian",
	"ubuntu":              "ubuntu",
	"rhel":                "redhat",
	"hummingbird":         "redhat",
	"rocky":               "rocky",
	"almalinux":           "almalinux",
	"ol":                  "ol",
	"amzn":                "amzn",
	"fedora":              "fedora",
	"sles":                "sles",
	"opensuse-leap":       "opensuse",
	"opensuse-tumbleweed": "opensuse",
	"mariner":             "mariner",
	"azurelinux":          "azurelinux",
	"photon":              "photon",
	"arch":                "arch",
}

// OSPackagePURL spells an image OS package's purl the way syft does (D121),
// so a VEX statement written against a syft SBOM of the same image names
// this package byte for byte:
//
//	pkg:<type>/<namespace>/<name>@<version>?arch=…&distro=<ID>-<VERSION_ID>[&epoch=…][&upstream=…]
//
// Qualifiers are in key order, as syft writes them. Per type:
//   - apk: upstream=<origin> only when the origin differs from the name.
//   - deb: the epoch stays inside the version ("1:1.2.13.dfsg-1", escaped
//     %3A). upstream=<source>@<source version> when the source version
//     differs from the binary's (a binNMU "+bN", or an epoch only the binary
//     carries), else upstream=<source> when only the name differs, else none.
//   - rpm: the epoch moves out of the version into epoch=, written only when
//     non-zero; upstream= is the SOURCERPM file name verbatim. syft also
//     writes epoch=0 when the rpmdb holds an explicit zero — the rpmdb
//     cataloger folds that to no epoch at all, so that one shape differs.
//   - alpm: upstream=%BASE%, always, even when it equals the name.
//
// Returns "" — no purl — for a package type outside those four, for a
// distro with no measured namespace row, and for a distro with no
// VERSION_ID, whose distro qualifier syft's spelling has no measured form
// for. A package that already has a purl is the caller's to leave alone:
// this function does not look at p.PURL.
func OSPackagePURL(d *Distro, p Package) string {
	if d == nil || d.VersionID == "" || p.Name == "" || p.Version == "" {
		return ""
	}
	ns, ok := osPURLNamespace[d.ID]
	if !ok {
		return ""
	}
	version := p.Version
	q := map[string]string{"distro": d.ID + "-" + d.VersionID}
	if p.Arch != "" {
		q["arch"] = p.Arch
	}
	switch p.Type {
	case "apk":
		if p.Source != nil && p.Source.Name != "" && p.Source.Name != p.Name {
			q["upstream"] = p.Source.Name
		}
	case "deb":
		if p.Source != nil && p.Source.Name != "" {
			switch {
			case p.Source.Version != "" && p.Source.Version != p.Version:
				q["upstream"] = p.Source.Name + "@" + p.Source.Version
			case p.Source.Name != p.Name:
				q["upstream"] = p.Source.Name
			}
		}
	case "rpm":
		if epoch, rest, ok := strings.Cut(version, ":"); ok {
			version = rest
			if epoch != "0" {
				q["epoch"] = epoch
			}
		}
		if p.Upstream != "" {
			q["upstream"] = p.Upstream
		}
	case "alpm":
		if p.Upstream != "" {
			q["upstream"] = p.Upstream
		}
	default:
		return ""
	}

	var b strings.Builder
	b.WriteString("pkg:" + p.Type + "/" + purlEscape(ns) + "/" + purlEscape(p.Name) + "@" + purlEscape(version))
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(k + "=" + purlEscape(q[k]))
	}
	return b.String()
}

// purlEscape percent-encodes the way syft's purl library does: everything
// but ASCII letters, digits and "-_.~" — so "+" is %2B, ":" %3A and "@" %40,
// each of which a real Debian or RPM version carries. url.QueryEscape is that
// set except that it writes a space as "+"; no package field holds a space,
// but it is mapped to %20 anyway so a "+" in the output always means one.
func purlEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
