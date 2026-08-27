package pkgmeta

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type PURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers map[string]string
}

var errNotPURL = errors.New("not a package URL")

// ParsePURL handles the subset of the purl spec that appears in SBOMs:
// pkg:type/namespace/name@version?qualifiers. Subpath (#…) is discarded.
func ParsePURL(s string) (PURL, error) {
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return PURL{}, fmt.Errorf("parse purl %q: %w", s, errNotPURL)
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}

	var p PURL
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		// Parsed by hand rather than url.ParseQuery: that function decodes '+'
		// as a space (the application/x-www-form-urlencoded convention), and
		// old-syft purls carry a raw, unencoded '+' in qualifier values — RPM
		// module EVRs ("module+el8.10.0+23091+...") and SLES upstream
		// filenames ("aaa_base-84.87+git20180409...") both do, measured
		// against real syft 0.84.1 output. url.PathUnescape leaves '+' alone,
		// which is what a purl qualifier needs.
		p.Qualifiers = make(map[string]string)
		for _, pair := range strings.Split(rest[i+1:], "&") {
			if pair == "" {
				continue
			}
			rawKey, rawVal, _ := strings.Cut(pair, "=")
			key, err := url.PathUnescape(rawKey)
			if err != nil {
				return PURL{}, fmt.Errorf("parse purl %q qualifier key: %w", s, err)
			}
			key = strings.ToLower(key)
			if _, dup := p.Qualifiers[key]; dup {
				// First value wins, matching url.Values' v[0] semantics — the
				// behavior this replaces.
				continue
			}
			val, err := url.PathUnescape(rawVal)
			if err != nil {
				return PURL{}, fmt.Errorf("parse purl %q qualifier %q: %w", s, key, err)
			}
			p.Qualifiers[key] = val
		}
		rest = rest[:i]
	}

	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return PURL{}, fmt.Errorf("parse purl %q: %w", s, errNotPURL)
	}
	// Only the type is case-insensitive. Lowercasing a name would silently
	// fail to match OSV, which is case-sensitive per ecosystem.
	p.Type = strings.ToLower(typ)

	if i := strings.LastIndexByte(path, '@'); i >= 0 {
		v, err := url.PathUnescape(path[i+1:])
		if err != nil {
			return PURL{}, fmt.Errorf("parse purl %q version: %w", s, err)
		}
		p.Version = v
		path = path[:i]
	}

	segs := strings.Split(path, "/")
	for i, seg := range segs {
		d, err := url.PathUnescape(seg)
		if err != nil {
			return PURL{}, fmt.Errorf("parse purl %q segment %d: %w", s, i, err)
		}
		segs[i] = d
	}
	if segs[len(segs)-1] == "" {
		return PURL{}, fmt.Errorf("parse purl %q: empty name", s)
	}
	p.Name = segs[len(segs)-1]
	p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	return p, nil
}

// purlTypeToEcosystem maps purl types to OSV ecosystem keys. Distro types (apk,
// deb, rpm) are absent on purpose: their ecosystem key includes the release
// (D6), which a purl does not carry, so they cannot be resolved here.
var purlTypeToEcosystem = map[string]string{
	"golang": "Go",
	"npm":    "npm",
	"pypi":   "PyPI",
	// OSV writes pkg:cargo/<crate> and keys the ecosystem "crates.io"; the
	// purl type and the ecosystem name differ, which is why this map exists.
	"cargo": "crates.io",
	// gem, nuget and composer also differ from their OSV ecosystem key;
	// maven happens to share its spelling, but is listed all the same so the
	// map stays the single place every purl type is resolved.
	"gem":      "RubyGems",
	"nuget":    "NuGet",
	"composer": "Packagist",
	"maven":    "Maven",
	// D99: Bitnami is a purl-type-keyed ecosystem, not a distro, even though
	// it names applications rather than a language package manager — it has
	// no os-release of its own (current images are Photon-based, frozen
	// legacy images Debian-based, D96/D7), so a Bitnami app package keys the
	// same way a Go or npm one does: by its purl type alone, with no release
	// axis (D6 does not apply, the same way it does not for Wolfi/Echo).
	// Measured 2026-08-27: OSV's own "Bitnami" ecosystem string is bare on
	// 100% of the 9,059-record archive, and syft's own purl type for these
	// packages is "bitnami" (pkg:bitnami/postgresql@18.6.0-3).
	"bitnami": "Bitnami",
}

func EcosystemForPURLType(typ string) (string, bool) {
	e, ok := purlTypeToEcosystem[strings.ToLower(typ)]
	return e, ok
}

// NormalizeName renders a package name in the form its ecosystem's advisory
// database is keyed on. It is the single definition of that mapping: the store
// applies it when indexing and when looking up, and the matcher applies it when
// filtering affected entries. If any of those three stopped agreeing, the
// mismatch would surface as a lookup that returns nothing — no error, no skip,
// just a package silently reported as clean.
//
// PyPI is the case that matters most. PEP 503 lowercases and folds runs of
// "-", "_" and "." into a single "-", and OSV publishes only normalized names:
// all 1,586 distinct PyPI names in the live dump are already in that form.
// syft is not — it emits pkg:pypi/Jinja2 and pkg:pypi/PyYAML verbatim from the
// installed metadata, so without this every mixed-case PyPI package missed
// every advisory it had.
//
// NuGet package IDs are case-insensitive — the NuGet client and gallery both
// treat "Newtonsoft.Json" and "newtonsoft.json" as one package — and OSV's own
// advisory names are not consistently cased: measured, 98% of advisory names
// in the live NuGet dump are mixed-case. A lowercase fold is enough; NuGet has
// no PEP 503-style separator folding to also apply.
//
// Go and npm names are case-sensitive in their own registries and OSV preserves
// them, so they — and every other ecosystem — are returned unchanged.
func NormalizeName(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		var b strings.Builder
		b.Grow(len(name))
		var lastSep bool
		for _, r := range strings.ToLower(name) {
			if r == '-' || r == '_' || r == '.' {
				if !lastSep {
					b.WriteByte('-')
					lastSep = true
				}
				continue
			}
			lastSep = false
			b.WriteRune(r)
		}
		return b.String()
	case "NuGet":
		return strings.ToLower(name)
	default:
		return name
	}
}
