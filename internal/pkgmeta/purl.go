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
		q, err := url.ParseQuery(rest[i+1:])
		if err != nil {
			return PURL{}, fmt.Errorf("parse purl %q qualifiers: %w", s, err)
		}
		p.Qualifiers = make(map[string]string, len(q))
		for k, v := range q {
			if len(v) > 0 {
				p.Qualifiers[strings.ToLower(k)] = v[0]
			}
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
// PyPI is the case that matters. PEP 503 lowercases and folds runs of "-", "_"
// and "." into a single "-", and OSV publishes only normalized names: all 1,586
// distinct PyPI names in the live dump are already in that form. syft is not —
// it emits pkg:pypi/Jinja2 and pkg:pypi/PyYAML verbatim from the installed
// metadata, so without this every mixed-case PyPI package missed every advisory
// it had.
//
// Go and npm names are case-sensitive in their own registries and OSV preserves
// them, so they are returned unchanged.
func NormalizeName(ecosystem, name string) string {
	if ecosystem != "PyPI" {
		return name
	}
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
}
