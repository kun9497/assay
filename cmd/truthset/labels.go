package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

// labelsSchemaVersion is the committed labels file's own contract version.
const labelsSchemaVersion = 1

// Label is one expected verdict: this package at this version, keyed the way
// its purl keys it, is -- or is not -- affected by this CVE, on the distro's
// own word.
type Label struct {
	// ID is unique across the file, "<case>/<CVE>" by convention; it is the
	// name every table and report row carries.
	ID string `json:"id"`
	// Case groups the labels that share one package and version: one SBOM
	// is written and one scan run per case.
	Case string `json:"case"`
	// Family is the metrics bucket -- a distro family (alpine, debian, leap)
	// -- so a figure is given per family a customer actually scans rather
	// than one blended number.
	Family string `json:"family"`
	// PURL is the package exactly as the image path would spell it (D121),
	// distro qualifier included: it is what keys the scan.
	PURL    string `json:"purl"`
	Name    string `json:"name"`
	Version string `json:"version"`
	CVE     string `json:"cve"`
	Expect  Expect `json:"expect"`
	// Class is "matcher" (feeds precision/recall) or "data" (a known data
	// gap: judged and printed, excluded from the metrics; Note says why).
	Class  string `json:"class"`
	Note   string `json:"note,omitempty"`
	Source Source `json:"source"`
	// ValidFrom is the earliest provider dataAsOf (full-date) the
	// expectation is known to hold at; a database older than it is not
	// evidence either way. Recorded, not yet enforced.
	ValidFrom string `json:"validFrom,omitempty"`
}

// Expect is the labelled verdict. State is "affected" or "clean"; Fixed is
// the fixed version an affected finding must carry. An affected label with
// Fixed "" holds the finding to its presence alone -- the label says the
// build is affected and takes no position on the fix named, which is the
// honest shape for a build SUSE lists as released and still affected
// (leap-libopenssl3-at-released-build: the fix is "In progress" beside the
// released build, so no version is right to demand).
type Expect struct {
	State string `json:"state"`
	Fixed string `json:"fixed,omitempty"`
}

// Source is where the label's truth was read: the upstream's own statement,
// its URL, and when it was fetched -- so a label can be re-checked against
// the upstream of its day, not today's.
type Source struct {
	Statement string `json:"statement"`
	URL       string `json:"url"`
	FetchedAt string `json:"fetchedAt"`
}

type labelsFile struct {
	SchemaVersion int     `json:"schemaVersion"`
	Description   string  `json:"description,omitempty"`
	Labels        []Label `json:"labels"`
}

var cveShape = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// purlNameVersion reads the name and version of a pkg: purl, percent-decoded
// (the purl spec encodes `:`, `+` and `@` inside a version). The name is the
// last path segment before `@`; qualifiers and subpath are dropped.
func purlNameVersion(purl string) (name, version string, err error) {
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	at := strings.LastIndex(rest, "@")
	if at < 0 {
		return "", "", fmt.Errorf("no @version")
	}
	version, err = url.PathUnescape(rest[at+1:])
	if err != nil {
		return "", "", err
	}
	name, err = url.PathUnescape(rest[strings.LastIndex(rest[:at], "/")+1 : at])
	if err != nil {
		return "", "", err
	}
	if name == "" || version == "" {
		return "", "", fmt.Errorf("empty name or version")
	}
	return name, version, nil
}

// loadLabels reads and validates the labels file. Every refusal names the
// label, because a labels file is edited by hand and a wrong row that loaded
// would be judged as if it were a truth.
func loadLabels(path string) ([]Label, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f labelsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("labels file %s: %w", path, err)
	}
	if f.SchemaVersion != labelsSchemaVersion {
		return nil, fmt.Errorf("labels file %s: schemaVersion %d, this tool reads %d", path, f.SchemaVersion, labelsSchemaVersion)
	}
	if len(f.Labels) == 0 {
		return nil, fmt.Errorf("labels file %s: no labels", path)
	}
	seen := map[string]bool{}
	casePURL := map[string]string{}
	for i, l := range f.Labels {
		where := fmt.Sprintf("labels file %s: label %d (%q)", path, i, l.ID)
		switch {
		case l.ID == "":
			return nil, fmt.Errorf("labels file %s: label %d has no id", path, i)
		case seen[l.ID]:
			return nil, fmt.Errorf("%s: duplicate id", where)
		case l.Case == "" || l.Family == "" || l.Name == "" || l.Version == "":
			return nil, fmt.Errorf("%s: case, family, name and version are all required", where)
		case !strings.HasPrefix(l.PURL, "pkg:"):
			return nil, fmt.Errorf("%s: purl %q must be a pkg: purl carrying the label's version", where, l.PURL)
		}
		// The purl is what keys the scan and the name/version are what the
		// SBOM component carries beside it; they must be one package, read
		// exactly (a deb epoch is `%3A`, `+dfsg` is `%2B`, and `@1.2` is not
		// `@1.20`), or the scan would judge a package the label did not name.
		pn, pv, perr := purlNameVersion(l.PURL)
		switch {
		case perr != nil:
			return nil, fmt.Errorf("%s: purl %q must be a pkg: purl carrying the label's version: %v", where, l.PURL, perr)
		case pv != l.Version:
			return nil, fmt.Errorf("%s: purl %q must be a pkg: purl carrying the label's version %q (it carries %q)", where, l.PURL, l.Version, pv)
		case pn != l.Name:
			return nil, fmt.Errorf("%s: purl names %q, label names %q", where, pn, l.Name)
		case !cveShape.MatchString(l.CVE):
			return nil, fmt.Errorf("%s: cve %q is not CVE-YYYY-NNNN", where, l.CVE)
		case l.Expect.State != "affected" && l.Expect.State != "clean":
			return nil, fmt.Errorf("%s: expect.state %q, want affected or clean", where, l.Expect.State)
		case l.Expect.State == "clean" && l.Expect.Fixed != "":
			return nil, fmt.Errorf("%s: a clean label names a fixed version %q", where, l.Expect.Fixed)
		case l.Class != "matcher" && l.Class != "data":
			return nil, fmt.Errorf("%s: class %q, want matcher or data", where, l.Class)
		case l.Class == "data" && l.Note == "":
			return nil, fmt.Errorf("%s: a data-class label needs a note saying which data gap it records", where)
		case l.Source.Statement == "" || l.Source.URL == "" || l.Source.FetchedAt == "":
			return nil, fmt.Errorf("%s: source.statement, source.url and source.fetchedAt are all required", where)
		}
		if p, ok := casePURL[l.Case]; ok && p != l.PURL {
			return nil, fmt.Errorf("%s: case %q names two purls (%s, %s); one case is one package at one version", where, l.Case, p, l.PURL)
		}
		casePURL[l.Case] = l.PURL
		seen[l.ID] = true
	}
	out := append([]Label(nil), f.Labels...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Case != out[j].Case {
			return out[i].Case < out[j].Case
		}
		return out[i].CVE < out[j].CVE
	})
	return out, nil
}
