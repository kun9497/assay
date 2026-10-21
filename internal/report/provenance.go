package report

import (
	"sort"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/store"
)

// Provenance is what produced a scan's verdict (D120): the tool, the database,
// the target's content identity, every input that can move the exit code, and
// every waiver that was read. It holds only facts that are the same every time
// the same inputs are scanned, so the report that carries it stays
// byte-deterministic; what differs per run — start and finish time, the exit
// code, the error of an exit 2, the hash of the report — lives in the sidecar
// --provenance writes (scancmd's Sidecar), never here.
//
// Nothing here identifies the machine or its user: no absolute path the caller
// did not type, no database path, no hostname, username or working directory,
// no upstream error text and no credential value. Every field below is either
// something the caller typed, a hash, a count, or a name this build defines.
//
// scancmd fills it stage by stage as the scan proceeds, so a run that stops
// early still has the part it reached for the sidecar; the renderers see it
// complete, because rendering is the last stage.
type Provenance struct {
	Tool ToolProvenance `json:"tool"`
	// Database is nil until the database has been opened and its metadata
	// read: a scan refused before that point used no database, and an empty
	// object would claim one.
	Database *DatabaseProvenance `json:"database,omitempty"`
	Target   TargetProvenance    `json:"target"`
	Policy   PolicyProvenance    `json:"policy"`
	Waivers  WaiversProvenance   `json:"waivers"`
}

// ToolProvenance is the build that ran: the ldflags values `assay version`
// prints. A development build carries version "dev", commit "none" and date
// "unknown" — those are the defaults the binary was built with, said as they
// are rather than replaced by something that looks like a release — and Dev
// says so in one field a policy can test.
type ToolProvenance struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	Dev       bool   `json:"dev"`
}

// NewToolProvenance builds the tool record from the three ldflags values.
func NewToolProvenance(version, commit, date string) ToolProvenance {
	return ToolProvenance{
		Name:      "assay",
		Version:   version,
		Commit:    commit,
		BuildDate: date,
		Dev:       version == "" || version == "dev",
	}
}

// DatabaseProvenance is the database the scan read. Artifact is set only when
// `db update` wrote a record of what it pulled into the database's own Meta
// (D127); a database built locally has none, and reports none rather than
// guessing.
type DatabaseProvenance struct {
	Schema   int                 `json:"schema"`
	BuiltAt  string              `json:"builtAt"`
	Artifact *ArtifactProvenance `json:"artifact,omitempty"`
	// Ratings is the data-as-of of every rating source (NVD, EPSS, KEV),
	// sorted by name; present and empty when the database carries none.
	Ratings []SourceAsOf `json:"ratings"`
	// EOL is the end-of-life catalogue's data-as-of, nil when the database
	// carries no catalogue.
	EOL *SourceAsOf `json:"eol,omitempty"`
	// Frozen and Renamed are the keys D110 carried forward and D115 renamed,
	// by name, sorted; present and empty when there are none.
	Frozen  []FrozenKey  `json:"frozen"`
	Renamed []RenamedKey `json:"renamed"`
}

// ArtifactProvenance is the published artifact a database came from. The pull
// time is kept in the artifact record itself and not here: it is a fact about
// the pull, and two scans of one database must not differ by it.
type ArtifactProvenance struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// SourceAsOf is one source's data-as-of. Failed says the source's last run did
// not finish; its error text is never copied (store.Provenance.Error can carry
// internal addresses).
type SourceAsOf struct {
	Source   string `json:"source"`
	DataAsOf string `json:"dataAsOf"`
	Failed   bool   `json:"failed,omitempty"`
}

// FrozenKey is one ecosystem key carried forward since a date (D110).
type FrozenKey struct {
	Key   string `json:"key"`
	Since string `json:"since"`
}

// RenamedKey is one key a provider declared renamed (D115).
type RenamedKey struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// NewDatabaseProvenance builds the database record from the Meta a scan read,
// artifact record included (Meta.Artifact, D127).
func NewDatabaseProvenance(m store.Meta) *DatabaseProvenance {
	d := &DatabaseProvenance{
		Schema:  m.Schema,
		BuiltAt: timestamp(m.BuiltAt),
		Ratings: []SourceAsOf{},
		Frozen:  []FrozenKey{},
		Renamed: []RenamedKey{},
	}
	if art := m.Artifact; art != nil {
		d.Artifact = &ArtifactProvenance{Reference: art.Reference, Digest: art.Digest}
	}
	names := make([]string, 0, len(m.Ratings))
	for n := range m.Ratings {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := m.Ratings[n]
		d.Ratings = append(d.Ratings, SourceAsOf{Source: n, DataAsOf: timestamp(p.DataAsOf), Failed: p.Error != ""})
	}
	if m.EOLProvenance != nil {
		d.EOL = &SourceAsOf{Source: "endoflife.date", DataAsOf: timestamp(m.EOLProvenance.DataAsOf),
			Failed: m.EOLProvenance.Error != ""}
	}
	for _, p := range m.Providers {
		for k, since := range p.Frozen {
			d.Frozen = append(d.Frozen, FrozenKey{Key: k, Since: dateOnly(since)})
		}
		for from, to := range p.Renamed {
			d.Renamed = append(d.Renamed, RenamedKey{From: from, To: to})
		}
	}
	sort.Slice(d.Frozen, func(i, j int) bool { return d.Frozen[i].Key < d.Frozen[j].Key })
	sort.Slice(d.Renamed, func(i, j int) bool { return d.Renamed[i].From < d.Renamed[j].From })
	return d
}

// timestamp renders t as RFC 3339 UTC, or "" for the zero time, which a
// database built before a field existed carries.
func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// TargetProvenance is what was scanned and its content identity. Argument is
// the target exactly as typed — the one path this record may hold, because the
// caller wrote it. Only the identity fields for the target's kind are set.
type TargetProvenance struct {
	Argument string `json:"argument"`
	// Kind is the classification ("image", "sbom", "directory", "go-binary",
	// "jar"); empty when the argument could not be classified at all.
	Kind string `json:"kind,omitempty"`
	// SHA256 is the file target's content hash (SBOM, Go binary, jar).
	SHA256 string `json:"sha256,omitempty"`
	// SerialNumber is a CycloneDX SBOM's own serialNumber, DocumentNamespace
	// an SPDX SBOM's documentNamespace — the document's identity as its
	// producer wrote it, beside the hash of its bytes.
	SerialNumber      string `json:"serialNumber,omitempty"`
	DocumentNamespace string `json:"documentNamespace,omitempty"`
	// Manifests is every manifest a directory scan read, by root-relative
	// path and sha256, in the order the walk found them.
	Manifests []ManifestProvenance `json:"manifests,omitempty"`
	// RegistryCredentials is which of D118's sources answered for a registry
	// pull — its name, never a value — and "none" for an anonymous one. Set
	// only for an image.
	RegistryCredentials string `json:"registryCredentials,omitempty"`
	// Image is D119's record, repeated here so the sidecar carries it too.
	Image *ImageRecord `json:"image,omitempty"`
}

// ManifestProvenance is one manifest a directory scan read.
type ManifestProvenance struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// PolicyProvenance is every input that can move the exit code. A gate that was
// not given is null (or false for a bare switch), so "not given" and "given as
// the loosest value" cannot look alike.
type PolicyProvenance struct {
	FailOn                 *string        `json:"failOn"`
	FailOnUnknown          bool           `json:"failOnUnknown"`
	FailOnIncomplete       bool           `json:"failOnIncomplete"`
	FailOnIncompleteTarget bool           `json:"failOnIncompleteTarget"`
	FailOnUnfixable        bool           `json:"failOnUnfixable"`
	FailOnUnfixableWontFix bool           `json:"failOnUnfixableWontFix"`
	FailOnKEV              bool           `json:"failOnKev"`
	FailOnEPSS             *float64       `json:"failOnEpss"`
	FailOnEOL              bool           `json:"failOnEol"`
	DBMaxAge               *string        `json:"dbMaxAge"`
	DBMaxRatingAge         *string        `json:"dbMaxRatingAge"`
	Timeout                *string        `json:"timeout"`
	Platform               PlatformPolicy `json:"platform"`
}

// PlatformPolicy is --platform's value and whether it was given. Defaulted, an
// image scan reads the host's platform, which is named; any other target has
// no platform, and Value is empty.
type PlatformPolicy struct {
	Value string `json:"value,omitempty"`
	Given bool   `json:"given"`
}

// DurationPolicy renders a duration gate: nil when off (zero), else Go's own
// spelling of it.
func DurationPolicy(d time.Duration) *string {
	if d <= 0 {
		return nil
	}
	s := d.String()
	return &s
}

// WaiversProvenance is every waiver input the scan read: the ignore file (nil
// when there was none) and each --vex document in the order given.
type WaiversProvenance struct {
	IgnoreFile *IgnoreFileProvenance `json:"ignoreFile"`
	VEX        []VEXProvenance       `json:"vex"`
}

// IgnoreFileProvenance is the .assay.yaml a scan applied. Path is the path as
// given to --config, or ".assay.yaml" when it was discovered in the working
// directory — never the absolute path discovery resolved, which would name the
// working directory.
type IgnoreFileProvenance struct {
	Path       string                 `json:"path"`
	Discovered bool                   `json:"discovered"`
	SHA256     string                 `json:"sha256,omitempty"`
	Rules      []IgnoreRuleProvenance `json:"rules"`
}

// IgnoreRuleProvenance is what one rule did: its 1-based position, its expiry
// if any, whether that expiry had passed (an expired rule waives nothing), and
// how many findings it waived.
type IgnoreRuleProvenance struct {
	Rule    int    `json:"rule"`
	Expires string `json:"expires,omitempty"`
	Expired bool   `json:"expired"`
	Matched int    `json:"matched"`
}

// VEXProvenance is one --vex document: the path as given, its sha256 (empty
// when it could not be read), its @id, and what became of its statements —
// how many were read, how many findings they suppressed, how many were skipped
// with a warning, how many named an image that is not this target, and how
// many matched no finding at all (skipped and out-of-scope among them).
type VEXProvenance struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256,omitempty"`
	ID         string `json:"id,omitempty"`
	Statements int    `json:"statements"`
	Applied    int    `json:"applied"`
	Skipped    int    `json:"skipped"`
	OutOfScope int    `json:"outOfScope"`
	Unmatched  int    `json:"unmatched"`
}

// SemanticVersion is the SARIF driver's semanticVersion for a tool version:
// the version without a leading "v" when it reads as one, "" for a
// development build (SARIF wants a semantic version or nothing).
func SemanticVersion(version string) string {
	v := strings.TrimPrefix(version, "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return ""
	}
	return v
}
