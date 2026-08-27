// Package ignore applies a user's suppression rules to a scan's findings —
// the "ignore rules" half of VEX/ignore (the OpenVEX document half is a
// later slice). A rule waives a finding the user has judged irrelevant or
// accepted; the matcher never sees these rules (it stays a pure function of
// target and store), so suppression is a step the scan path runs AFTER
// Match, moving waived findings into matcher.Result.Suppressed rather than
// dropping them.
//
// The discipline that separates this from a naive "just delete it" is the
// same one the whole project rests on (D11, D36): a suppressed finding is
// counted and its reason kept, never silently folded into a clean verdict.
// So a rule MUST state a reason (an unexplained waiver is refused), MAY
// carry an expiry (an expired rule stops waiving and warns, so a waiver
// cannot outlive its own justification in silence), and the report shows
// every suppression with its reason.
package ignore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/matcher"
	"gopkg.in/yaml.v3"
)

// DefaultFile is the config file discovered in a directory when the caller
// names no explicit path — grype's own `.grype.yaml` convention, which
// users already reach for.
const DefaultFile = ".assay.yaml"

// Config is a parsed .assay.yaml. Only the ignore list exists today; the
// file is a struct rather than a bare list so a later slice can add sibling
// keys (an openvex path, output defaults) without breaking a file that only
// carries ignore rules.
type Config struct {
	Ignore []Rule `yaml:"ignore"`
}

// Rule waives a finding that matches EVERY field it names (AND within a
// rule; OR across rules). At least one match field is required — a rule with
// only a reason would waive the whole scan, which is never what a reader
// intends and is refused at load time.
type Rule struct {
	// Vulnerability matches against a finding's identifiers — its advisory ID
	// and every CVE/GHSA alias — so `CVE-2024-1234` waives a finding whose
	// advisory merely aliases it, which is how a user thinks about it.
	Vulnerability string `yaml:"vulnerability"`
	// Package matches Finding.Package.Name exactly.
	Package string `yaml:"package"`
	// Ecosystem matches Finding.Package.Ecosystem exactly ("Alpine:v3.19",
	// "Go") — the escape hatch for "waive this CVE, but only on this distro".
	Ecosystem string `yaml:"ecosystem"`
	// Reason is mandatory: an ignore with no stated reason is refused. The
	// reason rides into the report next to the suppressed finding, so an
	// auditor sees why each waiver exists.
	Reason string `yaml:"reason"`
	// Expires is an optional YYYY-MM-DD date. A rule whose date is in the
	// past stops waiving anything and warns on stderr — a waiver cannot
	// outlive its justification unnoticed. Absent means "no expiry", a
	// deliberate choice a reader can see, not a silent forever.
	Expires string `yaml:"expires"`
}

// Discover returns the path to DefaultFile in dir if it exists. A caller
// uses it for the "no --config given, look in the working directory"
// default; an explicit path goes straight to Load.
func Discover(dir string) (string, bool) {
	p := filepath.Join(dir, DefaultFile)
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		return p, true
	}
	return "", false
}

// Load reads and validates a config file. Every rule is checked here, not at
// apply time: a malformed ignore file is a mistake the user wants told about
// before a scan runs on it, not one that silently waives nothing (or
// everything). The date format is checked too, so a typo'd expiry fails loud
// rather than being read as "already expired" or "never".
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ignore config %s: %w", path, err)
	}
	var c Config
	// KnownFields so a mistyped key ("vulnerabilty:", "reasn:") is an error
	// rather than a rule that silently matches nothing or everything.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse ignore config %s: %w", path, err)
	}
	for i, r := range c.Ignore {
		if strings.TrimSpace(r.Reason) == "" {
			return nil, fmt.Errorf("%s: ignore rule %d has no reason — an unexplained waiver is refused", path, i+1)
		}
		if r.Vulnerability == "" && r.Package == "" && r.Ecosystem == "" {
			return nil, fmt.Errorf("%s: ignore rule %d names no vulnerability, package, or ecosystem — it would waive the whole scan", path, i+1)
		}
		if r.Expires != "" {
			if _, err := time.Parse("2006-01-02", r.Expires); err != nil {
				return nil, fmt.Errorf("%s: ignore rule %d has an unparseable expires %q — want YYYY-MM-DD", path, i+1, r.Expires)
			}
		}
	}
	return &c, nil
}

// Apply partitions findings into those kept and those waived by the config's
// rules, evaluated against now. A rule that has expired is skipped and
// reported through warn (never nil at the call site) so its expiry is
// visible rather than silently no longer waiving. The returned slices never
// alias the input.
//
// now is passed in rather than read from the clock so the decision is
// testable and a scan is reproducible within one run.
func (c *Config) Apply(findings []matcher.Finding, now time.Time, warn func(string)) (kept []matcher.Finding, suppressed []matcher.Suppressed) {
	// Filter the rules to the live ones once, warning about the expired.
	live := make([]Rule, 0, len(c.Ignore))
	for i, r := range c.Ignore {
		if r.Expires != "" {
			// Parse cannot fail here: Load already validated every Expires.
			exp, _ := time.Parse("2006-01-02", r.Expires)
			// Expired at the START of the day AFTER the named date — the
			// named date is the last day the waiver holds, inclusive, which
			// is how a person reads "expires 2026-12-31".
			if !now.Before(exp.AddDate(0, 0, 1)) {
				warn(fmt.Sprintf("ignore rule %d expired %s and no longer applies: %s", i+1, r.Expires, ruleLabel(r)))
				continue
			}
		}
		live = append(live, r)
	}

	for _, f := range findings {
		if r, ok := firstMatch(live, f); ok {
			suppressed = append(suppressed, matcher.Suppressed{Finding: f, Reason: r.Reason})
		} else {
			kept = append(kept, f)
		}
	}
	return kept, suppressed
}

// firstMatch returns the first live rule that waives f, if any. First rather
// than best because reasons do not compose: a finding waived by two rules is
// waived for the first-listed reason, which is the one the file's author put
// first.
func firstMatch(rules []Rule, f matcher.Finding) (Rule, bool) {
	for _, r := range rules {
		if r.matches(f) {
			return r, true
		}
	}
	return Rule{}, false
}

// matches reports whether every field the rule names is satisfied by f.
func (r Rule) matches(f matcher.Finding) bool {
	if r.Vulnerability != "" && !identifierMatches(f, r.Vulnerability) {
		return false
	}
	if r.Package != "" && f.Package.Name != r.Package {
		return false
	}
	if r.Ecosystem != "" && f.Package.Ecosystem != r.Ecosystem {
		return false
	}
	return true
}

// identifierMatches reports whether want is one of the finding's
// identifiers. Compared case-insensitively: a user writing `cve-2024-1234`
// should waive `CVE-2024-1234`, and advisory IDs are not case-normalized
// upstream.
func identifierMatches(f matcher.Finding, want string) bool {
	for _, id := range f.Identifiers {
		if strings.EqualFold(id, want) {
			return true
		}
	}
	return false
}

func ruleLabel(r Rule) string {
	parts := make([]string, 0, 3)
	if r.Vulnerability != "" {
		parts = append(parts, r.Vulnerability)
	}
	if r.Package != "" {
		parts = append(parts, "package "+r.Package)
	}
	if r.Ecosystem != "" {
		parts = append(parts, "ecosystem "+r.Ecosystem)
	}
	return strings.Join(parts, ", ")
}
