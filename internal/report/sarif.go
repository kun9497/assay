package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/cataloger/cyclonedx"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/severity"
)

// SARIF renders findings as SARIF 2.1.0 (D55).
//
// The format exists to be uploaded, and in practice that means GitHub code
// scanning, which is stricter and narrower than the spec. Two of its rules
// shape everything below: `partialFingerprints` is REQUIRED for a result to be
// tracked across commits, and `security-severity` is the only severity channel
// it reads — a string above 0.0 and at most 10.0, on the RULE rather than the
// result.
//
// What is not negotiable is the obligation every renderer in this project
// carries: a scan that could not evaluate part of its input must not read as a
// clean one. SARIF has a spec-native place for that — invocations[] carrying
// toolExecutionNotifications[] — and GitHub does not support it. So the skips
// go BOTH places (D55): the notification for a consumer that honours the spec,
// and a note-level result so the one consumer that matters actually shows them.
func SARIF(w io.Writer, res matcher.Result, cat cyclonedx.Stats, target, version string, eol EOLStatus) (Summary, error) {
	sum := Summarize(res, cat)

	rules := make([]sarifRule, 0, len(res.Findings)+1)
	results := make([]sarifResult, 0, len(res.Findings)+len(res.Skipped))
	seen := map[string]bool{}

	for _, f := range res.Findings {
		id := ruleID(f)
		if !seen[id] {
			seen[id] = true
			rules = append(rules, findingRule(id, f))
		}
		results = append(results, sarifResult{
			RuleID:  id,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: findingMessage(f, target)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: locationURI(f)},
					Region:           &sarifRegion{StartLine: 1},
				},
			}},
			// Required by GitHub, and derived from what a finding IS rather
			// than from where it sits: a fingerprint keyed on a file offset
			// would make every alert new again the moment a package moved.
			PartialFingerprints: map[string]string{fingerprintKey: fingerprint(f)},
		})
	}

	var notes []sarifNotification
	if len(res.Skipped) > 0 {
		rules = append(rules, notEvaluatedRule())
		for _, s := range res.Skipped {
			msg := skipMessage(s)
			results = append(results, sarifResult{
				RuleID: notEvaluatedRuleID,
				// note, not warning: this is not a claim about the package's
				// security, it is a statement that no claim could be made.
				Level:   "note",
				Message: sarifText{Text: msg},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: skipURI(s)},
						Region:           &sarifRegion{StartLine: 1},
					},
				}},
				PartialFingerprints: map[string]string{
					fingerprintKey: hash(notEvaluatedRuleID, s.Package.Ecosystem, s.Package.Name, s.AdvisoryID),
				},
			})
			notes = append(notes, sarifNotification{
				Level:   "warning",
				Message: sarifText{Text: msg},
			})
		}
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "assay",
			Version:        version,
			InformationURI: "https://github.com/kun9497/assay",
			Rules:          rules,
		}},
		Results: results,
	}
	// Emitted even when nothing was skipped, carrying the counts. A consumer
	// that reads invocations gets the same summary the table prints, and the
	// exitSignalling one below is what says whether the run is worth trusting.
	run.Invocations = []sarifInvocation{{
		ExecutionSuccessful: sum.Trustworthy(),
		// D87: nil when there is no EOL answer (Properties' own doc
		// comment), which Go's json package then drops entirely under
		// sarifInvocation.Properties' own "properties,omitempty" tag — the
		// SARIF-native way to say nothing rather than assert "not EOL".
		Properties: eol.Properties(),
		ToolExecutionNotifications: append([]sarifNotification{{
			Level: summaryLevel(sum),
			Message: sarifText{Text: fmt.Sprintf(
				"%d component(s) seen, %d evaluated, %d finding(s), %d not evaluated, "+
					"%d unknown severity, %d with no fix available (%d will not be fixed)",
				sum.Components, sum.Evaluated, sum.Findings, sum.NotEvaluated,
				sum.UnknownSeverity, sum.Unfixable, sum.WontFix)},
		}}, notes...),
	}}

	doc := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return Summary{}, fmt.Errorf("write sarif: %w", err)
	}
	return sum, nil
}

const (
	notEvaluatedRuleID = "assay/not-evaluated"
	// fingerprintKey names the scheme, so a later change to what a fingerprint
	// is made of can ship as a new key rather than silently re-identifying
	// every existing alert.
	fingerprintKey = "assay/pkg-advisory/v1"
)

func ruleID(f matcher.Finding) string {
	return f.Advisory.ID + "-" + f.Package.Name
}

// findingRule carries everything GitHub reads about severity, plus the fields
// this project has that grype's SARIF drops on the floor.
func findingRule(id string, f matcher.Finding) sarifRule {
	props := map[string]any{
		"tags": []string{"security", "vulnerability"},
		// D52's distinction, which neither grype nor trivy puts in SARIF at
		// all: grype's help text prints an empty "Fix Version:" for every
		// unfixed finding and says nothing about whether one is ever coming.
		"fixState":  f.FixState().String(),
		"unfixable": f.Unfixable(),
	}
	if f.Package.PURL != "" {
		props["purls"] = []string{f.Package.PURL}
	}
	// Omitted, not zeroed, when nothing rated it (D17). GitHub's scale starts
	// above 0.0 and has no room for "unknown"; writing 0.1 would band an
	// unrated finding as low, which is the coercion D17 exists to forbid.
	if f.Severity != severity.Unknown {
		props["security-severity"] = fmt.Sprintf("%.1f", f.Score)
	}
	// D86, on this bag's own reasoning: neither grype nor trivy puts KEV
	// membership or an EPSS score in SARIF at all, and both change what a
	// finding is worth reviewing first, which is exactly what this
	// properties bag exists to carry past the four fixed SARIF levels.
	// Omitted rather than false/zero when absent, same as security-severity
	// above -- a finding no source scored must not render as EPSS 0.0, which
	// reads as "scored safest possible" rather than "not scored at all".
	if kr, ok := f.KnownExploited(); ok {
		props["kev"] = true
		props["kevDateAdded"] = kr.KEVDateAdded
		props["kevRansomware"] = kr.KEVRansomware
	}
	if v, ok := f.MaxEPSS(); ok {
		props["epss"] = v
	}
	r := sarifRule{
		ID:               id,
		Name:             "Vulnerability",
		ShortDescription: sarifText{Text: fmt.Sprintf("%s in %s", f.Advisory.ID, f.Package.Name)},
		FullDescription:  sarifText{Text: descriptionOf(f)},
		Help:             &sarifHelp{Text: helpText(f), Markdown: helpMarkdown(f)},
		Properties:       props,
	}
	return r
}

func notEvaluatedRule() sarifRule {
	return sarifRule{
		ID:               notEvaluatedRuleID,
		Name:             "NotEvaluated",
		ShortDescription: sarifText{Text: "a package this scan could not evaluate"},
		FullDescription: sarifText{Text: "The scan could not decide whether this package is " +
			"affected. It is neither a finding nor a clean result, and treating it as either " +
			"would be wrong: a partial scan must not read as a complete one."},
		Help: &sarifHelp{
			Text: "This package was catalogued but not evaluated. The reason is on the " +
				"result itself. Run `assay scan` without --output sarif to see the full " +
				"Not evaluated section, and use --fail-on-incomplete to make this fail a build.",
		},
		// No security-severity: this is not a security claim.
		Properties: map[string]any{"tags": []string{"security", "not-evaluated"}},
	}
}

// sarifLevel maps a band onto SARIF's four levels.
//
// Unknown lands on "warning" rather than "none". A finding nobody rated is
// still a finding, and "none" reads in most consumers as informational — the
// same flattening D17 refuses when it keeps unknown outside the ordering
// instead of below it.
func sarifLevel(b severity.Band) string {
	switch b {
	case severity.Critical, severity.High:
		return "error"
	case severity.Medium:
		return "warning"
	case severity.Low, severity.None:
		return "note"
	default:
		return "warning"
	}
}

// summaryLevel says how much to trust the run, in the one field a spec-honouring
// consumer reads before the results.
func summaryLevel(s Summary) string {
	switch {
	case !s.Trustworthy():
		return "error"
	case s.NotEvaluated > 0 || s.IncompleteChecks > 0:
		return "warning"
	default:
		return "note"
	}
}

func findingMessage(f matcher.Finding, target string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s affects %s %s", f.Advisory.ID, f.Package.Name, f.Package.Version)
	if f.MatchedName != "" && f.MatchedName != f.Package.Name {
		// D8 (or D95's apk provides bridge — see MatchedViaProvides). Without
		// this the reader looks up an advisory that never mentions the
		// installed package and cannot tell a real finding from a bug.
		if f.MatchedViaProvides {
			fmt.Fprintf(&b, " (matched through apk provides %s)", f.MatchedName)
		} else {
			fmt.Fprintf(&b, " (matched through source package %s)", f.MatchedName)
		}
	}
	if target != "" {
		fmt.Fprintf(&b, " in %s", target)
	}
	switch f.FixState() {
	case advisory.FixStateFixed:
		if f.Evidence.Fixed != "" {
			fmt.Fprintf(&b, ". Fixed in %s.", f.Evidence.Fixed)
		}
	case advisory.FixStateWontFix:
		b.WriteString(". The vendor has said this will not be fixed; " +
			"mitigating or removing the package is the only remedy.")
	case advisory.FixStateNotFixed:
		b.WriteString(". Affected, with no fix published yet.")
	default:
		b.WriteString(". No source records a version that fixes this.")
	}
	return b.String()
}

func skipMessage(s matcher.Skipped) string {
	who := s.Package.Name
	if s.Package.Version != "" {
		who += " " + s.Package.Version
	}
	if s.AdvisoryID != "" {
		return fmt.Sprintf("%s could not be evaluated against %s: %s (cause: %s)",
			who, s.AdvisoryID, s.Reason, s.Cause)
	}
	return fmt.Sprintf("%s could not be evaluated: %s (cause: %s)", who, s.Reason, s.Cause)
}

func descriptionOf(f matcher.Finding) string {
	if f.Advisory.Summary != "" {
		return f.Advisory.Summary
	}
	return fmt.Sprintf("%s affects %s.", f.Advisory.ID, f.Package.Name)
}

func helpText(f matcher.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Vulnerability: %s\n", f.Advisory.ID)
	fmt.Fprintf(&b, "Severity: %s\n", formatSeverity(f.Severity, f.Score))
	fmt.Fprintf(&b, "Package: %s\n", f.Package.Name)
	fmt.Fprintf(&b, "Version: %s\n", f.Package.Version)
	fmt.Fprintf(&b, "Ecosystem: %s\n", f.Package.Ecosystem)
	if f.MatchedName != "" && f.MatchedName != f.Package.Name {
		if f.MatchedViaProvides {
			fmt.Fprintf(&b, "Matched through apk provides: %s\n", f.MatchedName)
		} else {
			fmt.Fprintf(&b, "Matched through source package: %s\n", f.MatchedName)
		}
	}
	// Spelled out rather than left as an empty "Fix Version:", which is what
	// grype's SARIF prints for every unfixed finding.
	fmt.Fprintf(&b, "Fix: %s\n", fixSentence(f))
	if len(f.Ratings) > 1 {
		b.WriteString("Sources:\n")
		for _, r := range f.Ratings {
			fixed := r.Fixed
			if fixed == "" {
				fixed = "no fixed version"
			}
			fmt.Fprintf(&b, "  %s %s: %s, %s\n", r.Database, r.AdvisoryID, r.Severity, fixed)
		}
	}
	if other := otherIDs(f); len(other) > 0 {
		fmt.Fprintf(&b, "Also known as: %s\n", strings.Join(other, ", "))
	}
	return b.String()
}

func helpMarkdown(f matcher.Finding) string {
	return "```\n" + helpText(f) + "```\n"
}

func fixSentence(f matcher.Finding) string {
	switch f.FixState() {
	case advisory.FixStateFixed:
		if f.Evidence.Fixed != "" {
			return "upgrade to " + f.Evidence.Fixed
		}
		return "a fix exists"
	case advisory.FixStateWontFix:
		return "the vendor has said this will not be fixed"
	case advisory.FixStateNotFixed:
		return "affected, with no fix published yet"
	default:
		return "no source records a version that fixes this"
	}
}

func locationURI(f matcher.Finding) string {
	if len(f.Package.Locations) > 0 && f.Package.Locations[0].Path != "" {
		return f.Package.Locations[0].Path
	}
	// Every result needs a location or GitHub drops it, and a package with no
	// recorded path still has an identity worth pointing at.
	return f.Package.Ecosystem + "/" + f.Package.Name
}

func skipURI(s matcher.Skipped) string {
	if len(s.Package.Locations) > 0 && s.Package.Locations[0].Path != "" {
		return s.Package.Locations[0].Path
	}
	if s.Package.Ecosystem != "" {
		return s.Package.Ecosystem + "/" + s.Package.Name
	}
	return s.Package.Name
}

// fingerprint identifies a finding by what it IS. Package identity plus the
// vulnerability, never a file offset or a version — a fingerprint that moved
// when the package was upgraded would close every alert and open a new one on
// the same unfixed problem.
func fingerprint(f matcher.Finding) string {
	return hash(f.Advisory.ID, f.Package.Ecosystem, f.Package.Name, f.MatchedName)
}

func hash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// The SARIF subset this renderer writes. A hand-rolled struct rather than a
// dependency: the format is large, this uses a corner of it, and D-whatever's
// two-direct-dependency rule is not worth spending on a JSON shape.
type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             *sarifHelp     `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
	// Properties is the natural SARIF-native home for a run-level fact that
	// is not itself a result or a rule (D87): the spec's own propertyBag,
	// already used at the rule level by findingRule/notEvaluatedRule above,
	// applies equally at invocation level. nil (omitted) when there is
	// nothing to say — see EOLStatus.Properties' own doc comment.
	Properties                 map[string]any      `json:"properties,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}
