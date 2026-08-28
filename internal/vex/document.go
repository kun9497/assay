// Package vex reads OpenVEX documents and applies them to a scan's findings —
// the second half of D102's "VEX/ignore" story, alongside .assay.yaml (the
// internal/ignore package). A VEX statement exonerates a finding the way an
// ignore rule waives one, and both flow through the identical
// matcher.Result.Suppressed shape (D104): the matcher never sees either, so
// suppression stays a step the scan path runs AFTER Match, and every
// renderer still shows a suppressed finding as counted and reasoned, never
// dropped (D11, D36's own discipline, unchanged by where the waiver came
// from).
//
// Two OpenVEX shapes are read: v0.2.0 (the current spec — structured
// vulnerability{name,aliases,@id} and products[{@id,identifiers.purl,
// subcomponents}]) and the legacy v0.0.1 (`@context: https://openvex.dev/ns`,
// no version suffix — a bare vulnerability string, []string products, and
// subcomponents living on the STATEMENT rather than per-product). Both
// normalize into the one Document/Statement/Product shape below at Load
// time, so match.go never has to know which shape a statement came from.
package vex

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// contextV2 and contextV1 are OpenVEX's own @context strings — the only two
// this package recognizes. Anything else (missing, garbage, a future
// version this package predates) is an unreadable waiver file, not "nothing
// waived": D11 treats an untrustworthy result as worse than an empty one, so
// Load refuses it rather than silently applying zero statements.
const (
	contextV2 = "https://openvex.dev/ns/v0.2.0"
	contextV1 = "https://openvex.dev/ns"
)

// Document is one OpenVEX document, normalized from either wire shape.
// Timestamp is the document-level default a statement's own missing
// timestamp falls back to (D104's ordering rule); HasTimestamp says whether
// the document carried a parseable one at all, since a document that means
// "no timestamp" must not be confused with one meaning "timestamp 0001-01-01".
type Document struct {
	Path         string
	ID           string
	Author       string
	Timestamp    time.Time
	HasTimestamp bool
	Statements   []Statement
}

// Statement is one normalized OpenVEX statement. Order is the statement's
// index in the document (0-based) — needed because latest-statement-wins
// resolves an exact timestamp tie by LAST in document order, not by
// document order itself (grype instead keeps the FIRST/earliest statement,
// which the rules this package implements call a bug rather than a
// precedent to copy).
type Statement struct {
	Order           int
	Vulnerability   Vulnerability
	Products        []Product
	Status          string
	Justification   string
	ImpactStatement string
	ActionStatement string
	Timestamp       time.Time
	HasTimestamp    bool
}

// Vulnerability is a statement's vulnerability identity. ID is the v0.2.0
// vulnerability object's own "@id" (rarely used but part of the spec); Name
// and Aliases are what Chainguard's real feeds actually populate — a CGA
// identifier as Name, with the CVE reachable only through Aliases, so
// matching Name alone misses it (see match.go's vulnerabilityMatches).
type Vulnerability struct {
	Name    string
	Aliases []string
	ID      string
}

// Product is one statement product (v0.2.0) or one product string (v0.0.1,
// where PURLAttr is always empty and ID carries the raw string — including a
// "pkg:"-prefixed one, which match.go still treats as purl-pattern rather
// than a literal string, per the rules doc). Subcomponents narrows a product
// that names something broader than one package (an image, a container) to
// the specific packages inside it named by purl.
//
// v0.0.1's subcomponents live on the STATEMENT rather than per-product;
// normalizeV1 copies that one list onto every product the statement names,
// which is the only sensible reading when the wire format itself does not
// distinguish which product a subcomponent belongs to.
type Product struct {
	ID            string
	PURLAttr      string
	Subcomponents []Product
}

// rawDocument is the union of both wire shapes' top-level fields that this
// package reads before @context tells it which statement shape to expect.
// Version is read as json.RawMessage because v0.2.0 writes it as an int and
// v0.0.1 as a string — a single typed field cannot hold both, and this
// package never uses the value anyway (nothing here is version-gated on it
// beyond @context itself).
type rawDocument struct {
	Context    string          `json:"@context"`
	ID         string          `json:"@id"`
	Author     string          `json:"author"`
	Timestamp  string          `json:"timestamp"`
	Statements json.RawMessage `json:"statements"`
}

type rawStatementV2 struct {
	Vulnerability struct {
		Name    string   `json:"name"`
		Aliases []string `json:"aliases"`
		ID      string   `json:"@id"`
	} `json:"vulnerability"`
	Products []struct {
		ID          string `json:"@id"`
		Identifiers struct {
			PURL string `json:"purl"`
		} `json:"identifiers"`
		Subcomponents []struct {
			ID          string `json:"@id"`
			Identifiers struct {
				PURL string `json:"purl"`
			} `json:"identifiers"`
		} `json:"subcomponents"`
	} `json:"products"`
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement"`
	ActionStatement string `json:"action_statement"`
	Timestamp       string `json:"timestamp"`
}

type rawStatementV1 struct {
	Vulnerability   string   `json:"vulnerability"`
	Products        []string `json:"products"`
	Subcomponents   []string `json:"subcomponents"`
	Status          string   `json:"status"`
	Justification   string   `json:"justification"`
	ImpactStatement string   `json:"impact_statement"`
	ActionStatement string   `json:"action_statement"`
	Timestamp       string   `json:"timestamp"`
}

// Load reads and parses an OpenVEX document at path, normalizing either wire
// shape into Document. Only document-level problems fail here — unreadable
// file, invalid JSON, unrecognized @context — the same "cannot be trusted"
// reasoning ignore.Load applies to a malformed .assay.yaml (D11). A
// statement-level problem (an unknown status, a not_affected with no stated
// reason, a product-less statement) is not fatal to the rest of the
// document: Apply skips that one statement and warns, mirroring how
// ignore.Config.Apply skips one expired rule rather than failing the whole
// file. That split is deliberate, not an oversight — a single malformed
// statement in an otherwise-good feed (Chainguard's or anyone else's) must
// not blind the scan to every other statement in it.
func Load(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vex document %s: %w", path, err)
	}
	var raw rawDocument
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse vex document %s: %w", path, err)
	}

	doc := &Document{Path: path, ID: raw.ID, Author: raw.Author}
	if ts, ok := parseTimestamp(raw.Timestamp); ok {
		doc.Timestamp, doc.HasTimestamp = ts, true
	}

	switch raw.Context {
	case contextV2:
		var stmts []rawStatementV2
		if len(raw.Statements) > 0 {
			if err := json.Unmarshal(raw.Statements, &stmts); err != nil {
				return nil, fmt.Errorf("parse vex document %s: statements: %w", path, err)
			}
		}
		for i, s := range stmts {
			doc.Statements = append(doc.Statements, normalizeV2(i, s))
		}
	case contextV1:
		var stmts []rawStatementV1
		if len(raw.Statements) > 0 {
			if err := json.Unmarshal(raw.Statements, &stmts); err != nil {
				return nil, fmt.Errorf("parse vex document %s: statements: %w", path, err)
			}
		}
		for i, s := range stmts {
			doc.Statements = append(doc.Statements, normalizeV1(i, s))
		}
	default:
		// Empty and garbage both land here (an empty string is not
		// contextV1/contextV2 either), which is exactly right: a file that
		// forgot @context and a file that named a version this package
		// predates are the identical "cannot be trusted" case (D11).
		return nil, fmt.Errorf("vex document %s: unrecognized @context %q (want %q or %q)",
			path, raw.Context, contextV2, contextV1)
	}
	return doc, nil
}

func normalizeV2(order int, s rawStatementV2) Statement {
	st := Statement{
		Order: order,
		Vulnerability: Vulnerability{
			Name:    s.Vulnerability.Name,
			Aliases: s.Vulnerability.Aliases,
			ID:      s.Vulnerability.ID,
		},
		Status:          s.Status,
		Justification:   s.Justification,
		ImpactStatement: s.ImpactStatement,
		ActionStatement: s.ActionStatement,
	}
	if ts, ok := parseTimestamp(s.Timestamp); ok {
		st.Timestamp, st.HasTimestamp = ts, true
	}
	for _, p := range s.Products {
		prod := Product{ID: p.ID, PURLAttr: p.Identifiers.PURL}
		for _, sc := range p.Subcomponents {
			prod.Subcomponents = append(prod.Subcomponents, Product{ID: sc.ID, PURLAttr: sc.Identifiers.PURL})
		}
		st.Products = append(st.Products, prod)
	}
	return st
}

// normalizeV1 maps the legacy shape onto the same Statement type: the bare
// vulnerability string becomes Vulnerability.Name (v0.0.1 has no aliases or
// @id to carry), each product string becomes a Product{ID: ...} (PURLAttr is
// a v0.2.0-only concept — match.go's "@id starting with pkg:" fallback is
// what lets a v0.0.1 purl-shaped product string still match by purl
// semantics), and the statement-level Subcomponents list is copied onto
// EVERY product — see Product's own doc comment for why.
func normalizeV1(order int, s rawStatementV1) Statement {
	st := Statement{
		Order:           order,
		Vulnerability:   Vulnerability{Name: s.Vulnerability},
		Status:          s.Status,
		Justification:   s.Justification,
		ImpactStatement: s.ImpactStatement,
		ActionStatement: s.ActionStatement,
	}
	if ts, ok := parseTimestamp(s.Timestamp); ok {
		st.Timestamp, st.HasTimestamp = ts, true
	}
	var subs []Product
	for _, raw := range s.Subcomponents {
		subs = append(subs, Product{ID: raw})
	}
	for _, raw := range s.Products {
		st.Products = append(st.Products, Product{ID: raw, Subcomponents: subs})
	}
	return st
}

// parseTimestamp reads an OpenVEX timestamp, which the spec pins to RFC3339
// but real documents vary in sub-second precision — time.RFC3339Nano parses
// both a bare-seconds stamp and a fractional one, so trying it alone is
// enough. An empty or unparseable string reports !ok rather than erroring
// the whole document: D104's rules single out only the fully-absent case
// (row 29) as warn-worthy, at Apply time where the statement's identity is
// available to name in the message — a malformed string is treated the same
// as absent, not as a document-level failure.
func parseTimestamp(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
