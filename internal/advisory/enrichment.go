package advisory

// Enrichment is what one authority says about a CVE in prose, for a reader.
//
// It is deliberately not an Advisory and not a Rating. An Advisory says a
// package is affected and can produce a finding; a Rating says how bad a CVE
// is and can raise a band. Enrichment does neither — it carries a title, a
// summary and a link, and D3 fixes it that way: KISA describes much of its
// corpus in prose with no ecosystem and no package name, so treating it as a
// matching source would invent findings nothing can substantiate.
//
// Nothing here may reach a verdict. A scan against a database with no
// enrichment and one with a full bucket must agree on every exit code.
type Enrichment struct {
	CVE    string
	Source string
	Title  string
	// Summary is the notice's own overview section, plain text. It is
	// display copy, not something to parse: the store keeps what upstream
	// wrote (D13) and any structure a reader needs is derived at render
	// time.
	Summary string
	URL     string
}
