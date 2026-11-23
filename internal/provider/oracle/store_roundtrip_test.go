package oracle

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// QA 2026-11-20 (P1). One ELSA covering two majors used to be emitted as two
// records under the ELSA's id. The store keys records by id and the last one
// written wins, so the higher major's record replaced the lower's while the
// index still pointed the lower major's packages at it: 4,838 affected
// entries on the live archive (OL8: 1,507) reached a record holding nothing
// for them and were judged clean, with no skip. normalize's own tests could
// not see it -- they stopped at what normalize returned, and one of them
// demanded exactly the two colliding records.

// twoMajorDoc is ELSA-2026-42887's real shape: java-17-openjdk fixed at a
// different EVR on OL8 and on OL9 by one definition.
func twoMajorDoc() string {
	o := &ovalBuilder{}
	branch8 := o.platformCriterion(8) + o.fixCriterion("java-17-openjdk", "1:17.0.20.0.8-1.1.0.1.el8")
	branch9 := o.platformCriterion(9) + o.fixCriterion("java-17-openjdk", "1:17.0.20.0.8-1.1.0.1.el9")
	crit := fmt.Sprintf(`<criteria operator="OR"><criteria operator="AND">%s</criteria><criteria operator="AND">%s</criteria></criteria>`, branch8, branch9)
	return o.doc(definitionXML("ELSA-2026-42887", "elsa", "java-17-openjdk security update",
		[]cveFixture{{"CVE-2026-9001", ""}}, "IMPORTANT", crit))
}

// Through the store and the matcher, the path a scan takes: an install below
// the fix is found on BOTH majors, each against its own major's fix. Before
// the fix the OL8 row was clean.
func TestOracleRecord_EveryMajorSurvivesTheStore(t *testing.T) {
	ol8Below := pkgmeta.Package{Name: "java-17-openjdk", Version: "1:17.0.20.0.8-1.0.0.1.el8", Type: "rpm", Ecosystem: "Oracle Linux:8"}
	ol9Below := pkgmeta.Package{Name: "java-17-openjdk", Version: "1:17.0.20.0.8-1.0.0.1.el9", Type: "rpm", Ecosystem: ol9}
	ol8Fixed := pkgmeta.Package{Name: "java-17-openjdk", Version: "1:17.0.20.0.8-1.1.0.1.el8", Type: "rpm", Ecosystem: "Oracle Linux:8"}

	got := verdictsOf(t, twoMajorDoc(), ol8Below, ol9Below, ol8Fixed)
	if v := got["java-17-openjdk@1:17.0.20.0.8-1.0.0.1.el8"]; v != "1:17.0.20.0.8-1.1.0.1.el8" {
		t.Errorf("OL8 install below the fix = %q, want the el8 fix: the OL9 record must not have replaced OL8's", v)
	}
	if v := got["java-17-openjdk@1:17.0.20.0.8-1.0.0.1.el9"]; v != "1:17.0.20.0.8-1.1.0.1.el9" {
		t.Errorf("OL9 install below the fix = %q, want the el9 fix", v)
	}
	if v := got["java-17-openjdk@1:17.0.20.0.8-1.1.0.1.el8"]; v != "" {
		t.Errorf("OL8 install at the fix = %q, want clean", v)
	}
}

// The store's by-id bucket is last-writer-wins, so an id emitted twice is an
// entry lost. Held on the emitted set itself, whatever the definitions are.
func TestNormalize_NoIDIsEmittedTwice(t *testing.T) {
	var st stats
	defs, _, err := parseOVAL(strings.NewReader(twoMajorDoc()), &st)
	if err != nil {
		t.Fatalf("parseOVAL: %v", err)
	}
	advs := normalize(defs, &st)
	if id, ok := repeatedID(advs); ok {
		t.Fatalf("id %s was emitted more than once; the store keeps only the last record of an id", id)
	}
	if st.Advisories != 1 || st.Affected != 2 {
		t.Errorf("Advisories=%d Affected=%d, want 1 record carrying 2 entries", st.Advisories, st.Affected)
	}
}

// repeatedIDFixturePath is two definitions that both call themselves
// ELSA-2031-0001, one fixing curl and one wget on OL9 -- the one way left to
// emit an id twice now that a definition's majors are joined. Written by
// ovalBuilder and compressed like mini-elsa.xml.bz2 (oracle_test.go).
const repeatedIDFixturePath = "testdata/repeated-id.xml.bz2"

// The caller's test for the guard in Fetch: an archive that would write two
// records under one id fails the build and emits nothing, rather than
// publishing a database in which the first record's packages are judged
// clean.
func TestFetch_AnIDEmittedTwiceFailsTheBuild(t *testing.T) {
	srv := serveFixture(t, repeatedIDFixturePath)
	defer srv.Close()

	emitted := 0
	_, err := New(Options{URL: srv.URL}).Fetch(context.Background(), func(advisory.Advisory) error {
		emitted++
		return nil
	})
	if err == nil {
		t.Fatal("Fetch succeeded on an archive that emits ELSA-2031-0001 twice, want an error")
	}
	if !strings.Contains(err.Error(), "ELSA-2031-0001 was emitted more than once") {
		t.Errorf("error = %v, want it to name the repeated id", err)
	}
	if emitted != 0 {
		t.Errorf("%d records were emitted before the refusal, want none", emitted)
	}
}
