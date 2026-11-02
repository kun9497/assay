package suse

import (
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/pkgmeta"
)

// D159 end to end: SUSE leaves the product_version leaf out of a document
// for a package it has not shipped a build of yet, so a bare known_affected
// id is often the only thing a document says about a release -- 686 of the
// 10,737 known_affected ids on SLES 15 SPx / 16.x in 699 live documents
// sampled 2026-11-02 (MozillaFirefox, kernel, apache2 on SLES 15 SP7). Until
// D159 every one was a skip and the host running the package was told
// nothing; the name never needed the leaf (D126 takes it from the
// product_id), so the leaf's absence carried no information.
func TestD159_LeaflessBareIDIsJudgedAffectedNoFix(t *testing.T) {
	// buildDocWith with no known_not_affected ids: buildDoc's filler id
	// names no leaf either, and would be counted here too.
	d := buildDocWith(t, "CVE-2026-11786",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		// No leaf for MozillaFirefox at all: the document's tree names only
		// an unrelated build, the live shape (cve-2026-117860.json).
		map[string]string{"curl-8.0.0-1.1": "pkg:rpm/suse/curl@8.0.0-1.1?upstream=curl-8.0.0-1.1.src.rpm"},
		nil,
		[]string{"SUSE Linux Enterprise Server 15 SP6:MozillaFirefox"},
		nil,
		[]map[string]any{{
			"category":    "no_fix_planned",
			"product_ids": []string{"SUSE Linux Enterprise Server 15 SP6:MozillaFirefox"},
		}})

	var st stats
	adv, ok := convert(d, &st)
	if !ok {
		t.Fatal("convert dropped the document: its only statement is the leafless id")
	}
	got := verdictsOf(t, adv,
		pkgmeta.Package{Name: "MozillaFirefox", Version: "128.5.0-150200.152.1", Ecosystem: "SLES:15.SP6"})
	if v := got["SLES:15.SP6/MozillaFirefox@128.5.0-150200.152.1"]; v != affectedNoFix {
		t.Errorf("MozillaFirefox on SLES 15 SP6 = %q, want %q", v, affectedNoFix)
	}
	var entry *advisory.Affected
	for i := range adv.Affected {
		if adv.Affected[i].Ecosystem == "SLES:15.SP6" && adv.Affected[i].Name == "MozillaFirefox" {
			entry = &adv.Affected[i]
		}
	}
	if entry == nil || len(entry.Ranges) != 1 || entry.Ranges[0].FixState != advisory.FixStateWontFix {
		t.Errorf("entry = %+v, want one range carrying the no_fix_planned reason: the remediation id is the same leafless id", entry)
	}
	if st.BareNamedWithoutLeaf != 2 || st.SkippedUnknownPackage != 0 {
		t.Errorf("BareNamedWithoutLeaf = %d, SkippedUnknownPackage = %d, want 2 (status + remediation id), 0",
			st.BareNamedWithoutLeaf, st.SkippedUnknownPackage)
	}
}

// What D159 leaves alone. A recommended id still needs its leaf, because
// the leaf's purl is where the fixed version comes from; and a leaf that
// exists with no readable purl (the java-1_7_0-openjdk gap) stays a skip
// for a bare id too, because that is a leaf SUSE wrote and this reader
// could not read, not one SUSE left out.
func TestD159_RecommendedAndNoPurlLeavesStillSkip(t *testing.T) {
	d := buildDocWith(t, "CVE-2026-11787",
		[]string{"SUSE Linux Enterprise Server 15 SP6"},
		map[string]string{"java-1_7_0-openjdk": ""},
		[]string{"SUSE Linux Enterprise Server 15 SP6:ghost-1.0-1.1"},
		[]string{"SUSE Linux Enterprise Server 15 SP6:java-1_7_0-openjdk"},
		nil, nil)

	var st stats
	adv, ok := convert(d, &st)
	if ok {
		t.Errorf("convert kept the document with entries %+v, want none", adv.Affected)
	}
	if st.SkippedUnknownPackage != 2 || st.BareNamedWithoutLeaf != 0 || st.SkippedNoPurl != 1 {
		t.Errorf("SkippedUnknownPackage = %d, BareNamedWithoutLeaf = %d, SkippedNoPurl = %d, want 2, 0, 1",
			st.SkippedUnknownPackage, st.BareNamedWithoutLeaf, st.SkippedNoPurl)
	}
}

// Both counters reach the progress line, each beside what it is read
// against: the D159 names beside D126's renames, and the no-purl leaves
// beside the entries they caused to be skipped -- SkippedNoPurl was counted
// and never printed before (audit P4).
func TestStatsString_ReportsD159AndNoPurl(t *testing.T) {
	got := stats{SkippedUnknownPackage: 9, SkippedNoPurl: 4, BareNamedByProductID: 3, BareNamedWithoutLeaf: 7}.String()
	for _, want := range []string{
		"9 naming a package with no readable purl (4 leaves with no purl)",
		"3 bare entries named by their product id where the purl's name differed (D126), " +
			"7 bare entries named by their product id with no leaf in the document (D159)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stats.String() = %q, want it to contain %q", got, want)
		}
	}
}
