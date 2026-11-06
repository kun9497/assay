package redhat

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/matcher"
	"github.com/kun9497/assay/internal/pkgmeta"
	"github.com/kun9497/assay/internal/store"
)

// QA 2026-11-02 finding #4 (P1). A Hummingbird purl carries its epoch as a
// qualifier, not inside the version -- the live documents
// (cve-2026-42533, cve-2026-56434, cve-2026-60005) spell nginx
// "pkg:rpm/redhat/nginx@1.30.4-2.hum1?arch=x86_64&epoch=2&..." -- and the
// rpmdb cataloger writes the installed build "2:1.30.4-1.hum1" (header.go's
// evr, epoch first when non-zero). hummingbirdPurlRE threw the qualifier
// away, so the stored fix was "1.30.4-2.hum1", version.RPM ordered the
// installed epoch 2 above it, and every vulnerable epoch-carrying build (67
// of the 403 distinct Hummingbird purls in the 160 newest documents: nginx*
// at epoch 2, tomcat10/11 at epoch 1) was reported clean. The fix is the
// same rule pkgmeta.EVROf already applies to scan-side purls: a non-zero
// epoch qualifier is prefixed "epoch:" onto the version.
//
// The real purl, trimmed from cve-2026-42533.json.
const nginxEpochPurl = "pkg:rpm/redhat/nginx@1.30.4-2.hum1?arch=x86_64&distro=hummingbird-20251124&epoch=2&repository_id=public-hummingbird-x86_64-rpms"

// The document also fixes mainline RHEL 9's nginx, whose NEVRA spells its
// epoch inline ("nginx-1:1.20.1-16.el9_4"): every mainline evr carries
// "epoch:", so the counter must be the Hummingbird share alone, not every
// fixed entry with a colon in it.
func nginxEpochDoc(t *testing.T) *document {
	t.Helper()
	return buildHummingbirdDoc(t, "CVE-2026-42533",
		map[string]string{
			"Red Hat Hardened Images": "cpe:/a:redhat:hummingbird:1",
			"AppStream-9":             "cpe:/a:redhat:enterprise_linux:9::appstream",
		},
		map[string]string{"nginx-main@x86_64": nginxEpochPurl},
		[]string{
			"Red Hat Hardened Images:nginx-main@x86_64",
			"AppStream-9:nginx-1:1.20.1-16.el9_4.x86_64",
		},
		nil, nil)
}

// The store-level statement: what convert writes for the fixed event.
func TestConvert_HummingbirdEpochQualifierReachesTheFixedVersion(t *testing.T) {
	var st stats
	adv, ok := convert(nginxEpochDoc(t), &st)
	if !ok {
		t.Fatal("convert dropped a document naming a Hummingbird package")
	}
	a, ok := affectedByName(adv)["Hummingbird/nginx"]
	if !ok {
		t.Fatalf("no Hummingbird/nginx entry, got: %+v", adv.Affected)
	}
	if len(a.Ranges) != 1 || len(a.Ranges[0].Events) != 2 {
		t.Fatalf("Ranges = %+v, want one introduced/fixed pair", a.Ranges)
	}
	if got := a.Ranges[0].Events[1].Fixed; got != "2:1.30.4-2.hum1" {
		t.Errorf("Fixed = %q, want %q (the epoch=2 qualifier prefixed, as rpmdb spells the installed build)", got, "2:1.30.4-2.hum1")
	}
	if m, ok := affectedByName(adv)["Red Hat:9/nginx"]; !ok || m.Ranges[0].Events[1].Fixed != "1:1.20.1-16.el9_4" {
		t.Errorf("Red Hat:9/nginx = %+v, want the mainline fix 1:1.20.1-16.el9_4 beside the Hummingbird one", m)
	}
	if st.HummingbirdFixedWithEpoch != 1 {
		t.Errorf("HummingbirdFixedWithEpoch = %d, want 1: the mainline entry's inline epoch is not Hummingbird's", st.HummingbirdFixedWithEpoch)
	}
}

// The scan-level statement: what a host running nginx is told, through the
// real store and the matcher. Before the fix the first row was clean --
// zero findings, zero skips -- because 2:anything sorts above an epoch-less
// fix. The second row is the build Red Hat shipped the fix in, and must stay
// clean, so the fix is not "report every epoch-carrying build".
func TestHummingbirdEpoch_InstalledBuildBelowTheFixIsAffected(t *testing.T) {
	var st stats
	adv, ok := convert(nginxEpochDoc(t), &st)
	if !ok {
		t.Fatal("convert dropped a document naming a Hummingbird package")
	}
	got := verdictsOf(t, adv,
		pkgmeta.Package{Name: "nginx", Version: "2:1.30.4-1.hum1", Ecosystem: "Hummingbird"},
		pkgmeta.Package{Name: "nginx", Version: "2:1.30.4-2.hum1", Ecosystem: "Hummingbird"})
	if v := got["Hummingbird/nginx@2:1.30.4-1.hum1"]; v != "2:1.30.4-2.hum1" {
		t.Errorf("nginx 2:1.30.4-1.hum1 on Hummingbird = %q, want the fix %q", v, "2:1.30.4-2.hum1")
	}
	if v := got["Hummingbird/nginx@2:1.30.4-2.hum1"]; v != "" {
		t.Errorf("nginx 2:1.30.4-2.hum1 on Hummingbird = %q, want clean: it is the build that carries the fix", v)
	}
}

// The counter reaches the progress line, beside the other Hummingbird
// number, so the day the epoch-carrying share of the feed moves is visible
// in the nightly rather than only in a differential.
func TestStatsString_ReportsHummingbirdFixedWithEpoch(t *testing.T) {
	got := stats{SkippedNoPurl: 3, HummingbirdFixedWithEpoch: 67}.String()
	want := "3 Hummingbird components with no readable purl, 67 Hummingbird fixed builds carrying an epoch"
	if !strings.Contains(got, want) {
		t.Errorf("stats.String() = %q, want it to contain %q", got, want)
	}
}

// verdictsOf drives one converted document through the REAL store and the
// matcher and returns what each installed package was told: "" for no
// finding, the fixed version for a finding that names one, affectedNoFix
// for a finding that names none (suse's d131_verdict_test.go has the
// reasoning for the third value: a no-fix finding must not read as clean).
const affectedNoFix = "<affected, no fix>"

func verdictsOf(t *testing.T, adv advisory.Advisory, pkgs ...pkgmeta.Package) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.Put(adv); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := w.SetMeta(store.Meta{
		BuiltAt:   time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
		Providers: map[string]store.Provenance{SourceName: {Ecosystems: []string{hummingbirdEcosystem, "Red Hat:6", "Red Hat:7", "Red Hat:9"}}},
	}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	out := map[string]string{}
	for _, p := range pkgs {
		res, err := matcher.New(db).Match(pkgmeta.Target{Packages: []pkgmeta.Package{p}})
		if err != nil {
			t.Fatalf("Match(%s %s): %v", p.Name, p.Version, err)
		}
		if len(res.Skipped) != 0 {
			t.Fatalf("Match(%s %s) skipped: %+v", p.Name, p.Version, res.Skipped)
		}
		key := p.Ecosystem + "/" + p.Name + "@" + p.Version
		switch len(res.Findings) {
		case 0:
			out[key] = ""
		case 1:
			out[key] = res.Findings[0].Evidence.Fixed
			if out[key] == "" {
				out[key] = affectedNoFix
			}
		default:
			t.Fatalf("Match(%s %s) = %d findings, want at most 1", p.Name, p.Version, len(res.Findings))
		}
	}
	return out
}
