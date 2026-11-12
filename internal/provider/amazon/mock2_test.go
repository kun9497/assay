package amazon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
	"github.com/kun9497/assay/internal/version"
)

// The installed Core package and the two fixes below come from the pinned
// amazonlinux2 image and the November 2026 Core and Mock2 updateinfo.
func TestFetchMock2RPMRange(t *testing.T) {
	const core = "ALAS2-2026-4076"
	const extra = "ALAS2MOCK2-2026-003"
	const compat = "ALAS2MOCK2-2026-004"
	const mockOnly = "CVE-2026-103242"
	const shared = "CVE-2026-84837"

	mux := http.NewServeMux()
	mountExtrasCatalog(t, mux, []string{"mock2"})
	mountRepo(t, mux, "/core", []updateFixture{{id: core, cves: []string{shared},
		pkgs: []pkgFixture{{"rpm-libs", "0", "4.11.3", "48.amzn2.0.7", "x86_64"}}}})
	mountRepo(t, mux, "/extras/mock2/latest/x86_64", []updateFixture{
		{id: extra, cves: []string{shared, mockOnly}, pkgs: []pkgFixture{
			{"rpm-libs", "0", "4.14.3", "4.amzn2.0.4", "aarch64"},
			{"rpm-libs", "0", "4.14.3", "4.amzn2.0.4", "x86_64"},
		}},
		{id: compat, cves: []string{shared}, pkgs: []pkgFixture{
			{"compat-rpm-411", "0", "4.11.3", "40.amzn2.0.1", "x86_64"},
		}},
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	p := New(Options{
		Repos:         []Repo{{Ecosystem: "Amazon Linux:2", MirrorListURL: server.URL + "/core/mirror.list"}},
		ExtrasBaseURL: server.URL,
	})
	var advisories []advisory.Advisory
	_, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		advisories = append(advisories, a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, installed, id string
		cves                []string
	}{
		{"rpm-libs", "4.11.3-48.amzn2.0.5", core, []string{shared}},
		{"rpm-libs", "4.11.3-48.amzn2.0.7", "", nil},
		{"rpm-libs", "4.14.3-4.amzn2.0.1", extra, []string{shared, mockOnly}},
		{"rpm-libs", "0:4.14.3-4.amzn2.0.3", extra, []string{shared, mockOnly}},
		{"rpm-libs", "4.14.3-4.amzn2.0.4", "", nil},
		{"rpm-libs", "1:4.11.3-1.amzn2", "", nil},
		{"compat-rpm-411", "4.11.3-40.amzn2", compat, []string{shared}},
	} {
		t.Run(tc.name+"@"+tc.installed, func(t *testing.T) {
			var ids, cves []string
			for _, a := range advisories {
				for _, af := range a.Affected {
					if af.Name != tc.name {
						continue
					}
					hit, _, err := version.InRange(version.RPM{}, tc.installed, af.Ranges[0])
					if err != nil {
						t.Fatal(err)
					}
					if hit {
						ids = append(ids, a.ID)
						cves = append(cves, a.Related...)
					}
				}
			}
			var wantIDs []string
			if tc.id != "" {
				wantIDs = []string{tc.id}
			}
			if !slices.Equal(ids, wantIDs) || !slices.Equal(cves, tc.cves) {
				t.Errorf("got %v %v, want %v %v", ids, cves, wantIDs, tc.cves)
			}
		})
	}
}

func TestMock2IntroducedVersionScope(t *testing.T) {
	mock2 := Repo{Ecosystem: "Amazon Linux:2", Extras: true, Topic: "mock2"}
	for _, tc := range []struct {
		repo                        Repo
		name, epoch, upstream, want string
	}{
		{mock2, "python2-rpm", "0", "4.14.3", "4.14.3"},
		{mock2, "rpm-debuginfo", "", "4.14.3", "4.14.3"},
		{mock2, "compat-rpm-411", "0", "4.14.3", "0"},
		{mock2, "rpm-unrelated", "0", "4.14.3", "0"},
		{mock2, "rpm", "1", "4.14.3", "0"},
		{mock2, "rpm", "0", "4.15.0", "0"},
		{Repo{Ecosystem: "Amazon Linux:2"}, "rpm", "0", "4.14.3", "0"},
		{Repo{Ecosystem: "Amazon Linux:2", Extras: true, Topic: "docker"}, "rpm", "0", "4.14.3", "0"},
		{Repo{Ecosystem: "Amazon Linux:2023", Extras: true, Topic: "mock2"}, "rpm", "0", "4.14.3", "0"},
	} {
		got := introducedVersion(tc.repo, xmlPackage{Name: tc.name, Epoch: tc.epoch, Version: tc.upstream})
		if got != tc.want {
			t.Errorf("%s/%s %s %s:%s: introduced %q, want %q", tc.repo.Ecosystem, tc.repo.Topic, tc.name, tc.epoch, tc.upstream, got, tc.want)
		}
	}
}
