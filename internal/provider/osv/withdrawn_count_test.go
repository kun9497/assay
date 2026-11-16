package osv

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kun9497/assay/internal/advisory"
)

// The osv: progress line a build prints names how many records each
// ecosystem lost to D16's withdrawn drop, so a collapsed key (Echo:Go
// 285 -> 2 on 2026-11-15) reads as an upstream withdrawal from the log of
// the build that saw it. Driven through Fetch: the count is the caller's.
func TestFetch_ProgressNamesWithdrawnPerEcosystem(t *testing.T) {
	rec := func(id, eco, withdrawn string) string {
		w := ""
		if withdrawn != "" {
			w = `"withdrawn":"` + withdrawn + `",`
		}
		return `{"id":"` + id + `",` + w + `"affected":[{"package":{"name":"x","ecosystem":"` + eco + `"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}`
	}
	body := zipWith(t, map[string]string{
		"ECHO-a.json": rec("ECHO-a", "Echo:Go", "2026-11-12T08:00:07Z"),
		"ECHO-b.json": rec("ECHO-b", "Echo:Go", "2026-11-12T08:00:07Z"),
		"ECHO-c.json": rec("ECHO-c", "Echo:npm", "2026-11-12T08:00:07Z"),
		"ECHO-d.json": rec("ECHO-d", "Echo:Go", ""),
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Mon, 16 Nov 2026 00:00:00 GMT")
		w.Write(body)
	}))
	defer srv.Close()
	p := New([]string{"Echo"}, srv.URL)
	var progress bytes.Buffer
	p.progress = &progress
	var got []advisory.Advisory
	if _, err := p.Fetch(context.Background(), func(a advisory.Advisory) error {
		got = append(got, a)
		return nil
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "ECHO-d" {
		t.Fatalf("emitted %v, want only ECHO-d", got)
	}
	if want := "withdrawn (D16) by affected ecosystem: Echo:Go 2, Echo:npm 1"; !strings.Contains(progress.String(), want) {
		t.Errorf("progress lacks %q:\n%s", want, progress.String())
	}
}

func TestStats_WithdrawnSummaryNone(t *testing.T) {
	if got := (stats{}).withdrawnSummary(); got != "none" {
		t.Errorf("withdrawnSummary of nothing = %q, want none", got)
	}
	var st stats
	st.countWithdrawn([]rawAffected{{}, {}})
	if st.Withdrawn[""] != 1 {
		t.Errorf("two affected entries of one ecosystem counted %d, want 1", st.Withdrawn[""])
	}
}
