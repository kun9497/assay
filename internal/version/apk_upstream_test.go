//go:build upstreamvectors

// This file replays apk-tools' own version-ordering test vectors against our
// comparer. It is the strongest check that exists for this package — it is what
// caught the initial-digit leading-zero defect, which the hand-written table
// missed — so it lives in the repository rather than surviving as a claim in a
// commit message.
//
// Run it with:
//
//	go test -tags upstreamvectors ./internal/version/
//
// It is behind a build tag, and not part of `go test ./...`, for two reasons:
// it needs the network, and vendoring the vector file would import GPL-2.0 test
// data into an Apache-2.0 repository. Fetching at run time keeps the check
// reproducible without taking on that question.
//
// APK_VECTORS may point at a local copy to run it offline.
package version

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// The contents API is used rather than raw.githubusercontent.com because the
// raw host 404s for this path and the GitLab mirror rejects unauthenticated
// reads.
const apkVectorsURL = "https://api.github.com/repos/alpinelinux/apk-tools/contents/" +
	"test/unit/version.data?ref=master"

// Two vectors in the upstream file are versions apk cannot parse, where it falls
// back to a raw string sort and we return ErrInvalid instead (D9). They are
// listed rather than counted so that a THIRD divergence appearing — which would
// mean a real regression — cannot hide inside a tolerance.
var apkKnownDivergences = map[string]string{
	"23_foo > 4_beta": "unknown suffix; apk string-sorts, we refuse to guess",
	"1.0 < 1.0bc":     "two trailing letters; upstream's own comment says 'invalid. do string sort'",
}

func TestAPKAgainstUpstreamVectors(t *testing.T) {
	data := loadAPKVectors(t)

	var c APK
	var total, agree int
	var mismatches, unexpectedInvalid []string

	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		a, op, b := fields[0], fields[1], fields[2]

		var want int
		switch op {
		case "<":
			want = -1
		case "=":
			want = 0
		case ">":
			want = 1
		default:
			// Fuzzy operators (~, <~, >~, !~) are apk's partial-version matching,
			// which Comparer does not implement and is not asked to.
			continue
		}
		total++
		key := a + " " + op + " " + b

		got, err := c.Compare(a, b)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("%s: error does not wrap ErrInvalid: %v", key, err)
				continue
			}
			if _, known := apkKnownDivergences[key]; !known {
				unexpectedInvalid = append(unexpectedInvalid, key)
			}
			continue
		}
		if _, known := apkKnownDivergences[key]; known {
			t.Errorf("%s: now parses, but is recorded as a known divergence. "+
				"Either the parser gained a case it should not have, or the "+
				"divergence list is stale — remove the entry deliberately.", key)
			continue
		}
		if got != want {
			mismatches = append(mismatches, key+" -> apk="+op+" ours="+itoa(got))
			continue
		}
		agree++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	// A vector file that shrank to nothing would otherwise pass silently.
	if total < 700 {
		t.Fatalf("only %d comparisons parsed; the upstream file's format has "+
			"probably changed and this test is no longer checking anything", total)
	}
	for _, m := range mismatches {
		t.Errorf("MISMATCH %s", m)
	}
	for _, u := range unexpectedInvalid {
		t.Errorf("UNEXPECTED ErrInvalid: %s — apk orders these; refusing to is a "+
			"package we would report as unevaluable", u)
	}
	t.Logf("%d comparisons: %d agree, %d mismatch, %d known divergences",
		total, agree, len(mismatches), len(apkKnownDivergences))
}

func loadAPKVectors(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("APK_VECTORS"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("APK_VECTORS=%s: %v", p, err)
		}
		return string(b)
	}

	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Get(apkVectorsURL)
	if err != nil {
		t.Skipf("cannot reach the upstream vectors (%v); set APK_VECTORS to a local copy", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("upstream vectors returned %s; set APK_VECTORS to a local copy", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode contents response: %v", err)
	}
	// The contents API returns base64 with embedded newlines.
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
	if err != nil {
		t.Fatalf("decode vector file: %v", err)
	}
	return string(raw)
}

func itoa(n int) string {
	switch {
	case n < 0:
		return "-1"
	case n > 0:
		return "1"
	}
	return "0"
}
