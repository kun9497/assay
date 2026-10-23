// Command dbstatus writes status.json, the public freshness signal for the
// published database (D138). The publish and sign workflows run it after
// every run, success or failure, and commit its output to the `status`
// branch, where it is served at
// https://raw.githubusercontent.com/kun9497/assay/status/status.json.
//
// It answers the two questions nothing else answered for a customer or a
// monitor: is the database still being published (lastSuccess), and what
// is on the tag right now (published: digest, build date, data date,
// signature). It reads the live tag rather than trusting the run it was
// called from, because the tag is what `db update` will fetch: after a
// failed night it is the previous night's artifact, and that is the truth
// to report.
//
// Not shipped by `make build`; the workflows run it with `go run`.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kun9497/assay/internal/dbartifact"
	"github.com/kun9497/assay/internal/dbcmd"
	"github.com/kun9497/assay/internal/dbcmd/trust"
)

// Status is status.json. Fields are only ever added; a consumer keyed on
// schemaVersion 1 keeps working.
type Status struct {
	SchemaVersion int       `json:"schemaVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	// LastRun is the most recent publish-side run, whatever its result.
	LastRun *Run `json:"lastRun,omitempty"`
	// LastSuccess is the most recent run that succeeded. A monitor alerts
	// when it is older than a day and a half: the nightly runs every 24h.
	LastSuccess *Run `json:"lastSuccess,omitempty"`
	// Published describes what the tag served when it was last read.
	Published *Artifact `json:"published,omitempty"`
	// PublishedError is set when the tag could not be read this time; the
	// previous Published is kept beside it, with its own ObservedAt.
	PublishedError string `json:"publishedError,omitempty"`
}

type Run struct {
	Workflow   string    `json:"workflow"`
	Result     string    `json:"result"`
	FinishedAt time.Time `json:"finishedAt"`
	URL        string    `json:"url"`
}

type Artifact struct {
	Reference      string    `json:"reference"`
	Digest         string    `json:"digest"`
	SchemaVersion  int       `json:"schemaVersion"`
	BuiltAt        time.Time `json:"builtAt"`
	DataAsOf       time.Time `json:"dataAsOf"`
	DataAsOfSource string    `json:"dataAsOfSource,omitempty"`
	// Signed is never omitted: false is the outage D137 made possible,
	// and an absent field would read as "not reported".
	Signed         bool      `json:"signed"`
	SignedBy       string    `json:"signedBy,omitempty"`
	SignatureError string    `json:"signatureError,omitempty"`
	ObservedAt     time.Time `json:"observedAt"`
}

// Seams for tests: the clock, and the keys a signature is verified against
// (the embedded production keys cannot sign anything in a test).
var (
	now         = func() time.Time { return time.Now().UTC() }
	trustedKeys = trust.TrustedKeys
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dbstatus", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ref := fs.String("ref", dbcmd.Ref(dbcmd.DefaultRef), "the published tag to describe")
	prev := fs.String("prev", "", "the previous status.json, if any")
	out := fs.String("out", "status.json", "where to write status.json")
	workflow := fs.String("workflow", "", "the workflow reporting (db-publish, db-sign)")
	result := fs.String("result", "", "the run's result: success, failure or cancelled")
	runURL := fs.String("run-url", "", "the run's URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch *result {
	case "success", "failure", "cancelled":
	default:
		fmt.Fprintf(stderr, "error: -result %q, want success, failure or cancelled\n", *result)
		return 2
	}
	if *workflow == "" {
		fmt.Fprintln(stderr, "error: -workflow is required")
		return 2
	}

	var s Status
	if *prev != "" {
		b, err := os.ReadFile(*prev)
		switch {
		case err == nil:
			if err := json.Unmarshal(b, &s); err != nil {
				// A corrupt previous status is replaced, not fatal: the
				// next one is written from the live tag either way.
				fmt.Fprintf(stderr, "warning: previous status %s is not JSON (%v); starting fresh\n", *prev, err)
				s = Status{}
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			fmt.Fprintf(stderr, "error: read %s: %v\n", *prev, err)
			return 1
		}
	}

	at := now()
	s.SchemaVersion = 1
	s.GeneratedAt = at
	r := &Run{Workflow: *workflow, Result: *result, FinishedAt: at, URL: *runURL}
	s.LastRun = r
	if *result == "success" {
		s.LastSuccess = r
	}

	a, err := describe(context.Background(), *ref, at)
	if err != nil {
		fmt.Fprintf(stderr, "warning: could not read %s: %v (keeping the previous description)\n", *ref, err)
		s.PublishedError = err.Error()
	} else {
		s.Published = a
		s.PublishedError = ""
	}

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "error: encode status: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fmt.Fprintf(stderr, "error: write %s: %v\n", *out, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", b)
	return 0
}

// describe reads the tag's manifest and signature. A missing or invalid
// signature is part of the description, not an error: the artifact was
// read, and "unsigned" is what there is to say about it.
func describe(ctx context.Context, ref string, at time.Time) (*Artifact, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	img, err := remote.Image(r, opts...)
	if err != nil {
		return nil, err
	}
	d, err := img.Digest()
	if err != nil {
		return nil, err
	}
	m, err := dbartifact.MetaOf(img)
	if err != nil {
		return nil, err
	}
	a := &Artifact{
		Reference: r.String(), Digest: d.String(), SchemaVersion: m.SchemaVersion,
		BuiltAt: m.BuiltAt, DataAsOf: m.DataAsOf, DataAsOfSource: m.DataAsOfSource, ObservedAt: at,
	}
	keyID, err := trust.Verify(ctx, r.Context(), d, trustedKeys(), opts...)
	if err != nil {
		a.SignatureError = err.Error()
	} else {
		a.Signed, a.SignedBy = true, keyID
	}
	return a, nil
}
