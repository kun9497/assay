package scancmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kun9497/assay/internal/report"
	"github.com/kun9497/assay/internal/source"
)

// sidecarSchemaVersion is the --provenance file's own contract version, apart
// from the report's: the two documents change for different reasons.
const sidecarSchemaVersion = 1

// Sidecar is what --provenance writes (D120): the report's provenance object
// plus the facts that differ between two runs of the same inputs. Those are
// kept out of the report so it stays byte-deterministic, and they live here
// so a run that ended before any report existed still leaves a record.
type Sidecar struct {
	SchemaVersion int                `json:"schemaVersion"`
	Provenance    *report.Provenance `json:"provenance"`
	Run           SidecarRun         `json:"run"`
}

// SidecarRun is the run itself. Error is the first error line of an exit 2,
// with the database path replaced, and "" for any other exit. ReportSHA256
// is the sha256 of every byte written to stdout, null when nothing was
// written. Output is the renderer asked for: table, json, sarif or explain.
type SidecarRun struct {
	StartedAt    string  `json:"startedAt"`
	FinishedAt   string  `json:"finishedAt"`
	ExitCode     int     `json:"exitCode"`
	Error        string  `json:"error"`
	ReportSHA256 *string `json:"reportSha256"`
	Output       string  `json:"output"`
}

// recorder is one scan's provenance in progress (D120). Run builds it before
// anything can fail, every stage fills in what it learned, and finish — run
// from a defer, so no return path can skip it — writes the sidecar. The two
// writers it hands the scan are the caller's own, passed through: stdout is
// hashed on the way, and stderr is watched for the first "error: " line,
// which is how an exit 2 from any of the scan's many refusals gets its cause
// into the record without each one learning to report it twice.
type recorder struct {
	opts    Options
	dbPath  string
	started time.Time
	prov    *report.Provenance
	stdout  *hashingWriter
	stderr  *errorLineWriter
	// reason is an exit 2's cause when no error line states it — the
	// --fail-on-incomplete verdict, which prints none.
	reason string
}

func newRecorder(dbPath, target string, opts Options, stdout, stderr io.Writer) *recorder {
	return &recorder{
		opts:    opts,
		dbPath:  dbPath,
		started: clockNow().UTC(),
		prov: &report.Provenance{
			Tool:    report.NewToolProvenance(opts.Version, opts.Commit, opts.BuildDate),
			Target:  report.TargetProvenance{Argument: target},
			Policy:  policyOf(opts),
			Waivers: report.WaiversProvenance{VEX: []report.VEXProvenance{}},
		},
		stdout: &hashingWriter{w: stdout, h: sha256.New()},
		stderr: &errorLineWriter{w: stderr},
	}
}

// finish writes the sidecar when --provenance asked for one and returns the
// exit code: code itself, or 2 when the record could not be written — the
// caller asked for a record and did not get one.
func (r *recorder) finish(code int) int {
	if r.opts.ProvenanceFile == "" {
		return code
	}
	run := SidecarRun{
		StartedAt:  r.started.Format(time.RFC3339Nano),
		FinishedAt: clockNow().UTC().Format(time.RFC3339Nano),
		ExitCode:   code,
		Output:     outputName(r.opts),
	}
	if code == 2 {
		run.Error = r.errorText()
	}
	if r.stdout.n > 0 {
		s := hex.EncodeToString(r.stdout.h.Sum(nil))
		run.ReportSHA256 = &s
	}
	data, err := json.MarshalIndent(Sidecar{SchemaVersion: sidecarSchemaVersion, Provenance: r.prov, Run: run}, "", "  ")
	if err == nil {
		err = os.WriteFile(r.opts.ProvenanceFile, append(data, '\n'), 0o644)
	}
	if err != nil {
		fmt.Fprintf(r.stderr, "error: write provenance %s: %v\n", r.opts.ProvenanceFile, err)
		return 2
	}
	return code
}

// errorText is an exit 2's cause for the sidecar: the first error line the
// scan printed, without its "error: " prefix, and with the database path
// replaced — store.Open's errors name it, and it names the user's home.
func (r *recorder) errorText() string {
	msg := r.stderr.first
	if msg == "" {
		msg = r.reason
	}
	if msg == "" {
		return "exit 2"
	}
	if r.dbPath != "" {
		msg = strings.ReplaceAll(msg, r.dbPath, "<database>")
	}
	return msg
}

// outputName is the renderer a run asked for, as the sidecar names it.
func outputName(opts Options) string {
	switch {
	case opts.Explain != "":
		return "explain"
	case opts.Output == "":
		return "table"
	default:
		return opts.Output
	}
}

// Refuse ends a scan that failed before Run could start — the database could
// not even be located, or no target was given — the way Run ends one: the
// error on stderr, and the sidecar written when --provenance asked for it, so
// that no exit after argument parsing goes unrecorded.
func Refuse(target string, opts Options, err error, stderr io.Writer) int {
	r := newRecorder("", target, opts, io.Discard, stderr)
	fmt.Fprintf(r.stderr, "error: %v\n", err)
	return r.finish(2)
}

// hashingWriter passes writes through and hashes what was written.
type hashingWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (hw *hashingWriter) Write(p []byte) (int, error) {
	n, err := hw.w.Write(p)
	hw.h.Write(p[:n])
	hw.n += int64(n)
	return n, err
}

// errorLineWriter passes writes through and keeps the first line that starts
// "error: ". Only the line in progress is buffered, and only up to a bound, so
// a long diagnostic cannot grow it.
type errorLineWriter struct {
	w     io.Writer
	line  []byte
	first string
}

const maxErrorLine = 4096

func (ew *errorLineWriter) Write(p []byte) (int, error) {
	n, err := ew.w.Write(p)
	for _, b := range p[:n] {
		if b == '\n' {
			if ew.first == "" && bytes.HasPrefix(ew.line, []byte("error: ")) {
				ew.first = strings.TrimSpace(string(ew.line[len("error: "):]))
			}
			ew.line = ew.line[:0]
			continue
		}
		if len(ew.line) < maxErrorLine {
			ew.line = append(ew.line, b)
		}
	}
	return n, err
}

// policyOf records every input that can move the exit code (D120). Platform
// is filled in by Run once the target is classified: defaulted, it is the
// host's for an image and nothing for anything else.
func policyOf(opts Options) report.PolicyProvenance {
	p := report.PolicyProvenance{
		FailOnUnknown:          opts.FailOnUnknown,
		FailOnIncomplete:       opts.FailOnIncomplete,
		FailOnIncompleteTarget: opts.FailOnIncompleteTarget,
		FailOnUnfixable:        opts.FailOnUnfixable,
		FailOnUnfixableWontFix: opts.FailOnUnfixableWontFix,
		FailOnKEV:              opts.FailOnKEV,
		FailOnEOL:              opts.FailOnEOL,
		DBMaxAge:               report.DurationPolicy(opts.DBMaxAge),
		DBMaxRatingAge:         report.DurationPolicy(opts.DBMaxRatingAge),
		Timeout:                report.DurationPolicy(opts.Timeout),
	}
	if opts.FailOn != nil {
		s := opts.FailOn.String()
		p.FailOn = &s
	}
	if opts.FailOnEPSS != nil {
		v := *opts.FailOnEPSS
		p.FailOnEPSS = &v
	}
	if opts.Platform != "" {
		p.Platform = report.PlatformPolicy{Value: opts.Platform, Given: true}
	}
	return p
}

// defaultPlatformPolicy is --platform defaulted for an image: the host's
// platform, as the image loader will ask for it.
func defaultPlatformPolicy() report.PlatformPolicy {
	return report.PlatformPolicy{Value: source.DefaultPlatform().String()}
}

// credentialName is the provenance spelling of a D118 credential source: a
// name this build defines, never a value.
func credentialName(s source.CredentialSource) string {
	switch s {
	case source.CredentialsEnvironment:
		return "environment"
	case source.CredentialsDockerConfig:
		return "docker-config"
	case source.CredentialsPodmanFile:
		return "podman-auth-file"
	case source.CredentialsNone:
		return "none"
	}
	return string(s)
}

// fileSHA256 hashes a file target (a Go binary, a jar) by streaming it. ""
// when it cannot be read, which the parser reading it will report.
func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
