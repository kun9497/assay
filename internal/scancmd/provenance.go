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
	"path/filepath"
	"sort"
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
// scan printed, without its "error: " prefix, and with every machine path it
// may carry replaced by a name for what it is (D120: no absolute path that
// was not typed, no username, no working directory). store.Open's errors name
// the database path; a credential file's errors name the home directory or
// the D118 locations the environment points at; anything relative the scan
// resolved names the working directory. stderr keeps them all — it is the
// human channel, and the record is the one that travels.
func (r *recorder) errorText() string {
	msg := r.stderr.first
	if msg == "" {
		msg = r.reason
	}
	if msg == "" {
		return "exit 2"
	}
	return redactMachinePaths(msg, r.dbPath)
}

// redactMachinePaths replaces the database path and each machine location in
// msg with its placeholder, longest path first so a path inside another (the
// database under the home directory, the working directory under it) is named
// for the more specific one. A location that is not absolute, or is a
// filesystem root, is left alone: replacing "/" or "." would mangle every
// path in the message rather than hide one.
func redactMachinePaths(msg, dbPath string) string {
	type sub struct{ path, name string }
	var subs []sub
	add := func(p, name string) {
		if p != "" && filepath.IsAbs(p) && filepath.Dir(p) != p {
			subs = append(subs, sub{filepath.Clean(p), name})
		}
	}
	if wd, err := os.Getwd(); err == nil {
		add(wd, "<cwd>")
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(home, "<home>")
	}
	for _, v := range []string{"REGISTRY_AUTH_FILE", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		add(os.Getenv(v), "<"+v+">")
	}
	sort.SliceStable(subs, func(i, j int) bool { return len(subs[i].path) > len(subs[j].path) })
	// The database path first, whatever its length or form: it was replaced
	// before any of the others existed, and a relative ASSAY_DB_DIR is still
	// a path the caller did not type on this command line.
	if dbPath != "" {
		msg = strings.ReplaceAll(msg, dbPath, "<database>")
	}
	for _, s := range subs {
		msg = replacePath(msg, s.path, s.name)
	}
	return msg
}

// replacePath replaces each occurrence of the path p in msg that ends where a
// path component ends, so "/home/al" is not read inside "/home/alice", while
// a separator, a colon, a space or a sentence's closing period after it is a
// boundary.
func replacePath(msg, p, name string) string {
	var b strings.Builder
	for {
		i := strings.Index(msg, p)
		if i < 0 {
			b.WriteString(msg)
			return b.String()
		}
		end := i + len(p)
		b.WriteString(msg[:i])
		if componentEnds(msg, end) {
			b.WriteString(name)
		} else {
			b.WriteString(p)
		}
		msg = msg[end:]
	}
}

// componentEnds reports whether a path that stops at msg[end] stops at the
// end of a path component.
func componentEnds(msg string, end int) bool {
	if end == len(msg) || os.IsPathSeparator(msg[end]) {
		return true
	}
	if msg[end] == '.' {
		return end+1 == len(msg) || !nameByte(msg[end+1])
	}
	return !nameByte(msg[end])
}

// nameByte reports whether c can continue a file name.
func nameByte(c byte) bool {
	return c == '-' || c == '_' || c == '.' || c >= 0x80 ||
		'0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
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
