package scancmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/assay/internal/source"
	"github.com/kun9497/assay/internal/store"
)

// D112's caller tests. Every one drives Run end to end against a real
// docker-archive file or SBOM on disk, because the bound is only worth
// anything if the scan a user runs is the thing it stops: the source package's
// own tests reach Files and friends directly, and would stay green if Run
// caught the error and folded it into a partial result instead.

// lowerLimit sets one of source's D112 limits for the rest of the test. No test
// in this package runs in parallel, so a package variable is safe to move.
func lowerLimit(t *testing.T, limit *int64, v int64) {
	t.Helper()
	prev := *limit
	*limit = v
	t.Cleanup(func() { *limit = prev })
}

// d112DB is an empty, complete database covering Debian 12 and Go, so the
// fixtures below are evaluated and clean at the default limits: any exit 2
// they produce under a lowered limit can only come from the limit.
func d112DB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vulnerability.db")
	w, err := store.Create(path)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := w.SetMeta(store.Meta{Providers: map[string]store.Provenance{
		"osv": {Ecosystems: []string{"Debian:12", "Go"}},
	}}); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path
}

// d112Status is a real-shaped dpkg status of n installed packages, about 60
// bytes a stanza, so 100 stanzas is comfortably past a 4 KiB limit.
func d112Status(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "Package: d112pkg%03d\nStatus: install ok installed\nVersion: 1.0-%d\n\n", i, i)
	}
	return b.String()
}

func d112DebianImage(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{osReleasePath: osReleaseDebian12, dpkgDBPath: d112Status(100)}
	for k, v := range extra {
		files[k] = v
	}
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, files)
	return "docker-archive:" + tarPath
}

func runD112(t *testing.T, ctx context.Context, dbPath, target string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(ctx, dbPath, target, Options{}, &out, &errOut)
	return out.String(), errOut.String(), code
}

// TestRun_FileOverThePerFileLimitExits2 is the per-file bound held at the
// scan a user runs. The rendered pair "<path> exceeds the 4 KiB per-file
// limit" is asserted, not either half: the path alone also appears in the
// error a truncated read would produce, and "per-file limit" alone would pass
// on any file's message.
//
// The default-limit row is what makes the lowered row mean something: the same
// image is clean, so its exit 2 comes from the limit and nothing else.
func TestRun_FileOverThePerFileLimitExits2(t *testing.T) {
	dbPath := d112DB(t)
	target := d112DebianImage(t, nil)

	t.Run("default limit: the image scans clean", func(t *testing.T) {
		out, errOut, code := runD112(t, context.Background(), dbPath, target)
		if code != 0 {
			t.Fatalf("Run = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		if !strings.Contains(out, "in 100 package(s)") {
			t.Errorf("stdout should report all 100 dpkg packages evaluated:\n%s", out)
		}
	})

	t.Run("lowered limit: exit 2 naming the file and the limit", func(t *testing.T) {
		lowerLimit(t, &source.MaxFileBytes, 4<<10)
		out, errOut, code := runD112(t, context.Background(), dbPath, target)
		if code != 2 {
			t.Fatalf("Run = %d, want 2 -- a package database past the limit is an untrusted "+
				"result (D112, D11), not a partial one\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		if want := dpkgDBPath + " exceeds the 4 KiB per-file limit (D112)"; !strings.Contains(errOut, want) {
			t.Errorf("stderr does not say %q:\n%s", want, errOut)
		}
		// Stream discipline: an untrusted scan writes no report at all.
		if out != "" {
			t.Errorf("an over-limit scan wrote to stdout:\n%s", out)
		}
	})
}

// TestRun_ScanOverThePerScanLimitExits2 holds the per-scan total at Run. The
// three rows bracket the image's exact read total: os-release plus the status
// file is everything this scan collects (the Bitnami passes find nothing), so
// a budget of exactly that total must pass and one byte less must not. A
// counter that also charged bytes the tar reader skipped past, or charged a
// file twice, fails the first row; a counter never charged fails the others.
func TestRun_ScanOverThePerScanLimitExits2(t *testing.T) {
	dbPath := d112DB(t)
	target := d112DebianImage(t, nil)
	status := int64(len(d112Status(100)))
	total := status + int64(len(osReleaseDebian12))

	t.Run("budget equal to everything read: clean", func(t *testing.T) {
		lowerLimit(t, &source.MaxScanBytes, total)
		out, errOut, code := runD112(t, context.Background(), dbPath, target)
		if code != 0 {
			t.Fatalf("Run = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
	})

	t.Run("one byte under: exit 2 naming the per-scan limit", func(t *testing.T) {
		lowerLimit(t, &source.MaxScanBytes, total-1)
		out, errOut, code := runD112(t, context.Background(), dbPath, target)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		if !strings.Contains(errOut, "image reads exceeded the ") ||
			!strings.Contains(errOut, " per-scan limit (D112) at ") {
			t.Errorf("stderr does not name the per-scan limit:\n%s", errOut)
		}
		if out != "" {
			t.Errorf("an over-budget scan wrote to stdout:\n%s", out)
		}
	})

	// The status file alone is over this budget, so whichever order the layer
	// holds the two files in, the read that crosses it is the status file's.
	t.Run("the error names the read that crossed it", func(t *testing.T) {
		lowerLimit(t, &source.MaxScanBytes, status-1)
		_, errOut, code := runD112(t, context.Background(), dbPath, target)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstderr:\n%s", code, errOut)
		}
		if want := "per-scan limit (D112) at " + dpkgDBPath; !strings.Contains(errOut, want) {
			t.Errorf("stderr does not say %q:\n%s", want, errOut)
		}
	})
}

// paddedSBOM returns a document of exactly size bytes whose one Go component
// the database covers. The padding is whitespace INSIDE the top-level object,
// so a reader that stops at the limit stops mid-value — the shape that makes
// a bare decoder say "unexpected EOF" instead of naming the limit.
func paddedSBOM(t *testing.T, spdx bool, size int) string {
	t.Helper()
	head := `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[` +
		`{"type":"library","name":"x","version":"1.0.0","purl":"pkg:golang/example.com/x@1.0.0"}]`
	if spdx {
		head = `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[` +
			`{"name":"x","SPDXID":"SPDXRef-Package-x","versionInfo":"1.0.0",` +
			`"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",` +
			`"referenceLocator":"pkg:golang/example.com/x@1.0.0"}]}]`
	}
	pad := size - len(head) - 1
	if pad < 0 {
		t.Fatalf("size %d is smaller than the document itself", size)
	}
	return head + strings.Repeat(" ", pad) + "}"
}

// TestRun_SBOMOverThePerFileLimitExits2 holds the decoder bound at Run, for
// both decoders, at the exact boundary: a document of exactly the limit
// decodes, one byte more is refused with the file and the limit named — not
// the "unexpected EOF" a bare LimitReader would leave behind.
func TestRun_SBOMOverThePerFileLimitExits2(t *testing.T) {
	dbPath := d112DB(t)
	const limit = 4 << 10

	for _, format := range []struct {
		name string
		spdx bool
		file string
	}{
		{"CycloneDX", false, "s.cdx.json"},
		{"SPDX", true, "s.spdx.json"},
	} {
		t.Run(format.name, func(t *testing.T) {
			lowerLimit(t, &source.MaxFileBytes, limit)
			dir := t.TempDir()

			at := filepath.Join(dir, "at-limit-"+format.file)
			if err := os.WriteFile(at, []byte(paddedSBOM(t, format.spdx, limit)), 0o600); err != nil {
				t.Fatal(err)
			}
			out, errOut, code := runD112(t, context.Background(), dbPath, at)
			if code != 0 {
				t.Fatalf("Run(exactly the limit) = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			if !strings.Contains(out, "in 1 package(s)") {
				t.Errorf("stdout should report the one component evaluated:\n%s", out)
			}

			over := filepath.Join(dir, "over-limit-"+format.file)
			if err := os.WriteFile(over, []byte(paddedSBOM(t, format.spdx, limit+1)), 0o600); err != nil {
				t.Fatal(err)
			}
			out, errOut, code = runD112(t, context.Background(), dbPath, over)
			if code != 2 {
				t.Fatalf("Run(one byte over) = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			if want := over + " exceeds the 4 KiB per-file limit (D112)"; !strings.Contains(errOut, want) {
				t.Errorf("stderr does not say %q:\n%s", want, errOut)
			}
			if strings.Contains(errOut, "unexpected EOF") {
				t.Errorf("stderr reports the truncation instead of the limit:\n%s", errOut)
			}
			if out != "" {
				t.Errorf("an over-limit SBOM scan wrote to stdout:\n%s", out)
			}
		})
	}
}

// cancelAfterChecks is a real cancellable context that cancels itself on the
// (allowed+1)th call to Err. The layer walk is the only thing on a
// docker-archive scan that consults the context, once per tar entry, so this
// cancels the scan part-way through a layer deterministically — a tiny
// deadline would race the walk instead.
type cancelAfterChecks struct {
	context.Context
	cancel  context.CancelFunc
	allowed int
	calls   int
}

func (c *cancelAfterChecks) Err() error {
	c.calls++
	if c.calls > c.allowed {
		c.cancel()
	}
	return c.Context.Err()
}

// TestRun_CancelledContextStopsTheLayerWalk holds D112's third bound at Run. A
// docker-archive target never reaches the network, so before D112 nothing on
// this path consulted the context at all and a cancelled scan ran to its end.
func TestRun_CancelledContextStopsTheLayerWalk(t *testing.T) {
	dbPath := d112DB(t)
	// Forty files no cataloger wants, so the walk has entries to stop between.
	filler := map[string]string{}
	for i := 0; i < 40; i++ {
		filler[fmt.Sprintf("usr/share/d112/filler-%02d", i)] = "x"
	}
	target := d112DebianImage(t, filler)

	t.Run("a live context: the image scans clean", func(t *testing.T) {
		out, errOut, code := runD112(t, context.Background(), dbPath, target)
		if code != 0 {
			t.Fatalf("Run = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
	})

	t.Run("cancelled before the walk: exit 2 with the context's error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		out, errOut, code := runD112(t, ctx, dbPath, target)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		if !strings.Contains(errOut, "read layer sha256:") || !strings.Contains(errOut, "context canceled") {
			t.Errorf("stderr should name the layer and the cancellation:\n%s", errOut)
		}
		if out != "" {
			t.Errorf("a cancelled scan wrote to stdout:\n%s", out)
		}
	})

	t.Run("cancelled mid-layer: the walk stops at the next entry", func(t *testing.T) {
		parent, cancel := context.WithCancel(context.Background())
		defer cancel()
		ctx := &cancelAfterChecks{Context: parent, cancel: cancel, allowed: 5}
		out, errOut, code := runD112(t, ctx, dbPath, target)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		if !strings.Contains(errOut, "context canceled") {
			t.Errorf("stderr should carry the cancellation:\n%s", errOut)
		}
		// The check that saw the cancellation is the last one made: the walk
		// returned there, rather than reading on to the end of a 42-entry
		// layer and noticing afterwards.
		if ctx.calls != ctx.allowed+1 {
			t.Errorf("context checked %d times, want %d -- the walk kept going after "+
				"it was cancelled", ctx.calls, ctx.allowed+1)
		}
	})
}

// TestCatalogFromImage_EveryReadSiteIsBounded is the per-file bound held at
// each pass catalogFromImage makes, not only the first. Run's own tests put
// the oversized file where the first Files call reads it; a pass further down
// that read without the bound — the Bitnami marker walk, which runs on every
// image scanned — would leave them green.
func TestCatalogFromImage_EveryReadSiteIsBounded(t *testing.T) {
	big := strings.Repeat("x", 5000)
	for _, tc := range []struct {
		name  string
		path  string
		files map[string]string
	}{
		{"dpkg status, through Files", dpkgDBPath,
			map[string]string{osReleasePath: osReleaseDebian12, dpkgDBPath: big}},
		{"distroless status.d, through FilesUnder", dpkgStatusDir + "/libc6",
			map[string]string{osReleasePath: osReleaseDebian12, dpkgStatusDir + "/libc6": big}},
		{"pacman desc, through FilesNamed", pacmanLocalDir + "/bash-5.3.15-1/desc",
			map[string]string{osReleasePath: osReleaseArch, pacmanLocalDir + "/bash-5.3.15-1/desc": big}},
		{"Bitnami marker, through FilesMatching", "opt/bitnami/redis/.spdx-redis.spdx",
			map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkOneRecord,
				"opt/bitnami/redis/.spdx-redis.spdx": big}},
		{"Bitnami legacy file, through the second Files call", bitnamiLegacyPath,
			map[string]string{osReleasePath: osReleaseAlpine319, apkDBPath: apkOneRecord,
				bitnamiLegacyPath: big}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lowerLimit(t, &source.MaxFileBytes, 4<<10)
			img := &source.Image{Layers: []source.Layer{imageLayer(t, "sha256:big", tc.files)}}
			_, _, _, err := catalogFromImage(context.Background(), "test-image", img)
			want := tc.path + " exceeds the 4 KiB per-file limit (D112)"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("err = %v, want it to say %q", err, want)
			}
		})
	}
}

// TestCatalogFromImage_EveryLayerPassHonoursTheContext holds the context at
// every pass catalogFromImage makes. An Arch image takes all five (the
// probe, status.d, pacman, the Bitnami markers, the Bitnami legacy file), and
// the layer's Open cancels the context on its k-th call: a pass that walked
// with the scan's context stops at once, so the layer is opened exactly k
// times. A pass handed context.Background() instead walks to the end, and the
// next pass opens the layer again — or, if it was the last, the scan succeeds.
func TestCatalogFromImage_EveryLayerPassHonoursTheContext(t *testing.T) {
	raw := buildTar(t, map[string]string{
		osReleasePath:                          osReleaseArch,
		pacmanLocalDir + "/bash-5.3.15-1/desc": archDesc("bash", "5.3.15-1", "bash"),
	})
	catalog := func(cancelOnOpen int) (int, error) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		opens := 0
		img := &source.Image{Layers: []source.Layer{{DiffID: "sha256:arch", Open: func() (io.ReadCloser, error) {
			opens++
			if opens == cancelOnOpen {
				cancel()
			}
			return io.NopCloser(bytes.NewReader(raw)), nil
		}}}}
		_, _, _, err := catalogFromImage(ctx, "test-image", img)
		return opens, err
	}

	const passes = 5
	opens, err := catalog(0)
	if err != nil {
		t.Fatalf("uncancelled: %v", err)
	}
	if opens != passes {
		t.Fatalf("an Arch image took %d layer passes, want %d -- if a pass was added or "+
			"removed, this test's premise changed with it", opens, passes)
	}
	for k := 1; k <= passes; k++ {
		opens, err := catalog(k)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancelled at pass %d: err = %v, want context.Canceled", k, err)
			continue
		}
		if opens != k {
			t.Errorf("cancelled at pass %d, but the layer was opened %d times -- pass %d "+
				"walked on with a context other than the scan's", k, opens, k)
		}
	}
}

// servedReader counts the bytes a reader hands out, so a test can see that
// decodeSBOM stopped pulling at the limit rather than reading a large file to
// its end and refusing it afterwards.
type servedReader struct {
	r io.Reader
	n int64
}

func (s *servedReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.n += int64(n)
	return n, err
}

// TestDecodeSBOM_Limit is decodeSBOM on its own: the rows Run cannot reach
// cheaply. The path names a file that does not exist, so the SPDX sniff says
// no and the CycloneDX decoder runs; both decoders are held at Run.
func TestDecodeSBOM_Limit(t *testing.T) {
	const limit = 4 << 10
	lowerLimit(t, &source.MaxFileBytes, limit)
	const path = "not-on-disk.cdx.json"
	const doc = `{"bomFormat":"CycloneDX","components":[]}`

	t.Run("a complete document followed by bytes past the limit is refused", func(t *testing.T) {
		// The decoder finishes its value long before the limit; only the
		// drain sees the rest of the file.
		in := doc + strings.Repeat("\n", limit+1-len(doc))
		_, _, err := decodeSBOM(path, strings.NewReader(in))
		if err == nil || err.Error() != source.FileLimitError(path).Error() {
			t.Errorf("err = %v, want %v", err, source.FileLimitError(path))
		}
	})

	t.Run("the same document padded to exactly the limit decodes", func(t *testing.T) {
		in := doc + strings.Repeat("\n", limit-len(doc))
		if _, _, err := decodeSBOM(path, strings.NewReader(in)); err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("a 1 MiB document is not read past the limit", func(t *testing.T) {
		r := &servedReader{r: strings.NewReader(`{"bomFormat":"CycloneDX","components":[]` +
			strings.Repeat(" ", 1<<20) + `}`)}
		_, _, err := decodeSBOM(path, r)
		if err == nil || err.Error() != source.FileLimitError(path).Error() {
			t.Errorf("err = %v, want %v", err, source.FileLimitError(path))
		}
		if r.n > limit+1 {
			t.Errorf("decodeSBOM pulled %d bytes for a %d-byte limit", r.n, limit)
		}
	})

	t.Run("a malformed document under the limit keeps its own error", func(t *testing.T) {
		_, _, err := decodeSBOM(path, strings.NewReader(`{"bomFormat":`))
		if err == nil || !strings.HasPrefix(err.Error(), "parse "+path+": decode CycloneDX: ") {
			t.Errorf("err = %v, want the decoder's own error wrapped as before D112", err)
		}
	})
}

// TestRun_ExpiredDeadlineIsNamedAsTheFlagsOnlyWhenItIs holds Run's half of
// --timeout: the wording. cmd/assay sets the deadline; Run names it, and must
// name it only when Options.Timeout says the deadline is the flag's — a
// library caller's own deadline expiring is reported as the plain error it
// is, not attributed to a flag nobody passed.
func TestRun_ExpiredDeadlineIsNamedAsTheFlagsOnlyWhenItIs(t *testing.T) {
	dbPath := d112DB(t)
	target := d112DebianImage(t, nil)
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()

	t.Run("Options.Timeout set: named as the flag's, with its value and the cause", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(expired, dbPath, target, Options{Timeout: 5 * time.Minute}, &out, &errOut)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstderr:\n%s", code, errOut.String())
		}
		want := "error: scan did not finish within 5m0s (--timeout): read layer sha256:"
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr does not say %q:\n%s", want, errOut.String())
		}
		if !strings.Contains(errOut.String(), "context deadline exceeded") {
			t.Errorf("stderr dropped the underlying error:\n%s", errOut.String())
		}
		if out.Len() != 0 {
			t.Errorf("a timed-out scan wrote to stdout:\n%s", out.String())
		}
	})

	t.Run("no Options.Timeout: the plain error, no flag named", func(t *testing.T) {
		var out, errOut bytes.Buffer
		code := Run(expired, dbPath, target, Options{}, &out, &errOut)
		if code != 2 {
			t.Fatalf("Run = %d, want 2\nstderr:\n%s", code, errOut.String())
		}
		if strings.Contains(errOut.String(), "--timeout") {
			t.Errorf("stderr names a flag that was not given:\n%s", errOut.String())
		}
		if !strings.Contains(errOut.String(), "error: read layer sha256:") ||
			!strings.Contains(errOut.String(), "context deadline exceeded") {
			t.Errorf("stderr should carry the walk's own error:\n%s", errOut.String())
		}
	})
}

// TestRun_OverLimitFileBesideAReadableInventoryStillExits2 pins the
// fail-closed half of D112 where a partial answer is most tempting: the dpkg
// database reads fine and its packages evaluate clean, and only a Bitnami
// marker is past the limit. Counting that marker as a skipped record — the
// shape a symlinked marker already takes (D99) — would print a verdict over
// the readable half and exit 0. D112 refuses that: the scan exits 2 with no
// report. TestRun_FileOverThePerFileLimitExits2 cannot hold this on its own,
// because there the oversized file IS the inventory, and an image with no
// package evaluated exits 2 whatever the bound does.
func TestRun_OverLimitFileBesideAReadableInventoryStillExits2(t *testing.T) {
	dbPath := d112DB(t)
	tarPath := filepath.Join(t.TempDir(), "image.tar")
	writeImageTar(t, tarPath, map[string]string{
		osReleasePath:                        osReleaseDebian12,
		dpkgDBPath:                           d112Status(10), // ~600 bytes, under the limit
		"opt/bitnami/redis/.spdx-redis.spdx": strings.Repeat("x", 5000),
	})
	lowerLimit(t, &source.MaxFileBytes, 4<<10)

	out, errOut, code := runD112(t, context.Background(), dbPath, "docker-archive:"+tarPath)
	if code != 2 {
		t.Fatalf("Run = %d, want 2 -- an unread file is not a skipped record (D112)\n"+
			"stdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if want := "opt/bitnami/redis/.spdx-redis.spdx exceeds the 4 KiB per-file limit (D112)"; !strings.Contains(errOut, want) {
		t.Errorf("stderr does not say %q:\n%s", want, errOut)
	}
	if out != "" {
		t.Errorf("a scan that could not read part of its image wrote a report:\n%s", out)
	}
}
