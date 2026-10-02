package source

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// lowerLimit sets one of D112's limits for the rest of the test. No test in
// this package runs in parallel, so moving a package variable is safe.
func lowerLimit(t *testing.T, limit *int64, v int64) {
	t.Helper()
	prev := *limit
	*limit = v
	t.Cleanup(func() { *limit = prev })
}

// readSite is one of the four places this package copies a file out of a
// layer, driven the way its caller drives it.
type readSite struct {
	name string
	path string // where the fixture puts the file this site reads
	read func(ctx context.Context, img *Image) (map[string]FileFromLayer, error)
}

func readSites() []readSite {
	return []readSite{
		{"Files (walk.go)", "var/lib/dpkg/status",
			func(ctx context.Context, img *Image) (map[string]FileFromLayer, error) {
				return img.Files(ctx, []string{"var/lib/dpkg/status"})
			}},
		{"FilesUnder", "var/lib/dpkg/status.d/libc6",
			func(ctx context.Context, img *Image) (map[string]FileFromLayer, error) {
				m, _, err := img.FilesUnder(ctx, "var/lib/dpkg/status.d")
				return m, err
			}},
		{"FilesNamed", "var/lib/pacman/local/bash-5.3-1/desc",
			func(ctx context.Context, img *Image) (map[string]FileFromLayer, error) {
				m, _, err := img.FilesNamed(ctx, "var/lib/pacman/local", "desc")
				return m, err
			}},
		{"FilesMatching", "opt/bitnami/redis/.spdx-redis.spdx",
			func(ctx context.Context, img *Image) (map[string]FileFromLayer, error) {
				m, _, err := img.FilesMatching(ctx, "opt/bitnami", ".spdx-", ".spdx")
				return m, err
			}},
	}
}

// countingLayer wraps a layer so a test can see how many bytes the walk pulled
// out of its stream. A bound that only checked the length AFTER reading the
// whole entry would hold every assertion about the error and still allocate
// the entry; this is what tells the two apart.
func countingLayer(l Layer, n *int64) Layer {
	open := l.Open
	return Layer{DiffID: l.DiffID, Open: func() (io.ReadCloser, error) {
		rc, err := open()
		if err != nil {
			return nil, err
		}
		return &countingReadCloser{ReadCloser: rc, n: n}, nil
	}}
}

type countingReadCloser struct {
	io.ReadCloser
	n *int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	*c.n += int64(n)
	return n, err
}

// TestReadSites_FileOverTheLimitIsAnError holds the per-file bound at each of
// the four read sites on its own, at the exact boundary: a file of exactly
// the limit is read whole, one byte more is an error naming the path and the
// limit, and the walk stops pulling the entry at limit+1 bytes rather than
// reading a 1 MiB entry to its end and then refusing it.
func TestReadSites_FileOverTheLimitIsAnError(t *testing.T) {
	const limit = 1 << 10
	for _, site := range readSites() {
		t.Run(site.name, func(t *testing.T) {
			lowerLimit(t, &MaxFileBytes, limit)

			at := strings.Repeat("a", limit)
			got, err := site.read(context.Background(),
				imageOf(layerOf(t, "sha256:at", map[string]string{site.path: at})))
			if err != nil {
				t.Fatalf("a file of exactly the limit: %v", err)
			}
			if string(got[site.path].Data) != at {
				t.Errorf("a file of exactly the limit came back %d bytes, want %d",
					len(got[site.path].Data), limit)
			}

			var pulled int64
			big := strings.Repeat("b", 1<<20)
			img := imageOf(countingLayer(layerOf(t, "sha256:over", map[string]string{site.path: big}), &pulled))
			got, err = site.read(context.Background(), img)
			if err == nil {
				t.Fatalf("a 1 MiB file under a 1 KiB limit was read: %d bytes", len(got[site.path].Data))
			}
			want := "read layer sha256:over: " + site.path + " exceeds the 1 KiB per-file limit (D112)"
			if err.Error() != want {
				t.Errorf("err = %q\nwant  %q", err, want)
			}
			// A tar header block and the bytes up to limit+1, never the entry.
			if pulled >= 1<<20 {
				t.Errorf("the walk pulled %d bytes out of the layer for a 1 KiB limit -- "+
					"it read the whole entry before refusing it", pulled)
			}
		})
	}
}

// TestBudget_SpansPassesAndIsPerImage holds the per-scan total where it
// lives. Two passes over one image add up, which is what "per scan" means
// when a scan makes several; a second image starts from zero, which is what
// keeps one scan's total out of the next in a process that runs two.
func TestBudget_SpansPassesAndIsPerImage(t *testing.T) {
	files := map[string]string{
		"var/lib/dpkg/status":         strings.Repeat("s", 600),
		"var/lib/dpkg/status.d/libc6": strings.Repeat("d", 600),
	}
	scan := func(img *Image) error {
		if _, err := img.Files(context.Background(), []string{"var/lib/dpkg/status"}); err != nil {
			return err
		}
		_, _, err := img.FilesUnder(context.Background(), "var/lib/dpkg/status.d")
		return err
	}

	t.Run("exactly the total two passes read: both succeed", func(t *testing.T) {
		lowerLimit(t, &MaxScanBytes, 1200)
		if err := scan(imageOf(layerOf(t, "sha256:one", files))); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("one byte under: the second pass is refused", func(t *testing.T) {
		lowerLimit(t, &MaxScanBytes, 1199)
		err := scan(imageOf(layerOf(t, "sha256:one", files)))
		want := "read layer sha256:one: image reads exceeded the 1199 bytes per-scan limit (D112) " +
			"at var/lib/dpkg/status.d/libc6"
		if err == nil || err.Error() != want {
			t.Errorf("err = %v\nwant  %s", err, want)
		}
	})

	t.Run("a second image does not inherit the first one's total", func(t *testing.T) {
		lowerLimit(t, &MaxScanBytes, 1000)
		for i := 0; i < 2; i++ {
			img := imageOf(layerOf(t, "sha256:one", files))
			if _, err := img.Files(context.Background(), []string{"var/lib/dpkg/status"}); err != nil {
				t.Fatalf("image %d: %v -- the budget carried over from an earlier image", i+1, err)
			}
		}
	})
}

// TestReadSites_HonourTheContext holds the context at each of the four read
// sites on its own. Run's tests reach Files first and stop there, so a site
// further down that walked with context.Background() would leave them green.
func TestReadSites_HonourTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, site := range readSites() {
		t.Run(site.name, func(t *testing.T) {
			_, err := site.read(ctx, imageOf(layerOf(t, "sha256:cancelled", map[string]string{site.path: "x"})))
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err = %v, want context.Canceled", err)
			}
			if !strings.HasPrefix(err.Error(), "read layer sha256:cancelled: ") {
				t.Errorf("err = %q, want it to name the layer the walk was in", err)
			}
		})
	}
}

// cancelAfterChecks is a real cancellable context that cancels itself on the
// (allowed+1)th call to Err, so a test can stop a walk part-way through a
// layer without racing a deadline.
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

// TestReadLayer_StopsAtTheNextEntry is "at the next entry rather than at the
// end of the layer" (D112): cancelled after three entries of a twelve-entry
// layer, the walk makes exactly one more check and returns, and the file it
// was looking for — the last entry — is never reached.
func TestReadLayer_StopsAtTheNextEntry(t *testing.T) {
	var es []entry
	for i := 0; i < 11; i++ {
		es = append(es, entry{name: "usr/share/filler/" + string(rune('a'+i)), body: "x"})
	}
	es = append(es, entry{name: "etc/os-release", body: "ID=alpine\n"})
	img := imageOf(layerOfOrdered(t, "sha256:mid", es...))

	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelAfterChecks{Context: parent, cancel: cancel, allowed: 3}
	got, err := img.Files(ctx, []string{"etc/os-release"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v (got %v), want context.Canceled", err, got)
	}
	if ctx.calls != ctx.allowed+1 {
		t.Errorf("context checked %d times, want %d -- the walk went on past the "+
			"cancellation", ctx.calls, ctx.allowed+1)
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{
		512 << 20: "512 MiB",
		2 << 30:   "2 GiB",
		4 << 10:   "4 KiB",
		1536:      "1536 bytes", // not a whole KiB: shown as it is, never rounded
		1199:      "1199 bytes",
		0:         "0 bytes",
	} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestLimits_DefaultsAreD112s pins the two numbers the decision chose, so a
// change to either is a visible edit to a test as well as to the variable.
func TestLimits_DefaultsAreD112s(t *testing.T) {
	if MaxFileBytes != 512<<20 {
		t.Errorf("MaxFileBytes = %d, want 512 MiB (D112)", MaxFileBytes)
	}
	if MaxScanBytes != 2<<30 {
		t.Errorf("MaxScanBytes = %d, want 2 GiB (D112)", MaxScanBytes)
	}
}
