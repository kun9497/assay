package source

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// writeZip builds a minimal zip archive from name -> content pairs and writes
// it to path, for classify_test.go's own jar-sniffing fixtures. Never a
// committed binary fixture (CLAUDE.md) — built in-test with archive/zip.
func writeZip(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// The prefixes are the escape hatch from the sniff, so they must win outright
// — including when the sniff would have said something else, which is the only
// situation in which a user reaches for one.
func TestClassify_ExplicitPrefixesOverrideTheContent(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.json")
	if err := os.WriteFile(sbom, []byte(`{"bomFormat":"CycloneDX"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		in       string
		wantKind TargetKind
		wantPath string
	}{
		{"sbom:" + sbom, TargetSBOM, sbom},
		{"dir:" + dir, TargetDirectory, dir},
		// file: on a document the sniff would have called an SBOM. If the
		// prefix did not win, this row would return TargetSBOM.
		{"file:" + sbom, TargetGoBinary, sbom},
		// jar: on that same document. If the prefix did not win, this row
		// would return TargetSBOM too — the sniff never even runs.
		{"jar:" + sbom, TargetJar, sbom},
		// A prefix on a path that does not exist is still that kind. The
		// error the caller then reports is "cannot open", which is true,
		// rather than "not a recognised target", which is not.
		{"dir:/does/not/exist", TargetDirectory, "/does/not/exist"},
		{"file:/does/not/exist", TargetGoBinary, "/does/not/exist"},
		{"sbom:/does/not/exist", TargetSBOM, "/does/not/exist"},
		{"jar:/does/not/exist", TargetJar, "/does/not/exist"},
	} {
		gotKind, gotPath, err := Classify(tt.in)
		if err != nil {
			t.Errorf("Classify(%q): %v", tt.in, err)
			continue
		}
		if gotKind != tt.wantKind {
			t.Errorf("Classify(%q) kind = %v, want %v", tt.in, gotKind, tt.wantKind)
		}
		if gotPath != tt.wantPath {
			t.Errorf("Classify(%q) path = %q, want %q", tt.in, gotPath, tt.wantPath)
		}
	}
}

// Image prefixes keep their prefix, because source.Open re-parses it.
// Stripping one here would send an oci-dir: layout down the registry path.
func TestClassify_ImagePrefixesAreLeftIntact(t *testing.T) {
	for _, in := range []string{"docker-archive:/tmp/x.tar", "oci-dir:/tmp/layout"} {
		kind, path, err := Classify(in)
		if err != nil {
			t.Errorf("Classify(%q): %v", in, err)
			continue
		}
		if kind != TargetImage {
			t.Errorf("Classify(%q) kind = %v, want image", in, kind)
		}
		if path != in {
			t.Errorf("Classify(%q) path = %q, want it unchanged", in, path)
		}
	}
}

// A bare path is decided by content, in a fixed order.
//
// The Go-binary fixture is this test binary itself: os.Executable() is a real
// binary with real build info, so the case cannot pass against a sniff that
// says yes to everything — a hand-written fixture could.
func TestClassify_BarePathsAreSniffed(t *testing.T) {
	dir := t.TempDir()
	sbom := filepath.Join(dir, "s.cdx.json")
	if err := os.WriteFile(sbom,
		[]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	spdxDoc := filepath.Join(dir, "s.spdx.json")
	if err := os.WriteFile(spdxDoc,
		[]byte(`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	// Recognized by name suffix alone (the common case: a real jar always
	// carries META-INF/, but the suffix check is cheap and tried first).
	byName := filepath.Join(dir, "app.jar")
	writeZip(t, byName, map[string]string{"com/example/Main.class": "not real bytecode"})
	// No .jar/.war suffix at all, recognized only by the META-INF/ entry
	// inside it — the fallback the suffix check exists beside.
	byContent := filepath.Join(dir, "app.bin")
	writeZip(t, byContent, map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})

	for _, tt := range []struct {
		name string
		in   string
		want TargetKind
	}{
		{"a Go binary", self, TargetGoBinary},
		{"a CycloneDX document", sbom, TargetSBOM},
		{"an SPDX document", spdxDoc, TargetSBOM},
		{"a directory", dir, TargetDirectory},
		{"a jar recognized by its .jar name", byName, TargetJar},
		{"a jar recognized by its META-INF/ content", byContent, TargetJar},
		// Not a path at all: the pre-existing behaviour, unchanged.
		{"a registry reference", "alpine:3.19", TargetImage},
		{"a registry reference with a port", "registry.example.com:5000/team/app", TargetImage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, gotPath, err := Classify(tt.in)
			if err != nil {
				t.Fatalf("Classify(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Classify(%q) = %v, want %v", tt.in, got, tt.want)
			}
			if gotPath != tt.in {
				t.Errorf("Classify(%q) path = %q, want it unchanged", tt.in, gotPath)
			}
		})
	}
}

// A Go binary must be recognised before the CycloneDX test runs, not after.
// Order is the whole of D22's sniff: a file cannot be both, but a test that
// only ever sees one kind at a time cannot tell whether the order is right.
// This pins it by asserting the binary case specifically — the one that used
// to be classified as an SBOM.
func TestClassify_AGoBinaryIsNotAnSBOM(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Classify(self)
	if err != nil {
		t.Fatal(err)
	}
	if got == TargetSBOM {
		t.Fatal("a Go binary classified as an SBOM - the CycloneDX parser will " +
			"report a malformed document for a file that was never JSON")
	}
	if got != TargetGoBinary {
		t.Errorf("Classify(self) = %v, want go-binary", got)
	}
}

// A file that exists and is none of the three is an error naming all three,
// not a silent fallthrough to whichever branch is last. Falling through to
// SBOM is what happened before D22, and it reported a malformed JSON document
// for a file that was never meant to be one.
func TestClassify_AnUnrecognisedFileIsAnErrorNamingWhatWasTried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mystery.bin")
	if err := os.WriteFile(path, []byte("not a go binary, not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kind, _, err := Classify(path)
	if err == nil {
		t.Fatalf("Classify of an unrecognised file succeeded as %v", kind)
	}
	// The message has to name what was tried AND how to override, because
	// those are the user's two next questions.
	for _, want := range []string{"Go binary", "CycloneDX", "SPDX", "jar", "sbom:", "file:", "dir:", "jar:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q - the user cannot tell what to do next", err, want)
		}
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file", err)
	}
}

// A plain zip — the magic bytes without either signal jar scanning actually
// needs — is none of the four kinds and must reach the same loud error, not
// be misclassified as a component inventory just because it happens to share
// jar's container format.
func TestClassify_APlainZipIsNotAJar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.zip")
	writeZip(t, path, map[string]string{"readme.txt": "not a jar"})

	kind, _, err := Classify(path)
	if err == nil {
		t.Fatalf("Classify(plain zip) = %v, want an error - it names neither "+
			".jar/.war nor META-INF/", kind)
	}
}

// An empty file is a real case — a truncated download, an interrupted build —
// and it is none of the three. It must reach the same loud error rather than
// tripping a length check somewhere and being called an SBOM.
func TestClassify_AnEmptyFileIsUnrecognised(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if kind, _, err := Classify(path); err == nil {
		t.Errorf("Classify(empty file) = %v, want an error", kind)
	}
}

// JSON member order is arbitrary, so a valid CycloneDX document can put
// bomFormat past any fixed prefix. An 880-byte 1.6 document leading with a
// metadata block did exactly that and was rejected as "not a CycloneDX
// document" - a regression against the pre-sniff behaviour, where every
// existing file went to the order-independent parser.
func TestClassify_ACycloneDXDocumentWithALateBomFormat(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "late.cdx.json")
	// Padding pushes bomFormat well past the 512-byte fast path.
	pad := strings.Repeat("x", 900)
	body := `{"metadata":{"tools":[{"vendor":"` + pad + `","name":"syft"}]},` +
		`"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := Classify(p)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != TargetSBOM {
		t.Errorf("Classify = %v, want sbom", got)
	}
}

// The SPDX analogue of the late-bomFormat test above: LooksLikeSPDX needs the
// identical order-independent fallback, since SPDX's own top-level key order
// is exactly as arbitrary as CycloneDX's.
func TestClassify_AnSPDXDocumentWithALateSpdxVersion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "late.spdx.json")
	pad := strings.Repeat("x", 900)
	body := `{"SPDXID":"SPDXRef-DOCUMENT","name":"` + pad + `",` +
		`"spdxVersion":"SPDX-2.3","packages":[]}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, err := Classify(p)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got != TargetSBOM {
		t.Errorf("Classify = %v, want sbom", got)
	}
}

// D112's per-file limit holds the sniff, not only the decode after it. The
// sniff is a read of the target too, and on a bare path it runs before
// decodeSBOM's bound ever does: before this, a document whose marker sat
// behind a padding string longer than the limit was streamed all the way to
// the marker and called an SBOM. Under the bound the marker is never reached,
// and the error says why in the same words an image's file and a decoded
// SBOM get — the exact rendered sentence, path and limit together, because
// "not a CycloneDX document" would be wrong about a file that may well be
// one. scancmd.Run reports it as exit 2, never a scan that kept reading.
//
// The inside-the-limit document is what makes the past-the-limit one mean
// something: the same shape, its marker past the 512-byte fast path but
// inside the limit, still classifies, so the error below comes from the
// limit and not from the fixture.
func TestClassify_AMarkerPastTheFileLimitIsTheLimitsError(t *testing.T) {
	const limit = 4 << 10
	for _, tt := range []struct {
		name string
		doc  func(pad string) string
	}{
		{"CycloneDX", func(pad string) string {
			return `{"metadata":{"tools":[{"vendor":"` + pad + `","name":"syft"}]},` +
				`"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`
		}},
		{"SPDX", func(pad string) string {
			return `{"SPDXID":"SPDXRef-DOCUMENT","name":"` + pad + `",` +
				`"spdxVersion":"SPDX-2.3","packages":[]}`
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lowerLimit(t, &MaxFileBytes, limit)
			dir := t.TempDir()

			inside := filepath.Join(dir, "inside.json")
			if err := os.WriteFile(inside, []byte(tt.doc(strings.Repeat("x", limit/2))), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _, err := Classify(inside); err != nil || got != TargetSBOM {
				t.Fatalf("Classify(marker inside the limit) = %v, %v; want sbom", got, err)
			}

			past := filepath.Join(dir, "past.json")
			if err := os.WriteFile(past, []byte(tt.doc(strings.Repeat("x", 4*limit))), 0o600); err != nil {
				t.Fatal(err)
			}
			got, _, err := Classify(past)
			if err == nil {
				t.Fatalf("Classify(marker past the limit) = %v, want D112's per-file limit error - "+
					"the sniff read past the limit to find the marker", got)
			}
			if want := past + " exceeds the 4 KiB per-file limit (D112)"; err.Error() != want {
				t.Errorf("err = %q, want %q", err, want)
			}
		})
	}

	// The limit's error is for a sniff that REACHED the limit, not for any file
	// longer than it, and not for one shorter than it. Each of these is a file
	// the sniff could tell apart without reaching the limit, so each keeps the
	// sentence naming what was tried — a flag set on size alone, or on any
	// failed sniff, turns one of them red.
	for _, tt := range []struct{ name, body string }{
		{"a small JSON document with no marker", `{"pad":"` + strings.Repeat("x", limit/2) + `","name":"x"}`},
		{"a file past the limit that is not JSON at all", strings.Repeat("q", 4*limit)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lowerLimit(t, &MaxFileBytes, limit)
			p := filepath.Join(t.TempDir(), "mystery.bin")
			if err := os.WriteFile(p, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, _, err := Classify(p)
			if err == nil {
				t.Fatalf("Classify(%s) = %v, want the unrecognised-file error", tt.name, got)
			}
			if want := p + " is a file, but not a Go binary"; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("err = %q, want it to start %q", err, want)
			}
		})
	}
}

// The bound is on what the sniff PULLS, not on what it concludes. A sniff that
// read a whole file and then said no would pass the Classify test above and
// still have buffered the token D112 exists to refuse — json.Decoder holds a
// string token whole — so this counts the bytes served to it. The padding is
// one string 256 times the limit, ahead of the marker.
//
// The exactly-the-limit rows are the other edge, and where hitLimit's +1
// lives. A document decodeSBOM would accept, its marker as near the end as
// JSON lets it sit, is still found, so the bound refuses nothing the decoder
// after it would have read. The same size with no marker is judged on its
// content — no hitLimit, so Classify keeps the old sentence for it — and one
// byte more is the first size that reports the limit.
func TestSniffTopLevelKey_PullsNoMoreThanTheFileLimit(t *testing.T) {
	const limit = 4 << 10
	lowerLimit(t, &MaxFileBytes, limit)
	pad := strings.Repeat("x", 1<<20)

	// sized is a JSON object of exactly size bytes ending in tail.
	sized := func(t *testing.T, size int, tail string) string {
		t.Helper()
		doc := `{"pad":"` + strings.Repeat("x", size-len(`{"pad":"`)-len(`"`)-len(tail)) + `"` + tail
		if len(doc) != size {
			t.Fatalf("fixture is %d bytes, want %d", len(doc), size)
		}
		return doc
	}

	for _, tt := range []struct{ key, doc string }{
		{"bomFormat", `{"metadata":{"tools":[{"vendor":"` + pad + `","name":"syft"}]},` +
			`"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`},
		{"spdxVersion", `{"SPDXID":"SPDXRef-DOCUMENT","name":"` + pad + `",` +
			`"spdxVersion":"SPDX-2.3","packages":[]}`},
	} {
		t.Run(tt.key+" past the limit", func(t *testing.T) {
			var n int64
			r := &countingReadCloser{ReadCloser: io.NopCloser(strings.NewReader(tt.doc)), n: &n}
			found, hitLimit := sniffTopLevelKey(r, tt.key)
			if found {
				t.Errorf("sniff found %q %d bytes into the document, past a %d-byte limit",
					tt.key, strings.Index(tt.doc, `"`+tt.key+`"`), limit)
			}
			if !hitLimit {
				t.Errorf("sniff stopped at the limit without finding %q but did not say so", tt.key)
			}
			if n > limit+1 {
				t.Errorf("sniff pulled %d bytes of a %d-byte document for a %d-byte limit",
					n, len(tt.doc), limit)
			}
		})

		for _, row := range []struct {
			name          string
			size          int
			tail          string
			found, atEdge bool
		}{
			{"marker last in a document of exactly the limit", limit, `,"` + tt.key + `":1}`, true, false},
			{"no marker in a document of exactly the limit", limit, `,"other":1}`, false, false},
			{"no marker in a document one byte over the limit", limit + 1, `,"other":1}`, false, true},
		} {
			t.Run(tt.key+": "+row.name, func(t *testing.T) {
				found, hitLimit := sniffTopLevelKey(strings.NewReader(sized(t, row.size, row.tail)), tt.key)
				if found != row.found || hitLimit != row.atEdge {
					t.Errorf("sniff(%d bytes) = found %v, hitLimit %v; want %v, %v under a %d-byte limit",
						row.size, found, hitLimit, row.found, row.atEdge, limit)
				}
			})
		}
	}
}

// ...but the marker has to be a top-level KEY. A document whose only
// occurrence of the word is a value, or a nested property name - and
// CycloneDX property names come from whatever tool wrote the file - is not an
// SBOM, and calling it one sends a stranger's document to the wrong parser.
func TestClassify_BomFormatMustBeATopLevelKey(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct{ name, body string }{
		{"as a value", `{"note":"bomFormat","x":1}`},
		{"nested one level down", `{"metadata":{"bomFormat":"CycloneDX"}}`},
		{"as a property name inside an array", `{"a":[{"properties":[{"name":"bomFormat"}]}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".json")
			// The padding keeps the fast prefix scan from seeing it, so this
			// exercises the streaming fallback rather than the shortcut.
			body := `{"pad":"` + strings.Repeat("y", 900) + `",` + tt.body[1:]
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _, err := Classify(p); err == nil {
				t.Errorf("Classify(%s) = %v, want an error - the marker is not a top-level key",
					tt.name, got)
			}
		})
	}
}

// A truncated or non-object document must not hang or panic the fallback.
func TestClassify_MalformedJSONIsNotAnSBOM(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct{ name, body string }{
		{"truncated object", `{"pad":"` + strings.Repeat("z", 900) + `","a":`},
		{"a bare array", `[` + strings.Repeat(`"x",`, 300) + `"y"]`},
		{"not json at all", strings.Repeat("q", 900)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".json")
			if err := os.WriteFile(p, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, _, err := Classify(p); err == nil {
				t.Errorf("Classify(%s) = %v, want an error", tt.name, got)
			}
		})
	}
}

// The kind is printed in the scan's own output so a wrong guess is visible
// rather than inferred from a confusing downstream error, which makes these
// names contract.
func TestTargetKindString(t *testing.T) {
	for k, want := range map[TargetKind]string{
		TargetImage:     "image",
		TargetSBOM:      "sbom",
		TargetDirectory: "directory",
		TargetGoBinary:  "go-binary",
		TargetJar:       "jar",
	} {
		if got := k.String(); got != want {
			t.Errorf("TargetKind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
	// A kind from outside the set must be visibly wrong rather than blank:
	// an empty kind in "scanned X as a " reads as a rendering bug, not as an
	// unknown classification.
	if got := TargetKind(99).String(); !strings.Contains(got, "99") {
		t.Errorf("TargetKind(99).String() = %q, want something naming the value", got)
	}
}

// D112's revision, at the classifier: a file whose name does not say .jar is
// sniffed by opening its central directory to look for META-INF/, and that
// open reads every entry header into memory — so the archive's size is checked
// against the per-file limit first, and a file past it is the limit's error,
// not the "not a jar" sentence (which would send the reader after a prefix
// that cannot help: jar: reaches jar.Parse's refusal of the same file).
//
// A .jar-named archive past the limit is still classified as a jar: the name
// settles it without any open, and jar.Parse then refuses it with the same
// error — so the user sees the limit's sentence exactly once whichever way in.
//
// The fixture is padded well past the SBOM sniffs' 512-byte head on purpose.
// A smaller archive is drained by that head read alone, so with the limit one
// byte under its size the SBOM sniff reports the limit too, and a classifier
// that ignored the jar sniff's own verdict would pass here by accident.
func TestClassify_AnArchivePastTheFileLimitIsTheLimitsError(t *testing.T) {
	dir := t.TempDir()
	// writeZip deflates, and a run of one byte deflates to nearly nothing, so
	// the padding is varied enough to keep the archive past 512 bytes.
	var pad strings.Builder
	for i := 0; pad.Len() < 4<<10; i++ {
		pad.WriteString(strconv.Itoa(i * 7919))
	}
	entries := map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n",
		"META-INF/pad.txt":     pad.String(),
	}
	byContent := filepath.Join(dir, "app.bin")
	writeZip(t, byContent, entries)
	byName := filepath.Join(dir, "app.jar")
	writeZip(t, byName, entries)
	info, err := os.Stat(byContent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 2*512 {
		t.Fatalf("fixture is %d bytes, want it well past the SBOM sniffs' 512-byte head", info.Size())
	}

	t.Run("exactly the limit is sniffed", func(t *testing.T) {
		lowerLimit(t, &MaxFileBytes, info.Size())
		if got, _, err := Classify(byContent); err != nil || got != TargetJar {
			t.Fatalf("Classify(archive of exactly the limit) = %v, %v; want jar", got, err)
		}
	})

	t.Run("one byte past the limit is the limit's error", func(t *testing.T) {
		lowerLimit(t, &MaxFileBytes, info.Size()-1)
		got, _, err := Classify(byContent)
		if err == nil {
			t.Fatalf("Classify(archive past the limit) = %v, want D112's per-file limit error", got)
		}
		if want := FileLimitError(byContent).Error(); err.Error() != want {
			t.Errorf("err = %q, want %q", err, want)
		}
	})

	t.Run("a .jar name past the limit is left to jar.Parse", func(t *testing.T) {
		lowerLimit(t, &MaxFileBytes, 1)
		if got, _, err := Classify(byName); err != nil || got != TargetJar {
			t.Errorf("Classify(.jar past the limit) = %v, %v; want jar - the name settles it "+
				"without opening the archive, and jar.Parse refuses it", got, err)
		}
	})

	// Order, not only presence: the size is checked BEFORE zip.NewReader reads
	// the central directory. The rows above use a valid archive, so a check
	// moved to after a successful open still sees it and they stay green. This
	// file has the ZIP magic and no central directory: only a check made first
	// reports the limit; one made after the open never runs, the sniff answers
	// "not a jar", and Classify falls through to its catch-all sentence.
	t.Run("past the limit is refused before the central directory is read", func(t *testing.T) {
		junk := filepath.Join(dir, "junk.bin")
		body := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 4096)...)
		if err := os.WriteFile(junk, body, 0o600); err != nil {
			t.Fatal(err)
		}
		// Within the limit the sniff opens it and finds no jar, which is what
		// makes the row below able to tell the two orders apart.
		if got, _, err := Classify(junk); err == nil || !strings.Contains(err.Error(), "and not a jar") {
			t.Fatalf("Classify(fixture within the limit) = %v, %v; want the catch-all - the fixture "+
				"must have no readable central directory", got, err)
		}

		lowerLimit(t, &MaxFileBytes, int64(len(body))-1)
		_, _, err := Classify(junk)
		if want := FileLimitError(junk).Error(); err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q - the central directory was read before the size was checked", err, want)
		}
	})
}
