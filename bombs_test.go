package oci

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-volumes/safeio"
)

// Regression tests for the memory-bomb audit (2026-11-01). Each road that an
// input-declared size or count used to size an allocation (or a loop) is now
// refused BEFORE the memory is spent. The "before" figures in the comments were
// measured with runtime.MemStats.TotalAlloc on the code at v0.3.0.

// totalAlloc returns the cumulative bytes allocated by the process so far.
func totalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// rawTar writes headers (and optional bodies) with the standard tar writer.
func rawTar(tb testing.TB, hdrs []*tar.Header, bodies [][]byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for i, h := range hdrs {
		if err := tw.WriteHeader(h); err != nil {
			tb.Fatalf("WriteHeader %s: %v", h.Name, err)
		}
		if bodies != nil && len(bodies[i]) > 0 {
			if _, err := tw.Write(bodies[i]); err != nil {
				tb.Fatalf("Write %s: %v", h.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

// sparseTar returns a tar with one PAX-sparse (GNU 1.0) regular file whose real
// size is realSize and whose stored data is empty (one 512-byte map block).
func sparseTar(tb testing.TB, name string, realSize int64) []byte {
	tb.Helper()
	// Hand-built: archive/tar's Writer cannot emit GNU sparse records.
	rec := func(k, v string) string {
		body := " " + k + "=" + v + "\n"
		n := len(body) + 1
		for len(fmt.Sprint(n))+len(body) != n {
			n = len(fmt.Sprint(n)) + len(body)
		}
		return fmt.Sprint(n) + body
	}
	pax := rec("GNU.sparse.major", "1") + rec("GNU.sparse.minor", "0") +
		rec("GNU.sparse.name", name) + rec("GNU.sparse.realsize", fmt.Sprint(realSize))
	block := func(n string, flag byte, size int) []byte {
		b := make([]byte, 512)
		copy(b[0:], n)
		copy(b[100:], "0000644\x00")
		copy(b[108:], "0000000\x00")
		copy(b[116:], "0000000\x00")
		copy(b[124:], fmt.Sprintf("%011o\x00", size))
		copy(b[136:], "00000000000\x00")
		copy(b[148:], "        ")
		b[156] = flag
		copy(b[257:], "ustar\x0000")
		sum := 0
		for _, c := range b {
			sum += int(c)
		}
		copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
		return b
	}
	pad := func(s string) []byte {
		b := make([]byte, (len(s)+511)/512*512)
		copy(b, s)
		return b
	}
	var out []byte
	out = append(out, block("PaxHeaders/x", 'x', len(pax))...)
	out = append(out, pad(pax)...)
	out = append(out, block("GNUSparseFile.0/"+name, '0', 512)...)
	out = append(out, pad("0\n")...)
	return append(out, make([]byte, 1024)...)
}

// openLayers opens a layout holding layers under lim and reports the error and
// the bytes allocated by the open.
func openLayers(t *testing.T, layers []layerSpec, lim Limits) (*FS, error, uint64) {
	t.Helper()
	dir := t.TempDir()
	writeLayout(t, dir, layers)
	before := totalAlloc()
	f, err := OpenSelectLimits(OCILayout(dir), Selector{}, lim)
	return f, err, totalAlloc() - before
}

func wantTooLarge(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("%s: want ErrTooLarge, got %v", what, err)
	}
}

func gzLayer(t *testing.T, raw []byte) layerSpec {
	t.Helper()
	return layerSpec{blob: gzipBytes(t, raw), mediaType: MediaTypeLayerTarGzip}
}

func regFiles(n int, prefix string) []*tar.Header {
	hdrs := make([]*tar.Header, n)
	for i := range hdrs {
		hdrs[i] = &tar.Header{Name: fmt.Sprintf("%s%d", prefix, i), Typeflag: tar.TypeReg, Mode: 0o644}
	}
	return hdrs
}

// ----- the limits struct itself -----

func TestLimitsResolve(t *testing.T) {
	if got, want := (Limits{}).resolve(), DefaultLimits(); got != want {
		t.Fatalf("zero Limits did not resolve to the defaults:\n got %+v\nwant %+v", got, want)
	}
	all := Limits{
		MaxBlob: 1, MaxManifest: 2, MaxLayerUncompressed: 3, MaxImageUncompressed: 4, MaxFile: 5,
		MaxLayerStream: 6, MaxSparseHoles: 7, MaxMetadata: 8, MaxEntries: 9, MaxPathLen: 10,
		MaxLayers: 11, MaxIndexDepth: 12, MaxArchiveMember: 13, MaxArchiveTotal: 14,
	}
	if got := all.resolve(); got != all {
		t.Fatalf("explicit Limits were altered: %+v", got)
	}
}

// ----- entry count -----

func TestEntryCountBound(t *testing.T) {
	// The root is node #1, so a layer of k files holds k+1 nodes.
	for _, tc := range []struct {
		files, max int
		ok         bool
	}{{10, 11, true}, {11, 11, false}} {
		layer := gzLayer(t, rawTar(t, regFiles(tc.files, "f"), nil))
		f, err, alloc := openLayers(t, []layerSpec{layer}, Limits{MaxEntries: int64(tc.max)})
		if tc.ok {
			if err != nil {
				t.Fatalf("%d files under MaxEntries=%d: %v", tc.files, tc.max, err)
			}
			f.Close()
			continue
		}
		wantTooLarge(t, "one entry over the bound", err)
		if alloc > 1<<20 {
			t.Fatalf("refusal allocated %d bytes", alloc)
		}
	}
}

// Implied directories count too: one path of 1000 one-letter components creates
// 1000 nodes from a single header.
func TestEntryCountCountsImpliedDirs(t *testing.T) {
	name := strings.Repeat("a/", 1000) + "z"
	layer := gzLayer(t, rawTar(t, []*tar.Header{{Name: name, Typeflag: tar.TypeReg}}, nil))
	_, err, _ := openLayers(t, []layerSpec{layer}, Limits{MaxEntries: 500})
	wantTooLarge(t, "implied directories", err)
}

// ----- path length, name bytes -----

// Before: a 2093-byte gzip layer holding one 1 MiB PAX path of nested
// one-letter directories allocated 191 MB (about 90 000 times its size).
func TestLongPathRefused(t *testing.T) {
	name := strings.Repeat("a/", 500000) + "z"
	layer := gzLayer(t, rawTar(t, []*tar.Header{{Name: name, Typeflag: tar.TypeReg, Format: tar.FormatPAX}}, nil))
	_, err, alloc := openLayers(t, []layerSpec{layer}, Limits{})
	wantTooLarge(t, "1 MiB path", err)
	if alloc > 8<<20 {
		t.Fatalf("1 MiB path allocated %d bytes (was 191 MB)", alloc)
	}
}

func TestPathLenBound(t *testing.T) {
	const max = 4096
	at := strings.Repeat("a/", 2047) + "bb" // exactly 4096 bytes
	over := at + "c"
	if len(at) != max || len(over) != max+1 {
		t.Fatalf("test setup: %d %d", len(at), len(over))
	}
	layer := func(n string) layerSpec {
		return gzLayer(t, rawTar(t, []*tar.Header{{Name: n, Typeflag: tar.TypeReg, Format: tar.FormatPAX}}, nil))
	}
	f, err, _ := openLayers(t, []layerSpec{layer(at)}, Limits{})
	if err != nil {
		t.Fatalf("path of exactly %d bytes: %v", max, err)
	}
	f.Close()
	_, err, _ = openLayers(t, []layerSpec{layer(over)}, Limits{})
	wantTooLarge(t, "path one byte over", err)
}

// Before: 50 symlinks with 1 MiB targets, 130 KB of gzip, allocated 164 MB and
// kept 50 MiB in the tree.
func TestSymlinkTargetRefused(t *testing.T) {
	target := strings.Repeat("t", 1<<20-1024)
	hdrs := make([]*tar.Header, 50)
	for i := range hdrs {
		hdrs[i] = &tar.Header{Name: fmt.Sprintf("l%d", i), Typeflag: tar.TypeSymlink, Linkname: target, Format: tar.FormatPAX}
	}
	_, err, alloc := openLayers(t, []layerSpec{gzLayer(t, rawTar(t, hdrs, nil))}, Limits{})
	wantTooLarge(t, "long symlink targets", err)
	if alloc > 8<<20 {
		t.Fatalf("symlink targets allocated %d bytes (was 164 MB)", alloc)
	}
}

func TestMetadataBound(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{{"abcde", true}, {"abcdef", false}} {
		layer := gzLayer(t, rawTar(t, []*tar.Header{{Name: tc.name, Typeflag: tar.TypeReg}}, nil))
		f, err, _ := openLayers(t, []layerSpec{layer}, Limits{MaxMetadata: 5})
		if tc.ok {
			if err != nil {
				t.Fatalf("name of 5 bytes under MaxMetadata=5: %v", err)
			}
			f.Close()
		} else {
			wantTooLarge(t, "name of 6 bytes", err)
		}
	}
	// Link targets count as well, and across layers.
	l1 := gzLayer(t, rawTar(t, []*tar.Header{{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "0123456789"}}, nil))
	l2 := gzLayer(t, rawTar(t, []*tar.Header{{Name: "b", Typeflag: tar.TypeSymlink, Linkname: "0123456789"}}, nil))
	_, err, _ := openLayers(t, []layerSpec{l1, l2}, Limits{MaxMetadata: 21})
	wantTooLarge(t, "metadata over two layers", err)
	f, err, _ := openLayers(t, []layerSpec{l1, l2}, Limits{MaxMetadata: 22})
	if err != nil {
		t.Fatalf("22 bytes of names and targets under MaxMetadata=22: %v", err)
	}
	f.Close()
}

// ----- sparse members -----

// Before: 199 bytes of gzip declaring a 1 GiB sparse file allocated 2.19 GB
// (1 GiB live); a 3 KiB archive did the same through tarballFromReader.
func TestSparseLayerRefused(t *testing.T) {
	layer := gzLayer(t, sparseTar(t, "big", 1<<30))
	_, err, alloc := openLayers(t, []layerSpec{layer}, Limits{})
	wantTooLarge(t, "1 GiB sparse member", err)
	if alloc > 512<<20 {
		t.Fatalf("sparse member allocated %d bytes (was 2.19 GB)", alloc)
	}
	_, err, alloc = openLayers(t, []layerSpec{layer}, Limits{MaxSparseHoles: 1 << 20})
	wantTooLarge(t, "1 GiB sparse member, 1 MiB holes", err)
	if alloc > 8<<20 {
		t.Fatalf("sparse member allocated %d bytes with a 1 MiB hole budget", alloc)
	}
}

func TestSparseHoleBound(t *testing.T) {
	const holes = 1 << 20
	// Physical position when the data is read: PAX header + PAX body + file
	// header + map block = 2048 bytes. A real size of holes passes, holes+4096
	// (more than 2048 over the budget) is refused.
	f, err, _ := openLayers(t, []layerSpec{gzLayer(t, sparseTar(t, "s", holes))}, Limits{MaxSparseHoles: holes})
	if err != nil {
		t.Fatalf("sparse member at the bound: %v", err)
	}
	if b, rerr := f.ReadFile("/s"); rerr != nil || len(b) != holes {
		t.Fatalf("sparse member read back %d bytes, err %v", len(b), rerr)
	}
	f.Close()
	_, err, _ = openLayers(t, []layerSpec{gzLayer(t, sparseTar(t, "s", holes+4096))}, Limits{MaxSparseHoles: holes})
	wantTooLarge(t, "sparse member over the bound", err)
}

func TestSparseArchiveRefused(t *testing.T) {
	raw := sparseTar(t, "blobs/sha256/aa", 1<<30)
	before := totalAlloc()
	_, err := tarballFromReaderLimits(bytes.NewReader(raw), Limits{MaxSparseHoles: 1 << 20})
	wantTooLarge(t, "sparse archive member", err)
	if alloc := totalAlloc() - before; alloc > 8<<20 {
		t.Fatalf("sparse archive member allocated %d bytes (was 2.19 GB)", alloc)
	}
}

// A dense file never trips the hole guard, however large relative to the
// stream: logical bytes never exceed the physical position.
func TestDenseFileNotAHole(t *testing.T) {
	layer := gzLayer(t, rawTar(t, []*tar.Header{{Name: "d", Typeflag: tar.TypeReg, Size: 1 << 16}}, [][]byte{make([]byte, 1<<16)}))
	f, err, _ := openLayers(t, []layerSpec{layer}, Limits{MaxSparseHoles: 1})
	if err != nil {
		t.Fatalf("dense file with a 1-byte hole budget: %v", err)
	}
	f.Close()
}

// ----- decompressed stream -----

// Before: an entry of an unknown typeflag is skipped by reading its body; a
// 256 MiB body was consumed without error (and a gzip layer can stand for 4 TB).
func TestSkippedEntryStreamBound(t *testing.T) {
	var consumed int64
	head := rawTarHeaderOnly(t, &tar.Header{Name: "skip", Typeflag: 'Z', Size: 1 << 40})
	ov := newOverlayLimits(Limits{MaxLayerStream: 1 << 20})
	err := ov.applyLayer(&tallyReader{r: io.MultiReader(bytes.NewReader(head), zeroReader{}), n: &consumed}, 1<<30)
	wantTooLarge(t, "skipped entry body", err)
	if consumed > 2<<20 {
		t.Fatalf("consumed %d bytes of a 1 MiB stream budget", consumed)
	}
}

type tallyReader struct {
	r io.Reader
	n *int64
}

func (c *tallyReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	*c.n += int64(k)
	return k, err
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func rawTarHeaderOnly(tb testing.TB, h *tar.Header) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(h); err != nil {
		tb.Fatal(err)
	}
	_ = tw.Flush() // reports the missing body of the header; the header is written
	return buf.Bytes()
}

func TestLayerStreamExactBound(t *testing.T) {
	raw := rawTar(t, []*tar.Header{{Name: "f", Typeflag: tar.TypeReg, Size: 3}}, [][]byte{[]byte("abc")})
	n := int64(len(raw))
	if err := newOverlayLimits(Limits{MaxLayerStream: n}).applyLayer(bytes.NewReader(raw), 1<<30); err != nil {
		t.Fatalf("stream of exactly %d bytes under MaxLayerStream=%d: %v", n, n, err)
	}
	wantTooLarge(t, "stream one byte over", newOverlayLimits(Limits{MaxLayerStream: n - 1}).applyLayer(bytes.NewReader(raw), 1<<30))
}

// The overrun byte is withheld and every later read fails too, so a caller that
// fills its buffer cannot swallow the error.
func TestCountingReaderWithholdsOverrun(t *testing.T) {
	cr := &countingReader{r: bytes.NewReader(make([]byte, 100)), max: 10}
	buf := make([]byte, 64)
	n, err := io.ReadFull(cr, buf)
	if n != 10 {
		t.Fatalf("delivered %d bytes of a 10-byte budget", n)
	}
	wantTooLarge(t, "first overrun", err)
	if _, err := cr.Read(buf); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("read after the overrun: %v", err)
	}
	neg := &countingReader{r: bytes.NewReader([]byte("x")), max: -1}
	if _, err := neg.Read(buf); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("negative budget: %v", err)
	}
}

// ----- image-wide and layer counts -----

func TestImageUncompressedBound(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 600)
	mk := func(name string) layerSpec {
		return layerSpec{blob: rawTar(t, []*tar.Header{{Name: name, Typeflag: tar.TypeReg, Size: 600}}, [][]byte{body}), mediaType: MediaTypeLayerTar}
	}
	layers := []layerSpec{mk("a"), mk("b")}
	// Per-layer budget generous: only the image-wide budget can refuse.
	f, err, _ := openLayers(t, layers, Limits{MaxImageUncompressed: 1200})
	if err != nil {
		t.Fatalf("1200 bytes under MaxImageUncompressed=1200: %v", err)
	}
	f.Close()
	_, err, _ = openLayers(t, layers, Limits{MaxImageUncompressed: 1199})
	wantTooLarge(t, "image-wide budget", err)
}

func TestLayerCountBound(t *testing.T) {
	one := layerSpec{blob: rawTar(t, regFiles(1, "f"), nil), mediaType: MediaTypeLayerTar}
	three := []layerSpec{one, one, one}
	f, err, _ := openLayers(t, three, Limits{MaxLayers: 3})
	if err != nil {
		t.Fatalf("3 layers under MaxLayers=3: %v", err)
	}
	f.Close()
	_, err, _ = openLayers(t, three, Limits{MaxLayers: 2})
	wantTooLarge(t, "3 layers over MaxLayers=2", err)
}

// A docker-save manifest.json listing the same layer many times used to cost a
// SHA-256 of the whole member and a descriptor per name.
func TestSynthManifestLayerCount(t *testing.T) {
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("hi")}})
	p := filepath.Join(t.TempDir(), "img.tar")
	if err := os.WriteFile(p, writeDockerSaveTarball(t, [][]byte{layer, layer}), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := TarballLimits(p, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	// Two distinct names for the same member: the second reuses the first
	// digest (hashed once).
	f, err := OpenSelectLimits(src, Selector{}, Limits{MaxLayers: 2})
	if err != nil {
		t.Fatalf("2 layers under MaxLayers=2: %v", err)
	}
	f.Close()
	src, _ = TarballLimits(p, Limits{})
	_, err = OpenSelectLimits(src, Selector{}, Limits{MaxLayers: 1})
	wantTooLarge(t, "manifest.json with 2 layers over MaxLayers=1", err)
}

// ----- manifests, index.json, index nesting -----

// Before: index.json was read with an unbounded os.ReadFile and manifests up to
// 4 GiB (maxBlobSize).
func TestIndexJSONBound(t *testing.T) {
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: rawTar(t, regFiles(1, "f"), nil), mediaType: MediaTypeLayerTar}})
	idx, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxManifest: int64(len(idx)) - 1})
	wantTooLarge(t, "index.json one byte over", err)

	// A manifest (the blob index.json points to) is bounded by the same budget.
	// The largest document of this layout is the manifest or the index.json.
	f, err := OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxManifest: 4096})
	if err != nil {
		t.Fatalf("small documents under MaxManifest=4096: %v", err)
	}
	f.Close()

	// 8 MiB of junk in index.json: refused after reading MaxManifest+1 bytes.
	big := bytes.Repeat([]byte(" "), 8<<20)
	if err := os.WriteFile(filepath.Join(dir, "index.json"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	before := totalAlloc()
	_, err = OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxManifest: 1 << 20})
	wantTooLarge(t, "8 MiB index.json", err)
	if alloc := totalAlloc() - before; alloc > 8<<20 {
		t.Fatalf("8 MiB index.json allocated %d bytes", alloc)
	}
}

func TestManifestBlobBound(t *testing.T) {
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: rawTar(t, regFiles(1, "f"), nil), mediaType: MediaTypeLayerTar}})
	idx, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Find the manifest blob's size from index.json, then bound just below it.
	var ix index
	if err := json.Unmarshal(idx, &ix); err != nil {
		t.Fatal(err)
	}
	msize := ix.Manifests[0].Size
	if msize <= int64(len(idx)) {
		t.Skipf("manifest (%d) not larger than index.json (%d)", msize, len(idx))
	}
	// With the descriptor Size honest, the descriptor cap is the smaller bound;
	// MaxManifest just below the manifest's size refuses at the manifest.
	_, err = OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxManifest: msize - 1})
	wantTooLarge(t, "manifest one byte over", err)
	f, err := OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxManifest: msize})
	if err != nil {
		t.Fatalf("manifest of exactly %d bytes: %v", msize, err)
	}
	f.Close()
}

func TestDockerSaveManifestBound(t *testing.T) {
	layer := buildTar(t, []tentry{{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("hi")}})
	p := filepath.Join(t.TempDir(), "img.tar")
	if err := os.WriteFile(p, writeDockerSaveTarball(t, [][]byte{layer}), 0o644); err != nil {
		t.Fatal(err)
	}
	src, err := Tarball(p)
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSelectLimits(src, Selector{}, Limits{MaxManifest: 10})
	wantTooLarge(t, "docker-save manifest.json over MaxManifest", err)
}

// writeNestedLayout writes a layout whose index.json points through `levels`
// nested image indexes to a manifest.
func writeNestedLayout(t *testing.T, dir string, levels int) {
	t.Helper()
	writeLayout(t, dir, []layerSpec{{blob: rawTar(t, regFiles(1, "f"), nil), mediaType: MediaTypeLayerTar}})
	raw, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ix index
	if err := json.Unmarshal(raw, &ix); err != nil {
		t.Fatal(err)
	}
	cur := ix.Manifests[0]
	for i := 0; i < levels; i++ {
		b, _ := json.Marshal(index{SchemaVersion: 2, MediaType: MediaTypeImageIndex, Manifests: []descriptor{cur}})
		d := digestOf(b)
		_, hx, _ := parseDigest(d)
		if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", hx), b, 0o644); err != nil {
			t.Fatal(err)
		}
		cur = descriptor{MediaType: MediaTypeImageIndex, Digest: d, Size: int64(len(b))}
	}
	b, _ := json.Marshal(index{SchemaVersion: 2, MediaType: MediaTypeImageIndex, Manifests: []descriptor{cur}})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIndexDepthBound(t *testing.T) {
	// index.json is synthesised as depth 0; with 2 nested indexes the manifest
	// sits at depth 3.
	dir := t.TempDir()
	writeNestedLayout(t, dir, 2)
	f, err := OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxIndexDepth: 3})
	if err != nil {
		t.Fatalf("manifest at depth 3 under MaxIndexDepth=3: %v", err)
	}
	f.Close()
	_, err = OpenSelectLimits(OCILayout(dir), Selector{}, Limits{MaxIndexDepth: 2})
	wantTooLarge(t, "manifest at depth 3 over MaxIndexDepth=2", err)

	// The default depth holds a real nesting (3 levels) and refuses a deep chain.
	deep := t.TempDir()
	writeNestedLayout(t, deep, 40)
	_, err = Open(OCILayout(deep))
	wantTooLarge(t, "40 nested indexes", err)
}

// ----- digest path traversal -----

func TestParseDigestRejectsPathAlgorithm(t *testing.T) {
	for _, d := range []string{"../../etc:00", "a/b:00", "..:00", ".:00", `a\b:00`, "UPPER:00", "a b:00"} {
		if _, _, err := parseDigest(d); err == nil {
			t.Errorf("parseDigest(%q) accepted a hostile algorithm", d)
		}
	}
	for _, d := range []string{"sha256:00", "sha512:ab", "blake3.x-y_z+w:00"} {
		if _, _, err := parseDigest(d); err != nil {
			t.Errorf("parseDigest(%q): %v", d, err)
		}
	}
	// The layout never opens a file outside blobs/.
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "00"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc, err := OCILayout(filepath.Join(dir, "layout")).Blob("../../outside:00"); err == nil {
		rc.Close()
		t.Fatal("OCILayout.Blob followed a ../ algorithm out of the layout")
	}
}

// ----- archive members -----

func TestArchiveMemberCountAndNames(t *testing.T) {
	raw := rawTar(t, regFiles(3, "m"), nil)
	if _, err := tarballFromReaderLimits(bytes.NewReader(raw), Limits{MaxEntries: 3}); err != nil {
		t.Fatalf("3 members under MaxEntries=3: %v", err)
	}
	_, err := tarballFromReaderLimits(bytes.NewReader(raw), Limits{MaxEntries: 2})
	wantTooLarge(t, "3 members over MaxEntries=2", err)
	// Names: "m0","m1","m2" are 6 bytes together.
	if _, err := tarballFromReaderLimits(bytes.NewReader(raw), Limits{MaxMetadata: 6}); err != nil {
		t.Fatalf("6 name bytes under MaxMetadata=6: %v", err)
	}
	_, err = tarballFromReaderLimits(bytes.NewReader(raw), Limits{MaxMetadata: 5})
	wantTooLarge(t, "6 name bytes over MaxMetadata=5", err)
	// One long name.
	long := rawTar(t, []*tar.Header{{Name: strings.Repeat("n", 5000), Typeflag: tar.TypeReg}}, nil)
	_, err = tarballFromReaderLimits(bytes.NewReader(long), Limits{})
	wantTooLarge(t, "5000-byte member name", err)
}

// ----- opaque whiteouts -----

// Before: N files in a directory plus N opaque markers rescanned the directory
// for each marker and built a new map each time (O(N^2) time and garbage):
// 5000 of each took 6.1 s and about 1 GB of allocation. The allocation is the
// platform-independent witness, so the test asserts it rather than a duration.
func TestRepeatedOpaqueMarkersAreCheap(t *testing.T) {
	const n = 5000
	hdrs := []*tar.Header{{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755}}
	for i := 0; i < n; i++ {
		hdrs = append(hdrs, &tar.Header{Name: fmt.Sprintf("d/f%d", i), Typeflag: tar.TypeReg})
	}
	for i := 0; i < n; i++ {
		hdrs = append(hdrs, &tar.Header{Name: "d/.wh..wh..opq", Typeflag: tar.TypeReg})
	}
	lower := layerSpec{blob: rawTar(t, []*tar.Header{{Name: "d/", Typeflag: tar.TypeDir, Mode: 0o755}, {Name: "d/old", Typeflag: tar.TypeReg}}, nil), mediaType: MediaTypeLayerTar}
	upper := layerSpec{blob: rawTar(t, hdrs, nil), mediaType: MediaTypeLayerTar}
	f, err, alloc := openLayers(t, []layerSpec{lower, upper}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if alloc > 256<<20 {
		t.Fatalf("%d opaque markers allocated %d bytes", n, alloc)
	}
	if _, err := f.Stat("/d/old"); err == nil {
		t.Fatal("opaque marker did not clear the lower layer")
	}
	if _, err := f.Stat("/d/f0"); err != nil {
		t.Fatalf("opaque marker dropped a same-layer file: %v", err)
	}
}

// The per-layer flags are reset between layers, by the touched list rather than
// a tree walk: a later layer sees a clean tree.
func TestLayerFlagsResetBetweenLayers(t *testing.T) {
	l1 := layerSpec{blob: rawTar(t, []*tar.Header{{Name: "d/", Typeflag: tar.TypeDir}, {Name: "d/a", Typeflag: tar.TypeReg}, {Name: "d/.wh..wh..opq", Typeflag: tar.TypeReg}}, nil), mediaType: MediaTypeLayerTar}
	// Second layer re-applies an opaque marker on the same directory: it must
	// clear d/a (the first layer's file is no longer "touched in this layer").
	l2 := layerSpec{blob: rawTar(t, []*tar.Header{{Name: "d/.wh..wh..opq", Typeflag: tar.TypeReg}, {Name: "d/b", Typeflag: tar.TypeReg}}, nil), mediaType: MediaTypeLayerTar}
	f, err, _ := openLayers(t, []layerSpec{l1, l2}, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Stat("/d/a"); err == nil {
		t.Fatal("second layer's opaque marker did not clear the first layer's file (flags not reset)")
	}
	if _, err := f.Stat("/d/b"); err != nil {
		t.Fatalf("second layer's file missing: %v", err)
	}
}
