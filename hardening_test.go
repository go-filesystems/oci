package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/go-volumes/safeio"
)

// withLimits temporarily lowers the hardening ceilings so a test can trip them
// with small inputs, restoring the originals on cleanup.
func withLimits(t *testing.T, blob, layer, file, member, total int64) {
	t.Helper()
	ob, ol, of, om, ot := maxBlobSize, maxLayerUncompressed, maxFileSize, maxArchiveMember, maxArchiveTotal
	maxBlobSize, maxLayerUncompressed, maxFileSize, maxArchiveMember, maxArchiveTotal = blob, layer, file, member, total
	t.Cleanup(func() {
		maxBlobSize, maxLayerUncompressed, maxFileSize, maxArchiveMember, maxArchiveTotal = ob, ol, of, om, ot
	})
}

// ----- readAllCapped: negative limit + overrun -----

func TestReadAllCappedNegativeLimit(t *testing.T) {
	if _, err := readAllCapped(bytes.NewReader([]byte("x")), -1, "neg"); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("negative limit: want ErrTooLarge, got %v", err)
	}
}

func TestReadAllCappedOverrun(t *testing.T) {
	if _, err := readAllCapped(bytes.NewReader([]byte("0123456789")), 4, "blob"); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("overrun: want ErrTooLarge, got %v", err)
	}
	// Exactly at the limit succeeds.
	got, err := readAllCapped(bytes.NewReader([]byte("0123")), 4, "blob")
	if err != nil || string(got) != "0123" {
		t.Fatalf("at-limit read: %q %v", got, err)
	}
}

func TestReadAllCappedIOError(t *testing.T) {
	// errReader (from coverage_test.go) fails after `fail` bytes.
	if _, err := readAllCapped(&errReader{data: []byte("xxxx"), fail: 1}, 16, "blob"); err == nil {
		t.Fatal("expected io error to propagate")
	}
}

// ----- decompression bomb: tiny descriptor Size, huge expansion -----

// gzipBomb returns a gzip blob whose uncompressed payload is a tar containing a
// single file of n highly-compressible bytes — small on disk, large expanded.
func gzipBomb(tb testing.TB, n int) []byte {
	tb.Helper()
	inner := buildTarRaw(tb, []tentry{
		{name: "bomb", typeflag: tar.TypeReg, mode: 0o644, body: bytes.Repeat([]byte{0}, n)},
	})
	return gzipRaw(tb, inner)
}

// gzipRaw is the testing.TB variant of gzipBytes for fuzz-seed reuse.
func gzipRaw(tb testing.TB, b []byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		tb.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecompressionBombLayerRejected(t *testing.T) {
	// Layer uncompressed budget of 1 KiB; the bomb expands to 1 MiB.
	withLimits(t, 4<<30, 1<<10, 4<<30, 4<<30, 16<<30)
	bomb := gzipBomb(t, 1<<20)
	dir := t.TempDir()
	// Descriptor Size is the *compressed* blob length (small); it must not let
	// the uncompressed expansion through.
	writeLayout(t, dir, []layerSpec{{blob: bomb, mediaType: MediaTypeLayerTarGzip}})
	_, err := OpenLayout(dir)
	if !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("decompression bomb: want ErrTooLarge, got %v", err)
	}
}

func TestPerFileBombRejected(t *testing.T) {
	// File ceiling below the single file's size, layer budget generous.
	withLimits(t, 4<<30, 8<<30, 1<<10, 4<<30, 16<<30)
	layer := buildTar(t, []tentry{
		{name: "big", typeflag: tar.TypeReg, mode: 0o644, body: bytes.Repeat([]byte("A"), 1<<20)},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	if _, err := OpenLayout(dir); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("per-file bomb: want ErrTooLarge, got %v", err)
	}
}

// ----- mutually-referential hardlinks A->B->A -----

// cyclicHardlinkOverlay builds an overlay with two TypeLink nodes pointing at
// each other, the exact A->B->A vector, plus a self-referential C->C.
func cyclicHardlinkOverlay() *overlay {
	o := newOverlay()
	a := &node{name: "a", ftype: FileTypeHardlink, inode: o.alloc(), linkname: "/b"}
	b := &node{name: "b", ftype: FileTypeHardlink, inode: o.alloc(), linkname: "/a"}
	c := &node{name: "c", ftype: FileTypeHardlink, inode: o.alloc(), linkname: "/c"}
	o.root.children["a"] = a
	o.root.children["b"] = b
	o.root.children["c"] = c
	return o
}

func TestHardlinkCycleRejected(t *testing.T) {
	o := cyclicHardlinkOverlay()
	if _, err := o.resolveHardlink(o.root.children["a"]); !errors.Is(err, safeio.ErrCycle) {
		t.Fatalf("A->B->A: want ErrCycle, got %v", err)
	}
	if _, err := o.resolveHardlink(o.root.children["c"]); !errors.Is(err, safeio.ErrCycle) {
		t.Fatalf("C->C self-cycle: want ErrCycle, got %v", err)
	}
}

// TestHardlinkCycleViaFS exercises the cycle through the public FS surface
// (Stat / ReadFile) to prove the host never panics on a malicious image.
func TestHardlinkCycleViaFS(t *testing.T) {
	// Two hardlinks whose targets are each other, built from a real tar layer.
	layer := buildTar(t, []tentry{
		{name: "a", typeflag: tar.TypeLink, mode: 0o644, linkname: "b"},
		{name: "b", typeflag: tar.TypeLink, mode: 0o644, linkname: "a"},
	})
	dir := t.TempDir()
	writeLayout(t, dir, []layerSpec{{blob: layer, mediaType: MediaTypeLayerTar}})
	f, err := OpenLayout(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if _, err := f.ReadFile("/a"); !errors.Is(err, safeio.ErrCycle) {
		t.Fatalf("ReadFile cycle: want ErrCycle, got %v", err)
	}
	if _, err := f.Stat("/a"); !errors.Is(err, safeio.ErrCycle) {
		t.Fatalf("Stat cycle: want ErrCycle, got %v", err)
	}
}

// TestHardlinkDepthLimit forces the LoopGuard branch: a chain longer than
// maxHardlinkDepth with no repeated inode would otherwise pass the VisitSet but
// must still be cut off by the depth bound. We lower the bound for the test.
func TestHardlinkDepthLimit(t *testing.T) {
	old := maxHardlinkDepth
	maxHardlinkDepth = 2
	t.Cleanup(func() { maxHardlinkDepth = old })
	o := newOverlay()
	// /l0 -> /l1 -> /l2 -> /reg ; with bound 2 the guard trips before /reg.
	o.root.children["l0"] = &node{name: "l0", ftype: FileTypeHardlink, inode: o.alloc(), linkname: "/l1"}
	o.root.children["l1"] = &node{name: "l1", ftype: FileTypeHardlink, inode: o.alloc(), linkname: "/l2"}
	o.root.children["l2"] = &node{name: "l2", ftype: FileTypeHardlink, inode: o.alloc(), linkname: "/reg"}
	o.root.children["reg"] = &node{name: "reg", ftype: FileTypeRegular, inode: o.alloc()}
	if _, err := o.resolveHardlink(o.root.children["l0"]); !errors.Is(err, safeio.ErrLoopLimit) {
		t.Fatalf("depth limit: want ErrLoopLimit, got %v", err)
	}
}

// ----- archive member with a huge Size -----

func TestArchiveMemberTooLarge(t *testing.T) {
	withLimits(t, 4<<30, 8<<30, 4<<30, 1<<10, 16<<30)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := bytes.Repeat([]byte("M"), 1<<20)
	_ = tw.WriteHeader(&tar.Header{Name: "blobs/sha256/deadbeef", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	if _, err := tarballFromReader(bytes.NewReader(buf.Bytes())); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("huge archive member: want ErrTooLarge, got %v", err)
	}
}

func TestArchiveTotalBudget(t *testing.T) {
	// Per-member cap generous, total budget small: two members overrun it.
	withLimits(t, 4<<30, 8<<30, 4<<30, 4<<30, 1<<10)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, n int) {
		body := bytes.Repeat([]byte("T"), n)
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
	}
	add("a", 700)
	add("b", 700)
	_ = tw.Close()
	if _, err := tarballFromReader(bytes.NewReader(buf.Bytes())); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("archive total budget: want ErrTooLarge, got %v", err)
	}
}

// ----- sha512-digest layer is now verified (and rejected when wrong) -----

func TestSHA512LayerVerified(t *testing.T) {
	layer := buildTar(t, []tentry{
		{name: "f", typeflag: tar.TypeReg, mode: 0o644, body: []byte("hello")},
	})
	// A correct sha512 digest must verify and open cleanly.
	sum := sha512.Sum512(layer)
	good := "sha512:" + hex.EncodeToString(sum[:])
	if err := verifyDigest(good, layer); err != nil {
		t.Fatalf("correct sha512 layer: %v", err)
	}
	// A wrong sha512 digest is rejected rather than trusted.
	bad := "sha512:" + hex.EncodeToString(make([]byte, 64))
	if err := verifyDigest(bad, layer); err == nil {
		t.Fatal("wrong sha512 digest should be rejected")
	}
}

// ----- raw blob overrun: a source that streams past its descriptor Size -----

// oversizeSource serves a blob longer than the descriptor advertises.
type oversizeSource struct {
	top  descriptor
	data []byte
}

func (s *oversizeSource) topDescriptor() (descriptor, error) { return s.top, nil }
func (s *oversizeSource) Blob(string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.data)), nil
}

func TestRawBlobOverrunRejected(t *testing.T) {
	// Manifest descriptor claims Size=8 but the source streams far more; the
	// readAllCapped cap derived from Size must reject the overrun.
	payload := bytes.Repeat([]byte("x"), 4096)
	src := &oversizeSource{
		top:  descriptor{MediaType: MediaTypeImageManifest, Digest: "unknownalg:00", Size: 8},
		data: payload,
	}
	_, err := OpenSelect(src, Selector{})
	if !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("raw blob overrun: want ErrTooLarge, got %v", err)
	}
}

// ----- fuzz target: malformed OCI tarball must never panic -----

// FuzzOpenTarball feeds arbitrary bytes as a docker-save / OCI archive into the
// full open path. A malformed or malicious archive must always return an error
// (or a usable FS), never panic, OOM, or loop forever. Seeds include the exact
// hardening vectors and run under plain `go test`.
func FuzzOpenTarball(f *testing.F) {
	// Seed 1: a gzip-bomb layer wrapped in a docker-save archive.
	bomb := gzipBomb(f, 1<<16)
	f.Add(seedDockerSave(f, [][]byte{bomb}))
	// Seed 2: mutually-referential hardlinks A->B->A in a layer.
	cyc := buildTarRaw(f, []tentry{
		{name: "a", typeflag: tar.TypeLink, linkname: "b"},
		{name: "b", typeflag: tar.TypeLink, linkname: "a"},
	})
	f.Add(seedDockerSave(f, [][]byte{cyc}))
	// Seed 3: an archive member with a huge declared Size.
	f.Add(seedHugeMember(f))
	// Seed 4: random small junk and the empty input.
	f.Add([]byte("not a tar at all"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, archive []byte) {
		// Keep the fuzzer cheap and deterministic: tiny ceilings so a bomb is
		// caught fast instead of actually allocating.
		withLimits(t, 1<<20, 1<<20, 1<<18, 1<<20, 4<<20)
		src, err := tarballFromReader(bytes.NewReader(archive))
		if err != nil {
			return // graceful rejection
		}
		fsys, err := Open(src)
		if err != nil {
			return // graceful rejection
		}
		// Touch the public surface; none of it may panic on a hostile image.
		_, _ = fsys.ListDir("/")
		_, _ = fsys.Stat("/")
		_, _ = fsys.ReadFile("/a")
		_, _ = fsys.ReadLink("/a")
		_ = fsys.Close()
	})
}

// FuzzApplyLayer feeds arbitrary bytes as a single decompressed tar layer into
// the overlay folder, the innermost untrusted-parsing surface.
func FuzzApplyLayer(f *testing.F) {
	f.Add(buildTarRaw(f, []tentry{{name: "f", typeflag: tar.TypeReg, body: []byte("hi")}}))
	f.Add(buildTarRaw(f, []tentry{
		{name: "a", typeflag: tar.TypeLink, linkname: "b"},
		{name: "b", typeflag: tar.TypeLink, linkname: "a"},
	}))
	f.Add([]byte("junk"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, layer []byte) {
		withLimits(t, 1<<20, 1<<20, 1<<18, 1<<20, 4<<20)
		ov := newOverlay()
		if err := ov.applyLayer(tar.NewReader(io.LimitReader(bytes.NewReader(layer), maxLayerUncompressed+1)), maxLayerUncompressed); err != nil {
			return
		}
		// Resolve every node, following hardlinks, to exercise cycle guards.
		var walk func(n *node)
		walk = func(n *node) {
			if n.ftype == FileTypeHardlink {
				_, _ = ov.resolveHardlink(n)
			}
			for _, c := range n.children {
				walk(c)
			}
		}
		walk(ov.root)
	})
}

// ----- fuzz seed builders (no *testing.T, take testing.TB) -----

func buildTarRaw(tb testing.TB, entries []tentry) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Size: int64(len(e.body)), Linkname: e.linkname}
		_ = tw.WriteHeader(hdr)
		if len(e.body) > 0 {
			_, _ = tw.Write(e.body)
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

func seedDockerSave(tb testing.TB, layers [][]byte) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, body []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
	}
	add("config.json", []byte(`{"architecture":"arm64","os":"linux"}`))
	names := make([]string, 0, len(layers))
	for i, l := range layers {
		n := "layer" + string(rune('0'+i)) + "/layer.tar"
		add(n, l)
		names = append(names, n)
	}
	save := []dockerSaveManifest{{Config: "config.json", Layers: names}}
	sb, _ := json.Marshal(save)
	add("manifest.json", sb)
	_ = tw.Close()
	return buf.Bytes()
}

func seedHugeMember(tb testing.TB) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := bytes.Repeat([]byte("H"), 4096)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	return buf.Bytes()
}
