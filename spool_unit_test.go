package oci

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/go-volumes/safeio"
)

func TestSpoolFileIsCreatedOnce(t *testing.T) {
	s := newSpool(t.TempDir())
	defer s.close()
	a, err := s.file()
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.file()
	if err != nil || a != b {
		t.Fatalf("second file() = %v, %v; want the same file", b, err)
	}
	if _, err := newSpool(t.TempDir() + "/absent").file(); err == nil {
		t.Fatal("file() succeeded in a missing directory")
	}
}

func TestSpoolCopyIn(t *testing.T) {
	s := newSpool(t.TempDir())
	defer s.close()
	if _, _, err := s.copyIn(bytes.NewReader([]byte("x")), -1, "neg", nil); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("negative limit: %v", err)
	}
	if _, _, err := s.copyIn(bytes.NewReader([]byte("0123456789")), 5, "over", nil); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("overrun: %v", err)
	}
	off, n, err := s.copyIn(bytes.NewReader([]byte("0123456789")), 10, "exact", nil)
	if err != nil || n != 10 || off != 0 {
		t.Fatalf("exact: off=%d n=%d err=%v", off, n, err)
	}
	off, n, err = s.copyIn(bytes.NewReader([]byte("ab")), 10, "second", nil)
	if err != nil || off != 10 || n != 2 {
		t.Fatalf("second: off=%d n=%d err=%v", off, n, err)
	}
	got, _ := io.ReadAll(s.section(10, 2))
	if string(got) != "ab" {
		t.Fatalf("section = %q", got)
	}
	_, _, err = newSpool(t.TempDir()+"/absent").copyIn(bytes.NewReader([]byte("x")), 1, "dir", nil)
	if err == nil || !strings.Contains(err.Error(), "creating spool file") {
		t.Fatalf("copyIn in a missing directory: %v", err)
	}
}

func TestMemBudget(t *testing.T) {
	b := &memBudget{threshold: -1, max: -1}
	if !b.inMemory(0) || b.inMemory(1) {
		t.Fatal("negative budget: empty body must stay in memory, any other must not")
	}
	b = &memBudget{threshold: 10, max: 15}
	if !b.inMemory(10) || b.inMemory(11) || b.inMemory(6) || !b.inMemory(5) || b.inMemory(1) {
		t.Fatal("budget accounting is wrong")
	}
}

func TestStageBlob(t *testing.T) {
	data := []byte("some layer bytes")
	dg := sha256Digest(data)
	dir := t.TempDir()
	read := func(r io.Reader) string { b, _ := io.ReadAll(r); return string(b) }

	for _, declared := range []int64{int64(len(data)), 0} { // memory path, spool path
		r, cleanup, err := stageBlob(bytes.NewReader(data), 1<<20, declared, 1<<10, dir, dg, "blob")
		if err != nil || read(r) != string(data) {
			t.Fatalf("declared %d: %v", declared, err)
		}
		cleanup()
		if _, _, err := stageBlob(bytes.NewReader(data), 1<<20, declared, 1<<10, dir, sha256Digest([]byte("other")), "blob"); err == nil {
			t.Fatalf("declared %d: digest mismatch accepted", declared)
		}
		if _, _, err := stageBlob(bytes.NewReader(data), 1<<20, declared, 1<<10, dir, "md5:abcd", "blob"); err == nil {
			t.Fatalf("declared %d: unsupported digest accepted", declared)
		}
		if _, _, err := stageBlob(bytes.NewReader(data), 4, declared, 1<<10, dir, dg, "blob"); !errors.Is(err, safeio.ErrTooLarge) {
			t.Fatalf("declared %d: overrun: %v", declared, err)
		}
	}
	if _, _, err := stageBlob(bytes.NewReader(data), 1<<20, 0, 1<<10, dir, "sha256:zz", "blob"); err == nil || !strings.Contains(err.Error(), "malformed digest") {
		t.Fatalf("malformed digest: %v", err)
	}
	if _, _, err := stageBlob(bytes.NewReader(data), 1<<20, 0, 1<<10, dir+"/absent", dg, "blob"); err == nil {
		t.Fatal("missing spool dir accepted")
	}
}

func TestReadFileSpoolUnavailable(t *testing.T) {
	src, top, _ := zerosImage(t, 3<<20)
	m, err := resolveManifestLimits(src, top, Selector{}, Limits{}.resolve(), 0)
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := buildFS(src, m, Limits{SpoolDir: t.TempDir(), SpoolThreshold: 1}.resolve())
	if err != nil {
		t.Fatal(err)
	}
	fsys.ov.sp.close() // the spool vanishes under the FS
	if _, err := fsys.ReadFile("/zeros"); err == nil {
		t.Fatal("ReadFile of a spooled file succeeded without its spool")
	}
}

func TestTarballSpoolErrorsAndReads(t *testing.T) {
	big := bytes.Repeat([]byte{9}, 4096)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	tw.WriteHeader(&tar.Header{Name: "big/x", Mode: 0o644, Size: int64(len(big)), Typeflag: tar.TypeReg})
	tw.Write(big)
	tw.Close()

	if _, err := tarballFromReaderLimits(bytes.NewReader(buf.Bytes()), Limits{SpoolThreshold: 1, MaxArchiveMember: 10, SpoolDir: t.TempDir()}); !errors.Is(err, safeio.ErrTooLarge) {
		t.Fatalf("oversize spooled member: %v", err)
	}
	if _, err := tarballFromReaderLimits(bytes.NewReader(buf.Bytes()), Limits{SpoolThreshold: 1, SpoolDir: t.TempDir() + "/absent"}); err == nil {
		t.Fatal("missing spool dir accepted")
	}

	src, err := tarballFromReaderLimits(bytes.NewReader(buf.Bytes()), Limits{SpoolThreshold: 1, SpoolDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer src.(*tarball).Close()
	mem := src.(*tarball).fsys.(*memFS)
	f, err := mem.Open("big/x")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("read spooled member through Open: %d bytes, %v", len(got), err)
	}
	ents, err := mem.ReadDir(".")
	if err != nil || len(ents) != 1 || ents[0].Type() != fs.ModeDir {
		t.Fatalf("ReadDir = %v, %v", ents, err)
	}
}
