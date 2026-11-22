package oci

import (
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// Where a platform cannot unlink an open file (Windows), the spool keeps its
// name and close removes the file; a removal that fails is reported.
func TestSpoolCloseRemovesNamedFile(t *testing.T) {
	dir := t.TempDir()
	s := newSpool(dir)
	f, err := os.CreateTemp(dir, "named-*")
	if err != nil {
		t.Fatal(err)
	}
	s.f, s.name = f, f.Name()
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.Base(f.Name()))); !os.IsNotExist(err) {
		t.Fatalf("spool file not removed: %v", err)
	}

	f2, err := os.CreateTemp(dir, "gone-*")
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(f2.Name())
	s = newSpool(dir)
	s.f, s.name = f2, f2.Name()
	if err := s.close(); err == nil {
		t.Fatal("close of a spool whose file vanished reported no error")
	}
}

// A tarball source over a plain fs.FS owns no spool; Close is a no-op.
func TestTarballCloseWithoutSpool(t *testing.T) {
	tb := &tarball{fsys: fstest.MapFS{}}
	if err := tb.Close(); err != nil {
		t.Fatal(err)
	}
}
