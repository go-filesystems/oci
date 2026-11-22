package oci

import (
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"

	"github.com/go-volumes/safeio"
)

// Default in-memory ceilings. A file body (or a tarball member) larger than
// defaultSpoolThreshold, or one that would push the bytes held in RAM past
// defaultMaxMemory, is spooled to a temporary file instead of the heap, so the
// default budget never lets an untrusted image occupy more than about
// defaultMaxMemory of RAM for file contents however large its (still bounded)
// uncompressed size is.
var (
	defaultSpoolThreshold int64 = 4 << 20
	defaultMaxMemory      int64 = 256 << 20
)

// spool is an append-only temporary file holding the bodies that do not fit the
// in-memory budget. It is created lazily, with mode 0600 (os.CreateTemp), under
// dir (the system temporary directory when empty). On platforms that allow it
// the name is unlinked at once, so even a crashed process leaves nothing
// behind; elsewhere close removes it.
type spool struct {
	dir  string
	f    *os.File
	off  int64
	name string
}

func newSpool(dir string) *spool { return &spool{dir: dir} }

func (s *spool) file() (*os.File, error) {
	if s.f != nil {
		return s.f, nil
	}
	f, err := os.CreateTemp(s.dir, "oci-spool-*")
	if err != nil {
		return nil, fmt.Errorf("oci: creating spool file: %w", err)
	}
	// Remember the name; where the platform lets us unlink an open file the
	// name is forgotten at once, and close removes only what is still named.
	s.name = f.Name()
	if runtime.GOOS != "windows" && os.Remove(s.name) == nil {
		s.name = ""
	}
	s.f = f
	return f, nil
}

// copyIn appends at most limit bytes of r to the spool (feeding h when not
// nil) and returns where they landed. A source that streams more than limit
// bytes fails closed with safeio.ErrTooLarge, like readAllCapped.
func (s *spool) copyIn(r io.Reader, limit int64, what string, h hash.Hash) (off, n int64, err error) {
	// A negative limit reads zero bytes and 0 > limit refuses below.
	f, err := s.file()
	if err != nil {
		return 0, 0, err
	}
	src := io.LimitReader(r, limit+1)
	if h != nil {
		src = io.TeeReader(src, h)
	}
	off = s.off
	n, err = io.Copy(io.NewOffsetWriter(f, off), src)
	if err != nil {
		return 0, 0, fmt.Errorf("oci: spooling %s: %w", what, err)
	}
	if n > limit {
		return 0, 0, fmt.Errorf("oci: %s: blob exceeds %d bytes: %w", what, limit, safeio.ErrTooLarge)
	}
	s.off += n
	return off, n, nil
}

// section returns a reader over [off, off+n) of the spool.
func (s *spool) section(off, n int64) *io.SectionReader {
	return io.NewSectionReader(s.f, off, n)
}

// close closes the spool file and removes it where it was not unlinked at
// creation. It is idempotent.
func (s *spool) close() error {
	if s == nil || s.f == nil {
		return nil
	}
	err := s.f.Close()
	if s.name != "" {
		if rerr := os.Remove(s.name); rerr != nil && err == nil {
			err = rerr
		}
	}
	s.f, s.name = nil, ""
	return err
}

// memBudget decides, for a body of a declared size, between the heap and the
// spool.
type memBudget struct {
	threshold int64
	max       int64
	used      int64
}

// inMemory reports whether a body of size n may stay on the heap, and if so
// accounts for it. An empty body always may.
func (b *memBudget) inMemory(n int64) bool {
	if n == 0 {
		return true
	}
	if n > b.threshold || b.used+n > b.max {
		return false
	}
	b.used += n
	return true
}

// stageBlob reads a layer blob of at most limit bytes into a reader positioned
// at its start, verifying its digest while it streams. A blob of declared
// size <= threshold stays on the heap; any other goes to a temporary file under
// dir. cleanup releases the file.
func stageBlob(r io.Reader, limit, declared int64, threshold int64, dir, digest, what string) (io.Reader, func(), error) {
	noop := func() {}
	if declared > 0 && declared <= threshold {
		data, err := readAllCapped(r, limit, what)
		if err != nil {
			return nil, noop, err
		}
		if err := verifyDigest(digest, data); err != nil {
			return nil, noop, err
		}
		return byteReader(data), noop, nil
	}
	h, want, err := newDigestHash(digest)
	if err != nil {
		return nil, noop, err
	}
	sp := newSpool(dir)
	_, n, err := sp.copyIn(r, limit, what, h)
	if err != nil {
		sp.close()
		return nil, noop, err
	}
	if err := checkDigest(digest, h, want); err != nil {
		sp.close()
		return nil, noop, err
	}
	return sp.section(0, n), func() { sp.close() }, nil
}
