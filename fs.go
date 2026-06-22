package oci

import (
	"archive/tar"
	"errors"
	"fmt"
	"io/fs"
	"os"

	filesystem "github.com/go-filesystems/interface"
)

// ErrReadOnly is returned by every mutating method of FS. An OCI image
// filesystem is immutable: it is a read-only overlay of the image's layers.
var ErrReadOnly = errors.New("oci: read-only filesystem")

// FS is a read-only github.com/go-filesystems/interface Filesystem view over an
// OCI/Docker image's merged layer tree.
//
// ReadFile strategy: file contents are buffered into the in-memory merged tree
// at Open time (each regular file's bytes are read once while its owning layer
// is decompressed). This keeps ReadFile a pure in-memory lookup, makes
// hardlink resolution trivial (both names share the target's buffered bytes),
// and avoids holding blob file handles open after Open returns. The trade-off
// is memory proportional to the uncompressed image size; for the
// disk-image-as-filesystem use cases this driver targets that is acceptable
// and matches how the sibling drivers buffer their trees.
type FS struct {
	ov     *overlay
	closed bool
}

// compile-time assertion: FS implements the shared Filesystem interface.
var _ filesystem.Filesystem = (*FS)(nil)

// Open resolves the single image addressed by src (the first manifest in the
// index, or a multi-arch index's first matching manifest) and returns a
// read-only FS over its merged layers. To select a specific manifest from a
// multi-arch index, pass a Selector via OpenSelect.
func Open(src BlobSource) (*FS, error) {
	return OpenSelect(src, Selector{})
}

// OpenSelect is like Open but selects a manifest from a multi-arch index by
// digest or platform.
func OpenSelect(src BlobSource, sel Selector) (*FS, error) {
	top, err := topDescriptor(src)
	if err != nil {
		return nil, err
	}
	m, err := resolveManifest(src, top, sel)
	if err != nil {
		return nil, err
	}
	ov := newOverlay()
	for _, layer := range m.Layers {
		if err := applyLayerBlob(ov, src, layer); err != nil {
			return nil, err
		}
		ov.clearOpaqueFlags()
	}
	return &FS{ov: ov}, nil
}

// OpenLayout is a convenience wrapper: OpenLayout(dir) == Open(OCILayout(dir)).
func OpenLayout(dir string) (*FS, error) {
	return Open(OCILayout(dir))
}

// OpenTarball is a convenience wrapper around Tarball.
func OpenTarball(p string) (*FS, error) {
	src, err := Tarball(p)
	if err != nil {
		return nil, err
	}
	return Open(src)
}

// applyLayerBlob fetches, verifies, decompresses and folds one layer.
func applyLayerBlob(ov *overlay, src BlobSource, layer descriptor) error {
	rc, err := src.Blob(layer.Digest)
	if err != nil {
		return err
	}
	defer rc.Close()

	// Digest verification requires the full blob; read it once. Cap the read
	// at the digest-verified descriptor Size (clamped to the hardening
	// ceiling) so a blob that streams more bytes than promised — or an
	// untrusted source with no Size at all — cannot OOM the host. We read up
	// to limit+1 and reject when the source overruns the declared length.
	limit := maxBlobSize
	if layer.Size > 0 && layer.Size < limit {
		limit = layer.Size
	}
	data, err := readAllCapped(rc, limit, "layer "+layer.Digest)
	if err != nil {
		return err
	}
	if err := verifyDigest(layer.Digest, data); err != nil {
		return err
	}
	d, err := lookupDecompressor(layer.MediaType)
	if err != nil {
		return err
	}
	dr, err := d(byteReader(data))
	if err != nil {
		return fmt.Errorf("oci: decompressing layer %s: %w", layer.Digest, err)
	}
	// Bound the *uncompressed* stream: a tiny gzip blob can expand without
	// limit (decompression bomb). applyLayer reads every file body through a
	// bounded readAllCapped and tracks a cumulative budget, so the expansion
	// is cut off with a graceful safeio.ErrTooLarge rather than buffering the
	// whole bomb. Tar headers are fixed-size (512 B) so the header reads are
	// inherently bounded; no outer LimitReader is needed.
	return ov.applyLayer(tar.NewReader(dr), maxLayerUncompressed)
}

// resolve resolves a cleaned path to its node, following hardlinks for the
// terminal entry. Returns a wrapped fs.ErrNotExist when absent.
func (f *FS) resolve(path string, followHardlink bool) (*node, error) {
	if f.closed {
		return nil, fmt.Errorf("oci: filesystem closed")
	}
	n, ok := f.ov.lookup(path)
	if !ok {
		return nil, fmt.Errorf("oci: %s: %w", cleanPath(path), fs.ErrNotExist)
	}
	if followHardlink && n.ftype == FileTypeHardlink {
		return f.ov.resolveHardlink(n)
	}
	return n, nil
}

// Stat returns metadata for path. Mode packs the POSIX type bits with the
// permission bits.
func (f *FS) Stat(path string) (filesystem.Stat, error) {
	n, err := f.resolve(path, false)
	if err != nil {
		return nil, err
	}
	target := n
	if n.ftype == FileTypeHardlink {
		t, err := f.ov.resolveHardlink(n)
		if err != nil {
			return nil, err
		}
		target = t
	}
	return filesystem.NewStat(modeWithType(target), target.size, target.inode), nil
}

// ListDir returns the entries of the directory at path, sorted by name.
func (f *FS) ListDir(path string) ([]filesystem.DirEntry, error) {
	n, err := f.resolve(path, false)
	if err != nil {
		return nil, err
	}
	if n.ftype != FileTypeDir {
		return nil, fmt.Errorf("oci: %s: not a directory", cleanPath(path))
	}
	children := sortedChildren(n)
	out := make([]filesystem.DirEntry, 0, len(children))
	for _, c := range children {
		out = append(out, filesystem.NewDirEntry(c.inode, c.name, c.ftype))
	}
	return out, nil
}

// ReadFile returns the contents of the regular file (or hardlink to one) at
// path.
func (f *FS) ReadFile(path string) ([]byte, error) {
	n, err := f.resolve(path, true)
	if err != nil {
		return nil, err
	}
	if n.ftype != FileTypeRegular {
		return nil, fmt.Errorf("oci: %s: not a regular file", cleanPath(path))
	}
	buf := make([]byte, len(n.data))
	copy(buf, n.data)
	return buf, nil
}

// ReadLink returns the target of the symbolic link at path.
func (f *FS) ReadLink(path string) (string, error) {
	n, err := f.resolve(path, false)
	if err != nil {
		return "", err
	}
	if n.ftype != FileTypeSymlink {
		return "", fmt.Errorf("oci: %s: not a symlink", cleanPath(path))
	}
	return n.linkname, nil
}

// Close releases the filesystem. It is idempotent; a second call returns nil.
func (f *FS) Close() error {
	f.closed = true
	f.ov = nil
	return nil
}

// ---- mutating methods: all read-only ----

// WriteFile always returns ErrReadOnly.
func (f *FS) WriteFile(path string, data []byte, perm os.FileMode) error { return ErrReadOnly }

// MkDir always returns ErrReadOnly.
func (f *FS) MkDir(path string, perm os.FileMode) error { return ErrReadOnly }

// DeleteFile always returns ErrReadOnly.
func (f *FS) DeleteFile(path string) error { return ErrReadOnly }

// DeleteDir always returns ErrReadOnly.
func (f *FS) DeleteDir(path string) error { return ErrReadOnly }

// Rename always returns ErrReadOnly.
func (f *FS) Rename(oldPath, newPath string) error { return ErrReadOnly }

// modeWithType packs the POSIX file-type bits into the permission mode so that
// Stat.Mode() round-trips through standard mode-bit inspection.
func modeWithType(n *node) uint16 {
	const (
		sIFREG = 0o100000
		sIFDIR = 0o040000
		sIFLNK = 0o120000
		sIFCHR = 0o020000
		sIFBLK = 0o060000
		sIFIFO = 0o010000
	)
	var typ uint16
	switch n.ftype {
	case FileTypeRegular, FileTypeHardlink:
		typ = sIFREG
	case FileTypeDir:
		typ = sIFDIR
	case FileTypeSymlink:
		typ = sIFLNK
	case FileTypeChar:
		typ = sIFCHR
	case FileTypeBlock:
		typ = sIFBLK
	case FileTypeFifo:
		typ = sIFIFO
	}
	return typ | (n.mode & 0o7777)
}
