package oci

import (
	"archive/tar"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// BlobSource provides content-addressed access to an image's blobs (manifests,
// configs and layers) by their digest string (e.g. "sha256:abc...").
type BlobSource interface {
	// Blob returns a reader for the blob identified by digest. The caller
	// must Close the returned reader. An error wrapping fs.ErrNotExist is
	// returned when the digest is unknown.
	Blob(digest string) (io.ReadCloser, error)
}

// sha256Digest returns the "sha256:<hex>" digest of data.
func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// normalizeArchivePath cleans an archive member path the same way the tar
// indexer does (strip "./" prefix, path.Clean).
func normalizeArchivePath(p string) string {
	return path.Clean(strings.TrimPrefix(p, "./"))
}

// parseDigest splits an "alg:hex" digest into its algorithm and lower-case hex
// parts, validating shape. Only sha256 and sha512 hex shapes are recognised
// for path construction; any algorithm is accepted structurally.
func parseDigest(digest string) (alg, hexpart string, err error) {
	i := strings.IndexByte(digest, ':')
	if i <= 0 || i == len(digest)-1 {
		return "", "", fmt.Errorf("oci: malformed digest %q", digest)
	}
	alg, hexpart = digest[:i], digest[i+1:]
	// The algorithm names a directory in the OCI layout (blobs/<alg>/<hex>), and
	// it comes from an untrusted manifest: restrict it to the image-spec
	// grammar (lower-case alphanumerics joined by + . _ -) so "../.." cannot
	// walk out of the layout.
	for _, c := range []byte(alg) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '_' || c == '-') {
			return "", "", fmt.Errorf("oci: malformed digest %q: bad algorithm", digest)
		}
	}
	if alg == "." || alg == ".." {
		return "", "", fmt.Errorf("oci: malformed digest %q: bad algorithm", digest)
	}
	if _, err := hex.DecodeString(hexpart); err != nil {
		return "", "", fmt.Errorf("oci: malformed digest %q: %w", digest, err)
	}
	return alg, hexpart, nil
}

// verifyDigest verifies that data matches the given content digest. Both
// sha256 and sha512 — the only algorithms registered in the OCI image-spec
// digest set — are computed and compared. An unknown algorithm is REJECTED
// (fail closed) rather than trusted unverified: an attacker must not be able to
// bypass content verification by labelling a blob with a digest algorithm we
// do not implement.
func verifyDigest(digest string, data []byte) error {
	alg, want, err := parseDigest(digest)
	if err != nil {
		return err
	}
	var got string
	switch alg {
	case "sha256":
		sum := sha256.Sum256(data)
		got = hex.EncodeToString(sum[:])
	case "sha512":
		sum := sha512.Sum512(data)
		got = hex.EncodeToString(sum[:])
	default:
		return fmt.Errorf("oci: unsupported digest algorithm %q (only sha256, sha512)", alg)
	}
	if got != want {
		return fmt.Errorf("oci: digest mismatch for %s: computed %s:%s", digest, alg, got)
	}
	return nil
}

// ----- OCI image layout (directory) -----

type ociLayout struct {
	dir string
	// synth holds in-memory blobs (e.g. the top-level index, which lives in
	// index.json rather than the content store) keyed by their sha256 digest.
	synth map[string][]byte
}

// OCILayout returns a BlobSource backed by an OCI image layout directory, i.e.
// a directory containing an "oci-layout" marker, "index.json" and a
// "blobs/<alg>/<hex>" content store.
func OCILayout(dir string) BlobSource { return &ociLayout{dir: dir} }

func (o *ociLayout) Blob(digest string) (io.ReadCloser, error) {
	alg, hexpart, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	if b, ok := o.synth[digest]; ok {
		return io.NopCloser(byteReader(b)), nil
	}
	p := filepath.Join(o.dir, "blobs", alg, hexpart)
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("oci: blob %s: %w", digest, fs.ErrNotExist)
		}
		return nil, err
	}
	return f, nil
}

// ----- Tarball (docker save / OCI archive) -----

type tarball struct {
	fsys fs.FS
	// index maps "alg/hex" to the entry name inside the archive. docker save
	// stores blobs under blobs/<alg>/<hex>; some tools also store layer.tar
	// files referenced by manifest.json which we map via configMap.
	blobs map[string]string
}

// Tarball returns a BlobSource backed by a `docker save` / OCI archive tar
// file on disk.
func Tarball(p string) (BlobSource, error) {
	return TarballLimits(p, Limits{})
}

// TarballLimits is Tarball with an explicit resource budget for the archive
// (MaxArchiveMember, MaxArchiveTotal, MaxEntries, MaxMetadata, MaxPathLen,
// MaxSparseHoles). A zero field takes the default.
func TarballLimits(p string, lim Limits) (BlobSource, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return tarballFromReaderLimits(f, lim)
}

// TarballFS returns a BlobSource backed by an archive tar exposed through an
// fs.FS. The archive is expected at the path "image.tar"; if absent, the first
// (and only) regular file is used. Most callers should prefer Tarball.
func TarballFS(fsys fs.FS) (BlobSource, error) {
	// Find a single tar file in the FS root.
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var name string
	for _, e := range entries {
		if !e.IsDir() {
			name = e.Name()
			break
		}
	}
	if name == "" {
		return nil, errors.New("oci: TarballFS: no archive file found in fs")
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return tarballFromReader(f)
}

// tarballFromReader indexes every member of a tar archive into an in-memory
// content store keyed by digest path ("alg/hex"). Entries that already live
// under blobs/<alg>/<hex> are indexed by that path; bare "<hex>/layer.tar"
// style members are indexed by their sha256 so manifest references resolve.
func tarballFromReader(r io.Reader) (BlobSource, error) {
	return tarballFromReaderLimits(r, Limits{})
}

func tarballFromReaderLimits(r io.Reader, lim Limits) (BlobSource, error) {
	lim = lim.resolve()
	mem := &memFS{files: map[string][]byte{}}
	// The stream is read through a counter: the archive may be handed to us
	// through an fs.FS that decompresses, and an entry of an unknown typeflag is
	// skipped by reading its body. Members hold at most lim.MaxArchiveTotal
	// bytes; names and headers get lim.MaxMetadata on top.
	cr := &countingReader{r: r, max: lim.MaxArchiveTotal + lim.MaxMetadata}
	tr := tar.NewReader(cr)
	blobs := map[string]string{}
	var total int64   // cumulative bytes buffered across all members
	var meta int64    // cumulative bytes of stored member names
	var members int64 // stored members
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("oci: reading archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// Count and name bytes: a member of zero bytes still costs a map entry
		// and its name, and a name may be up to 1 MiB in a PAX header.
		members++
		meta += int64(len(hdr.Name))
		if members > lim.MaxEntries || meta > lim.MaxMetadata || len(hdr.Name) > lim.MaxPathLen {
			return nil, tooLarge("archive holds too many members or names (%d members, %d name bytes)", members, meta)
		}
		// Per-member and cumulative caps: an archive must not be able to
		// buffer a decompression/expansion bomb. The smaller of the absolute
		// per-member ceiling and the remaining total budget bounds this read;
		// hdr.Size is attacker-controlled so it only ever shrinks the cap. A
		// sparse member reads back as zeros it does not carry: holeGuard bounds
		// the logical bytes by the physical position plus lim.MaxSparseHoles.
		memberCap := min(lim.MaxArchiveMember, lim.MaxArchiveTotal-total)
		if hdr.Size >= 0 && hdr.Size < memberCap {
			memberCap = hdr.Size
		}
		body := &holeGuard{r: tr, phys: cr, base: total, max: lim.MaxSparseHoles}
		data, err := readAllCapped(body, memberCap, fmt.Sprintf("archive member %q", hdr.Name))
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		mem.files[name] = data
		// Index blobs/<alg>/<hex>.
		if strings.HasPrefix(name, "blobs/") {
			rest := strings.TrimPrefix(name, "blobs/")
			if i := strings.IndexByte(rest, '/'); i > 0 {
				alg := rest[:i]
				hx := rest[i+1:]
				blobs[alg+"/"+hx] = name
			}
		}
		// Index any member by its sha256 so legacy docker-save layer.tar
		// files (referenced by sha256 in synthesized manifests) resolve.
		sum := sha256.Sum256(data)
		blobs["sha256/"+hex.EncodeToString(sum[:])] = name
	}
	return &tarball{fsys: mem, blobs: blobs}, nil
}

func (t *tarball) Blob(digest string) (io.ReadCloser, error) {
	alg, hexpart, err := parseDigest(digest)
	if err != nil {
		return nil, err
	}
	name, ok := t.blobs[alg+"/"+hexpart]
	if !ok {
		return nil, fmt.Errorf("oci: blob %s: %w", digest, fs.ErrNotExist)
	}
	// name is guaranteed present in the backing memFS: the blobs index and
	// mem.files are populated together.
	return io.NopCloser(byteReader(t.fsys.(*memFS).files[name])), nil
}

// memFS is a trivial in-memory fs.FS for the indexed tarball members.
type memFS struct {
	files map[string][]byte
}

func (m *memFS) Open(name string) (fs.File, error) {
	data, ok := m.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &memFile{name: name, data: data}, nil
}

func (m *memFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	seen := map[string]bool{}
	var out []fs.DirEntry
	for k := range m.files {
		top := k
		if i := strings.IndexByte(k, '/'); i >= 0 {
			top = k[:i]
		}
		if seen[top] {
			continue
		}
		seen[top] = true
		isDir := strings.ContainsRune(k, '/')
		out = append(out, memDirEntry{name: top, dir: isDir})
	}
	return out, nil
}

type memDirEntry struct {
	name string
	dir  bool
}

func (e memDirEntry) Name() string { return e.name }
func (e memDirEntry) IsDir() bool  { return e.dir }
func (e memDirEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e memDirEntry) Info() (fs.FileInfo, error) { return memFileInfo{name: e.name, dir: e.dir}, nil }

type memFile struct {
	name string
	data []byte
	off  int
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return memFileInfo{name: f.name, size: int64(len(f.data))}, nil
}

func (f *memFile) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

func (f *memFile) Close() error { return nil }

type memFileInfo struct {
	name string
	size int64
	dir  bool
}

func (i memFileInfo) Name() string { return i.name }
func (i memFileInfo) Size() int64  { return i.size }
func (i memFileInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (i memFileInfo) ModTime() time.Time { return time.Time{} }
func (i memFileInfo) IsDir() bool        { return i.dir }
func (i memFileInfo) Sys() any           { return nil }
