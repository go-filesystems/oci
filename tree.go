package oci

import (
	"archive/tar"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/go-volumes/safeio"
)

// FileType constants returned by DirEntry.FileType() and node.ftype. The
// go-filesystems/interface package does not define these, so we define a local
// mapping that mirrors the POSIX d_type / tar typeflag taxonomy.
const (
	FileTypeUnknown uint8 = iota
	FileTypeRegular
	FileTypeDir
	FileTypeSymlink
	FileTypeHardlink
	FileTypeChar
	FileTypeBlock
	FileTypeFifo
)

// node is a single entry in the merged overlay tree.
type node struct {
	name     string // base name
	ftype    uint8
	mode     uint16 // permission + type bits, POSIX style (lower 16 of tar mode)
	size     uint64
	inode    uint64
	linkname string // symlink target or hardlink target path (clean, absolute)

	// content location for regular files: the layer blob and the offset/size
	// of the file's data within the decompressed tar stream is not stored;
	// instead we buffer file bytes at index time (see ReadFile strategy).
	data []byte

	// children for directories: base name -> *node.
	children map[string]*node

	// opaque marks a directory that had an opaque whiteout applied in the
	// current layer (used only transiently during a single layer apply).
	opaque bool
}

func newDir(name string, mode uint16, inode uint64) *node {
	return &node{
		name:     name,
		ftype:    FileTypeDir,
		mode:     mode,
		inode:    inode,
		children: map[string]*node{},
	}
}

// tarTypeToFileType maps a tar typeflag to our FileType constant.
func tarTypeToFileType(flag byte) uint8 {
	switch flag {
	case tar.TypeReg, tar.TypeRegA:
		return FileTypeRegular
	case tar.TypeDir:
		return FileTypeDir
	case tar.TypeSymlink:
		return FileTypeSymlink
	case tar.TypeLink:
		return FileTypeHardlink
	case tar.TypeChar:
		return FileTypeChar
	case tar.TypeBlock:
		return FileTypeBlock
	case tar.TypeFifo:
		return FileTypeFifo
	default:
		return FileTypeUnknown
	}
}

// overlay builds and holds the merged tree.
type overlay struct {
	root   *node
	nextID uint64
}

func newOverlay() *overlay {
	o := &overlay{nextID: 1}
	o.root = newDir("", 0o755, o.alloc())
	return o
}

func (o *overlay) alloc() uint64 {
	id := o.nextID
	o.nextID++
	return id
}

// cleanPath normalizes p to a rooted, slash-clean absolute path with no
// trailing slash (except root "/").
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	c := path.Clean(p)
	return c
}

// splitParent returns the cleaned parent directory and base name of p.
func splitParent(p string) (parent, base string) {
	c := cleanPath(p)
	if c == "/" {
		return "/", ""
	}
	parent = path.Dir(c)
	base = path.Base(c)
	return parent, base
}

// ensureDir walks/creates the directory chain for the cleaned absolute dir
// path and returns its node.
func (o *overlay) ensureDir(dir string) *node {
	dir = cleanPath(dir)
	if dir == "/" {
		return o.root
	}
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	cur := o.root
	for _, part := range parts {
		child, ok := cur.children[part]
		if !ok || child.ftype != FileTypeDir {
			child = newDir(part, 0o755, o.alloc())
			cur.children[part] = child
		}
		cur = child
	}
	return cur
}

// lookup resolves a cleaned absolute path to its node, or (nil, false).
func (o *overlay) lookup(p string) (*node, bool) {
	c := cleanPath(p)
	if c == "/" {
		return o.root, true
	}
	parts := strings.Split(strings.TrimPrefix(c, "/"), "/")
	cur := o.root
	for _, part := range parts {
		if cur.children == nil {
			return nil, false
		}
		child, ok := cur.children[part]
		if !ok {
			return nil, false
		}
		cur = child
	}
	return cur, true
}

// applyLayer folds one decompressed tar stream onto the merged tree using
// overlayfs whiteout semantics. maxUncompressed bounds the cumulative
// uncompressed bytes of regular-file contents in this layer; exceeding it (a
// decompression bomb) fails closed with safeio.ErrTooLarge.
func (o *overlay) applyLayer(tr *tar.Reader, maxUncompressed int64) error {
	// Track directories that received an opaque marker in this layer so that
	// later entries in the same layer are preserved.
	var consumed int64 // cumulative uncompressed file bytes folded so far
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("oci: reading layer tar: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if name == "." || name == "/" || name == "" {
			continue
		}
		dir, base := splitParent("/" + name)

		// Whiteout handling.
		if strings.HasPrefix(base, ".wh.") {
			parent := o.ensureDir(dir)
			if base == ".wh..wh..opq" {
				// Opaque: clear lower contents of this directory, but keep
				// entries added in this same layer.
				keep := map[string]*node{}
				for n, c := range parent.children {
					if c.opaque {
						keep[n] = c
					}
				}
				parent.children = keep
				parent.opaque = true
				continue
			}
			removed := strings.TrimPrefix(base, ".wh.")
			delete(parent.children, removed)
			continue
		}

		parent := o.ensureDir(dir)
		ft := tarTypeToFileType(hdr.Typeflag)

		switch ft {
		case FileTypeDir:
			existing, ok := parent.children[base]
			if ok && existing.ftype == FileTypeDir {
				// Update mode but keep children (merge).
				existing.mode = uint16(hdr.Mode) & 0o7777
				existing.opaque = true
				existing.name = base
			} else {
				d := newDir(base, uint16(hdr.Mode)&0o7777, o.alloc())
				d.opaque = true
				parent.children[base] = d
			}
		case FileTypeRegular:
			// Per-file cap: the smaller of the declared header Size, the
			// remaining cumulative uncompressed budget, and the absolute
			// per-file ceiling. hdr.Size is attacker-controlled (and can lie),
			// so we never trust it to *grow* the cap — only to shrink it — and
			// we re-check the actual byte count after reading.
			remaining := maxUncompressed - consumed
			fileCap := maxFileSize
			if remaining < fileCap {
				fileCap = remaining
			}
			if hdr.Size >= 0 && hdr.Size < fileCap {
				fileCap = hdr.Size
			}
			data, err := readAllCapped(tr, fileCap, fmt.Sprintf("file %q", name))
			if err != nil {
				return err
			}
			consumed += int64(len(data))
			parent.children[base] = &node{
				name:   base,
				ftype:  FileTypeRegular,
				mode:   uint16(hdr.Mode) & 0o7777,
				size:   uint64(len(data)),
				inode:  o.alloc(),
				data:   data,
				opaque: true,
			}
		case FileTypeSymlink:
			parent.children[base] = &node{
				name:     base,
				ftype:    FileTypeSymlink,
				mode:     uint16(hdr.Mode) & 0o7777,
				size:     uint64(len(hdr.Linkname)),
				inode:    o.alloc(),
				linkname: hdr.Linkname,
				opaque:   true,
			}
		case FileTypeHardlink:
			// Resolve target relative to root; store the cleaned target path.
			target := cleanPath("/" + path.Clean(strings.TrimPrefix(hdr.Linkname, "./")))
			parent.children[base] = &node{
				name:     base,
				ftype:    FileTypeHardlink,
				mode:     uint16(hdr.Mode) & 0o7777,
				inode:    o.alloc(),
				linkname: target,
				opaque:   true,
			}
		case FileTypeChar, FileTypeBlock, FileTypeFifo:
			parent.children[base] = &node{
				name:   base,
				ftype:  ft,
				mode:   uint16(hdr.Mode) & 0o7777,
				inode:  o.alloc(),
				opaque: true,
			}
		default:
			// Unknown/unsupported tar entry types are skipped.
		}
	}
}

// clearOpaqueFlags resets transient opaque markers between layers.
func (o *overlay) clearOpaqueFlags() {
	var walk func(n *node)
	walk = func(n *node) {
		n.opaque = false
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(o.root)
}

// resolveHardlink follows a hardlink node to the regular file it targets.
// Mutually-referential or self-referential TypeLink entries (A→B→A) would
// otherwise recurse without bound and panic the host; a VisitSet keyed by
// inode bails out with safeio.ErrCycle, and a LoopGuard bounds the chain
// length as a belt-and-braces depth limit.
func (o *overlay) resolveHardlink(n *node) (*node, error) {
	var seen safeio.VisitSet
	guard := safeio.NewLoopGuard(maxHardlinkDepth)
	cur := n
	for {
		if err := guard.Next(); err != nil {
			return nil, fmt.Errorf("oci: hardlink %s: %w", n.name, err)
		}
		if err := seen.Check(cur.inode); err != nil {
			return nil, fmt.Errorf("oci: hardlink %s: %w", n.name, err)
		}
		target, ok := o.lookup(cur.linkname)
		if !ok {
			return nil, fmt.Errorf("oci: hardlink %s targets missing path %s", cur.name, cur.linkname)
		}
		if target.ftype != FileTypeHardlink {
			return target, nil
		}
		cur = target
	}
}

// sortedChildren returns a directory's children sorted by name.
func sortedChildren(n *node) []*node {
	out := make([]*node, 0, len(n.children))
	for _, c := range n.children {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
