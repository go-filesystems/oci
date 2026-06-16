# oci

[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![CGO_ENABLED=0](https://img.shields.io/badge/CGO__ENABLED-0-success)](https://pkg.go.dev/cmd/cgo)

Pure-Go, read-only **OCI / Docker image filesystem** for the
[go-filesystems](https://github.com/go-filesystems) family. It overlays an
image's tar layers — honouring whiteouts, opaque directories, hardlinks and
symlinks — and serves the merged rootfs through
[`go-filesystems/interface`](https://github.com/go-filesystems/interface). No
container runtime, no cgo.

## Why

A container image *is* a filesystem: an ordered stack of tar layers that overlay
into a rootfs. This driver reads that rootfs natively — to `mkfs` it into an
ext4 image, serve it read-only over virtio-fs, or inspect it — without pulling
in containerd, a runtime, or any C toolchain.

## Install

```sh
go get github.com/go-filesystems/oci
```

## Usage

```go
import "github.com/go-filesystems/oci"

// From an OCI image layout directory…
fsys, err := oci.OpenLayout("path/to/oci-layout")
// …or a `docker save` / OCI archive tarball:
//   fsys, err := oci.OpenTarball("image.tar")
if err != nil {
    return err
}
defer fsys.Close()

data, err := fsys.ReadFile("/etc/os-release")
entries, err := fsys.ListDir("/usr/bin")
st, err := fsys.Stat("/bin/sh")
target, err := fsys.ReadLink("/bin/sh") // if it is a symlink
```

`fsys` satisfies `filesystem.Filesystem`. For a multi-arch index, select a
manifest with `OpenSelect`/`OpenDescriptor`; to read from a custom blob store,
implement `BlobSource` and call `Open`.

The image is **read only**: `WriteFile`, `MkDir`, `DeleteFile`, `DeleteDir` and
`Rename` return `ErrReadOnly`.

## Layer compression

`gzip` and uncompressed layers are built in (stdlib only). Other codecs are
opt-in with no extra dependency — register them yourself:

```go
oci.RegisterDecompressor(oci.MediaTypeLayerTarZstd, func(r io.Reader) (io.Reader, error) {
    return zstd.NewReader(r) // your pure-Go zstd of choice
})
```

## License

BSD-3-Clause © the go-filesystems/oci authors.
