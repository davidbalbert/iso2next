package fsutil

import "io/fs"

type DeviceDirEntry interface {
	fs.DirEntry
	GetDevice() (Device, error)
}

type Device interface {
	Major() uint64
	Minor() uint64
}

// Copied from Go 1.23
type SymlinkFS interface {
	fs.FS
	ReadLink(name string) (string, error)
	Lstat(name string) (fs.FileInfo, error)
}

func ReadLink(fsys fs.FS, name string) (string, error) {
	sym, ok := fsys.(SymlinkFS)
	if !ok {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	return sym.ReadLink(name)
}

func Lstat(fsys fs.FS, name string) (fs.FileInfo, error) {
	sym, ok := fsys.(SymlinkFS)
	if !ok {
		return fs.Stat(fsys, name)
	}
	return sym.Lstat(name)
}
