package fsutil

import "io/fs"

type DeviceFileInfo interface {
	fs.FileInfo
	Device() (Device, error)
}

type Device interface {
	Major() uint64
	Minor() uint64
}

// https://github.com/golang/go/issues/49580
type ReadLinkFS interface {
	fs.FS
	ReadLink(name string) (string, error)
	StatLink(name string) (fs.FileInfo, error)
}

func ReadLink(fsys fs.FS, name string) (string, error) {
	sym, ok := fsys.(ReadLinkFS)
	if !ok {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	return sym.ReadLink(name)
}

func StatLink(fsys fs.FS, name string) (fs.FileInfo, error) {
	sym, ok := fsys.(ReadLinkFS)
	if !ok {
		return fs.Stat(fsys, name)
	}
	return sym.StatLink(name)
}
