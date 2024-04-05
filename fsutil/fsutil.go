package fsutil

import "io/fs"

type ReadlinkDirEntry interface {
	fs.DirEntry
	Readlink() (string, error)
}

type DeviceDirEntry interface {
	fs.DirEntry
	GetDevice() (Device, error)
}

type Device interface {
	Major() uint64
	Minor() uint64
}
