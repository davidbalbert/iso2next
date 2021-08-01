package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
)

type ReadlinkDirEntry interface {
	fs.DirEntry
	Readlink() (string, error)
}

type DeviceDirEntry interface {
	fs.DirEntry
	Device() (uint64, error)
}

func major(dev uint64) uint64 {
	return dev >> 32
}

func minor(dev uint64) uint64 {
	return dev & 0xffffffff
}

func readBytes(r io.ReaderAt, offset int64, n int) ([]byte, error) {
	buf := make([]byte, n)

	// No need to check number of bytes read. ReadAt will block until
	// len(buf) bytes are available or fail with an error.
	if _, err := r.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("error reading bytes: %w", err)
	}

	return buf, nil
}

func parseString(buf []byte) string {
	return string(bytes.TrimRight(buf, "\x00"))
}

const (
	kb            = 1024
	diskLabelSize = 8 * kb
)

const (
	dlv1 uint32 = 0x4e655854 // "NeXT"
	dlv2 uint32 = 0x646c5632 // "dlV2"
	dlv3 uint32 = 0x646c5633 // "dlV3"
)

type diskLabel struct {
	version   uint32
	label     string
	driveName string
	driveType string
	sectsize  int32
}

func readDiskLabel(r io.ReaderAt) (*diskLabel, error) {
	buf, err := readBytes(r, 0, diskLabelSize)
	if err != nil {
		return nil, err
	}

	version := binary.BigEndian.Uint32(buf[:4])

	if version != dlv1 && version != dlv2 && version != dlv3 {
		return nil, fmt.Errorf("can't find nextstep disk label")
	}

	label := parseString(buf[12:36])
	driveName := parseString(buf[44:68])
	driveType := parseString(buf[68:92])
	sectsize := int32(binary.BigEndian.Uint32(buf[92:96]))

	return &diskLabel{
		version:   version,
		label:     label,
		driveName: driveName,
		driveType: driveType,
		sectsize:  sectsize,
	}, nil
}

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <iso9660 image>\n", os.Args[0])
	}

	fname := os.Args[1]

	f, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	d, err := readDiskLabel(f)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(d)

	// r, err := mmap.Open(fname)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer r.Close()

	// fsys, err := iso9660.NewFS(r)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// err = fs.WalkDir(fsys, ".", func(path string, dirent fs.DirEntry, err error) error {
	// 	if err != nil {
	// 		return err
	// 	}

	// 	info, err := dirent.Info()
	// 	if err != nil {
	// 		return err
	// 	}

	// 	fmt.Printf("%s\t", info.Mode().String())

	// 	if dirent, ok := dirent.(DeviceDirEntry); info.Mode()&fs.ModeDevice != 0 && ok {
	// 		dev, err := dirent.Device()
	// 		if err != nil {
	// 			return err
	// 		}

	// 		fmt.Printf("%d, %d\t", major(dev), minor(dev))
	// 	} else {
	// 		fmt.Printf("%d\t", info.Size())
	// 	}

	// 	if path == "." {
	// 		fmt.Print("/")
	// 	} else {
	// 		fmt.Printf("/%s", path)
	// 	}

	// 	if dirent, ok := dirent.(ReadlinkDirEntry); info.Mode()&fs.ModeSymlink != 0 && ok {
	// 		target, err := dirent.Readlink()
	// 		if err != nil {
	// 			return err
	// 		}

	// 		fmt.Printf(" -> %s", target)
	// 	}
	// 	fmt.Println()

	// 	return nil
	// })
	// if err != nil {
	// 	log.Fatal(err)
	// }
}
