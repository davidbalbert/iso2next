package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
)

const kb = 1024
const sectBytes = 2 * kb

var (
	aChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!\"%&'()*+,-./:;<=>?]*$")
	dChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
)

type reader struct {
	io.ReaderAt
	size   int64
	offset int64
}

func newReader(r io.ReaderAt, size int64) *reader {
	return &reader{
		ReaderAt: r,
		size:     size,
		offset:   0,
	}
}

func (r *reader) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = r.offset + offset
	case io.SeekEnd:
		newOffset = r.size - 1 + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newOffset < 0 || newOffset >= r.size {
		return 0, fmt.Errorf("invalid offset: %d", newOffset)
	}

	r.offset = newOffset
	return newOffset, nil
}

func (r *reader) Read(p []byte) (n int, err error) {
	n, err = r.ReadAt(p, r.offset)
	r.offset += int64(n)

	return n, err
}

func contains(s []byte, c byte) bool {
	for _, b := range s {
		if b == c {
			return true
		}
	}

	return false
}

func readStrA(r *reader, offset int64, n int) (string, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return "", fmt.Errorf("error reading strA: %w", err)
	}

	buf = bytes.TrimRight(buf, " ")

	for _, c := range buf {
		if !contains(aChars, c) {
			return "", fmt.Errorf("invalid strA: %d in %s", c, string(buf))
		}
	}

	return string(buf), nil
}

func readStrD(r *reader, offset int64, n int) (string, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return "", fmt.Errorf("error reading strD: %w", err)
	}

	buf = bytes.TrimRight(buf, " ")

	for _, c := range buf {
		if !contains(dChars, c) {
			return "", fmt.Errorf("invalid strD: %d in %s", c, string(buf))
		}
	}

	return string(buf), nil
}

type vType uint8

const (
	vtBoot vType = iota
	vtPrimary
	vtSupplementary
	vtPartition
	vtTerminator = 255
)

type vDescriptor interface {
	vType() vType
	vTypeDescription() string
}

type vdBase struct {
	type_ vType
}

func (vd *vdBase) vType() vType {
	return vd.type_
}

func (vd *vdBase) vTypeDescription() string {
	switch vd.type_ {
	case vtBoot:
		return "boot"
	case vtPrimary:
		return "primary"
	case vtSupplementary:
		return "supplementary"
	case vtPartition:
		return "partition"
	case vtTerminator:
		return "terminator"
	default:
		return "unknown"
	}

}

type vdBoot struct {
	vdBase
}

type vdPrimary struct {
	vdBase
	systemId string
	volumeId string
	// volumeSpaceSize             uint32
	// volumeSetSize               uint16
	// volumeSequenceNumber        uint16
	// logicalBlockSize            uint16
	// pathTableSize               uint32
	// pathTableLocationLE         uint32
	// optionalPathTableLocationLE uint32
	// pathTableLocationBE         uint32
	// optionalPathTableLocationBE uint32
	// // TODO: root directory record
	// volumeSetId         string
	// publisherId         string
	// dataPreparerId      string
	// applicationId       string
	// copyrightFileId     string
	// abstractFileId      string
	// bibliographicFileId string
	// // TODO: volume creation date and time
	// // TODO: volume modification date and time
	// // TODO: volume expiration date and time
	// // TODO: volume effective date and time
	// fileStructureVersion uint8
}

type vdSupplementary struct {
	vdBase
}

type vdPartition struct {
	vdBase
}

func readVDescriptor(r *reader, offset int64) (vDescriptor, error) {
	id, err := readStrA(r, offset+1, 5)
	if err != nil {
		return nil, fmt.Errorf("error reading volume identifier: %w", err)
	}

	if id != "CD001" {
		return nil, fmt.Errorf("invalid volume identifier: %s", id)
	}

	var vtype byte
	r.Seek(offset, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &vtype); err != nil {
		return nil, fmt.Errorf("error reading volume type: %w", err)
	}

	if vtype > byte(vtPartition) && vtype < byte(vtTerminator) {
		return nil, fmt.Errorf("invalid volume type: %d", vtype)
	}

	vd := vdBase{vType(vtype)}
	switch vd.type_ {
	case vtBoot:
		return &vdBoot{vd}, nil
	case vtPrimary:
		return readVdPrimary(r, offset)
	case vtSupplementary:
		return &vdSupplementary{vd}, nil
	case vtPartition:
		return &vdPartition{vd}, nil
	default:
		return nil, fmt.Errorf("invalid volume type: %d", vtype)
	}
}

func readVdPrimary(r *reader, offset int64) (*vdPrimary, error) {
	buf := make([]byte, 1)

	var version uint8
	r.Seek(offset+6, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor: %w", err)
	}

	if version != 0x01 {
		return nil, fmt.Errorf("invalid primary descriptor version: %d", buf[0])
	}

	systemId, err := readStrA(r, offset+8, 32)
	if err != nil {
		return nil, fmt.Errorf("error reading primary descriptor system id: %w", err)
	}

	volumeId, err := readStrD(r, offset+40, 32)
	if err != nil {
		return nil, fmt.Errorf("error reading primary descriptor volume id: %w", err)
	}

	// var volumeSpaceSize uint32

	return &vdPrimary{
		vdBase{vType(vtPrimary)},
		systemId,
		volumeId,
	}, nil
}

func eachVolume(r *reader, fn func(vd vDescriptor, stop *bool)) error {
	var offset int64 = 16 * sectBytes

	for {
		vd, err := readVDescriptor(r, offset)
		if err != nil {
			return err
		}

		if vd.vType() == vtTerminator {
			break
		}

		stop := false
		fn(vd, &stop)

		if stop {
			break
		}

		offset += sectBytes
	}

	return nil
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

	info, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}

	r := newReader(f, info.Size())

	var primary vDescriptor = nil
	err = eachVolume(r, func(vd vDescriptor, stop *bool) {
		if vd.vType() == vtPrimary {
			primary = vd
			*stop = true
		}
	})

	if err != nil {
		log.Fatalf("error reading %s: %v\n", fname, err)
	}

	if primary != nil {
		fmt.Println(primary.vTypeDescription())
	}

	fmt.Println(primary)
}
