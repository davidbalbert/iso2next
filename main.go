package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"time"
)

const kb = 1024
const sectBytes = 2 * kb

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

func readStr(r *reader, offset int64, n int) (string, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return "", fmt.Errorf("error reading strD: %w", err)
	}

	buf = bytes.TrimRight(buf, " ")

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
	systemId             string
	volumeId             string
	volumeSpaceSize      uint32
	volumeSetSize        uint16
	volumeSequenceNumber uint16
	logicalBlockSize     uint16
	pathTableSize        uint32
	// uses the little endian variants of path tables
	pathTableLocation         uint32
	optionalPathTableLocation uint32
	rootDirEntry              *dirEntry
}

type vdSupplementary struct {
	vdBase
}

type vdPartition struct {
	vdBase
}

func readVDescriptor(r *reader, offset int64) (vDescriptor, error) {
	id, err := readStr(r, offset+1, 5)
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

	systemId, err := readStr(r, offset+8, 32)
	if err != nil {
		return nil, fmt.Errorf("error reading primary descriptor system id: %w", err)
	}

	volumeId, err := readStr(r, offset+40, 32)
	if err != nil {
		return nil, fmt.Errorf("error reading primary descriptor volume id: %w", err)
	}

	var volumeSpaceSize uint32
	r.Seek(offset+80, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &volumeSpaceSize); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor volume space size: %w", err)
	}

	var volumeSetSize uint16
	r.Seek(offset+120, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &volumeSetSize); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor volume set size: %w", err)
	}

	var volumeSequenceNumber uint16
	r.Seek(offset+124, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &volumeSequenceNumber); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor volume sequence number: %w", err)
	}

	var logicalBlockSize uint16
	r.Seek(offset+128, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &logicalBlockSize); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor logical block size: %w", err)
	}

	var pathTableSize uint32
	r.Seek(offset+132, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &pathTableSize); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor path table size: %w", err)
	}

	var pathTableLocation uint32
	r.Seek(offset+140, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &pathTableLocation); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor path table location: %w", err)
	}

	var optionalPathTableLocation uint32
	if err := binary.Read(r, binary.LittleEndian, &optionalPathTableLocation); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor optional path table location: %w", err)
	}

	rootDirEntry, err := readDirEntry(r, offset+156)
	if err != nil {
		return nil, fmt.Errorf("error reading root directory entry: %w", err)
	}

	var fileStructureVersion uint8
	r.Seek(offset+881, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &fileStructureVersion); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor file structure version: %w", err)
	}

	if fileStructureVersion != 0x01 {
		return nil, fmt.Errorf("invalid primary descriptor file structure version: %d", fileStructureVersion)
	}

	return &vdPrimary{
		vdBase{vType(vtPrimary)},
		systemId,
		volumeId,
		volumeSpaceSize,
		volumeSetSize,
		volumeSequenceNumber,
		logicalBlockSize,
		pathTableSize,
		pathTableLocation,
		optionalPathTableLocation,
		rootDirEntry,
	}, nil
}

type pathTableEntry struct {
	location    uint32
	directoryId string
	size        int64
}

func readPathTableEntry(r *reader, offset int64) (*pathTableEntry, error) {
	var length uint8
	r.Seek(offset, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("error reading directory identifier length: %w", err)
	}

	var location uint32
	r.Seek(offset+2, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &location); err != nil {
		return nil, fmt.Errorf("error reading path table entry location: %w", err)
	}

	directoryId, err := readStr(r, offset+8, int(length))
	if err != nil {
		return nil, fmt.Errorf("error reading path table entry directory id: %w", err)
	}

	var size int64
	size = 8 + int64(length)
	if length%2 == 1 {
		size += 1
	}

	return &pathTableEntry{location, directoryId, size}, nil
}

func (vd *vdPrimary) eachPathTableEntry(r *reader, fn func(entry *pathTableEntry) (stop bool)) error {
	start := int64(vd.pathTableLocation) * int64(vd.logicalBlockSize)
	offset := start

	for {
		pte, err := readPathTableEntry(r, offset)
		if err != nil {
			log.Fatalf("error reading path table entry: %v\n", err)
		}

		stop := fn(pte)
		if stop {
			break
		}

		offset += pte.size

		if offset >= start+int64(vd.pathTableSize) {
			break
		}
	}

	return nil
}

func eachVolume(r *reader, fn func(vd vDescriptor) (stop bool)) error {
	var offset int64 = 16 * sectBytes

	for {
		vd, err := readVDescriptor(r, offset)
		if err != nil {
			return err
		}

		if vd.vType() == vtTerminator {
			break
		}

		stop := fn(vd)

		if stop {
			break
		}

		offset += sectBytes
	}

	return nil
}

const (
	flagDir uint8 = (1 << 1)
)

type dirEntry struct {
	len      uint8
	eaLen    uint8
	lba      uint32
	fileSize uint32
	mode     fs.FileMode
	name     string
}

func readDirEntry(r *reader, offset int64) (*dirEntry, error) {
	var len uint8
	r.Seek(offset, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &len); err != nil {
		return nil, fmt.Errorf("error reading directory entry length: %w", err)
	}

	var eaLen uint8
	if err := binary.Read(r, binary.LittleEndian, &eaLen); err != nil {
		return nil, fmt.Errorf("error reading directory entry extended attribute length: %w", err)
	}

	var lba uint32
	if err := binary.Read(r, binary.LittleEndian, &lba); err != nil {
		return nil, fmt.Errorf("error reading directory entry logical block address: %w", err)
	}

	var fileSize uint32
	r.Seek(offset+10, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &fileSize); err != nil {
		return nil, fmt.Errorf("error reading file size: %w", err)
	}

	// todo: recording date and time
	var flags uint8
	r.Seek(offset+25, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, fmt.Errorf("error reading file flags: %w", err)
	}

	// mode todo:
	// - files with multiple directory entries
	// - extended attribute record (+ owner and group permissions)
	// - "associated files" (?)

	var mode fs.FileMode
	if flags&flagDir != 0 {
		mode = fs.ModeDir
	} else {
		mode = 0
	}

	var nameLen uint8
	r.Seek(offset+32, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &nameLen); err != nil {
		return nil, fmt.Errorf("error reading directory entry name length: %w", err)
	}

	name, err := readStr(r, offset+33, int(nameLen))
	if err != nil {
		return nil, fmt.Errorf("error reading file name: %w", err)
	}

	return &dirEntry{len, eaLen, lba, fileSize, mode, name}, nil
}

func (d *dirEntry) Name() string {
	return d.name
}

func (d *dirEntry) IsDir() bool {
	return d.mode.IsDir()
}

func (d *dirEntry) Type() fs.FileMode {
	return d.mode
}

func (d *dirEntry) Mode() fs.FileMode {
	return d.mode
}

func (d *dirEntry) ModTime() time.Time {
	return time.Now()
}

func (d *dirEntry) Size() int64 {
	return int64(d.fileSize)
}

func (d *dirEntry) Sys() interface{} {
	return nil
}

func (d *dirEntry) Info() (fs.FileInfo, error) {
	return d, nil
}

type FS struct {
	r   *reader
	pvd *vdPrimary
}

func newFS(readerAt io.ReaderAt, size int64) (*FS, error) {
	r := newReader(readerAt, size)

	var primary vDescriptor = nil
	err := eachVolume(r, func(vd vDescriptor) (stop bool) {
		if vd.vType() == vtPrimary {
			primary = vd
			return true
		}

		return false
	})

	if err != nil {
		return nil, fmt.Errorf("error reading primary descriptor: %w", err)
	}

	if primary == nil {
		return nil, fmt.Errorf("primary descriptor not found")
	}

	return &FS{
		r:   r,
		pvd: primary.(*vdPrimary),
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

	info, err := f.Stat()
	if err != nil {
		log.Fatal(err)
	}

	r := newReader(f, info.Size())

	var primary vDescriptor = nil
	err = eachVolume(r, func(vd vDescriptor) (stop bool) {
		if vd.vType() == vtPrimary {
			primary = vd
			return true
		}

		return false
	})

	if err != nil {
		log.Fatalf("error reading %s: %v\n", fname, err)
	}

	p := primary.(*vdPrimary)

	fmt.Println(p.rootDirEntry)

	// p.eachPathTableEntry(r, func(pathTableEntry *pathTableEntry) (stop bool) {
	// 	log.Printf("%s - %d\n", pathTableEntry.directoryId, pathTableEntry.location)
	// 	return false
	// })
}
