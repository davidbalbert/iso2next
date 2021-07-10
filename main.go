package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/exp/mmap"
)

const kb = 1024
const sectSize = 2 * kb

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

func readBytes(r *reader, offset int64, n int) ([]byte, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("error reading bytes: %w", err)
	}

	return buf, nil
}

func readString(r *reader, offset int64, n int) (string, error) {
	buf, err := readBytes(r, offset, n)
	if err != nil {
		return "", err
	}

	buf = bytes.TrimRight(buf, " ")

	return string(buf), nil
}

func readStringJoliet(r *reader, offset int64, n int) (string, error) {
	buf, err := readBytes(r, offset, n)
	if err != nil {
		return "", err
	}

	if eq(buf, []byte{0x00}) || eq(buf, []byte{0x01}) {
		return string(buf), nil
	}

	buf = bytes.TrimRight(buf, "\x00")

	if len(buf)%2 == 1 {
		return "", fmt.Errorf("odd length UCS-2 string: %v", buf)
	}

	br := bytes.NewReader(buf)

	encoded := make([]uint16, len(buf)/2)
	if err := binary.Read(br, binary.BigEndian, &encoded); err != nil {
		return "", err
	}

	runes := utf16.Decode(encoded)

	return string(runes), nil
}

type vType uint8

const (
	vtBoot vType = iota
	vtPrimary
	vtSupplementary
	vtPartition
	vtTerminator = 255
)

type vVersion byte

const (
	vvSupplementary vVersion = 1
	vvEnhanced      vVersion = 2
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
	logicalBlockSize uint16
	root             *dirEntry
}

type vdSupplementary struct {
	vdBase
	version          vVersion
	flags            byte
	escapeSequences  []byte
	logicalBlockSize uint16
	root             *dirEntry
}

type vdPartition struct {
	vdBase
}

type vdTerminator struct {
	vdBase
}

func chunk(b []byte, n int) [][]byte {
	var chunks [][]byte

	for len(b) > n {
		chunks = append(chunks, b[:n])
		b = b[n:]
	}

	if len(b) > 0 {
		chunks = append(chunks, b)
	}

	return chunks
}

func eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, v := range a {
		if v != b[i] {
			return false
		}
	}

	return true
}

func (vd *vdSupplementary) isJoliet() bool {
	if vd.version != vvSupplementary {
		return false
	}

	if vd.flags&0x01 != 0 {
		return false
	}

	chunkedSequences := chunk(vd.escapeSequences, 3)
	for _, seq := range chunkedSequences {
		if eq(seq, []byte{0x25, 0x2f, 0x40}) || eq(seq, []byte{0x25, 0x2f, 0x43}) || eq(seq, []byte{0x25, 0x2f, 0x45}) {
			return true
		}
	}

	return false
}

func readVDescriptor(r *reader, offset int64) (vDescriptor, error) {
	id, err := readString(r, offset+1, 5)
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
		return readVdSupplementary(r, offset)
	case vtPartition:
		return &vdPartition{vd}, nil
	case vtTerminator:
		return &vdTerminator{vd}, nil
	default:
		return nil, fmt.Errorf("invalid volume type: %d", vtype)
	}
}

func readVdPrimary(r *reader, offset int64) (*vdPrimary, error) {
	var version byte
	r.Seek(offset+6, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor: %w", err)
	}

	if version != 0x01 {
		return nil, fmt.Errorf("invalid primary descriptor version: %d", version)
	}

	var logicalBlockSize uint16
	r.Seek(offset+128, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &logicalBlockSize); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor logical block size: %w", err)
	}

	rootDirEntry, err := readDirEntry(r, offset+156, false)
	if err != nil {
		return nil, fmt.Errorf("error reading root directory entry: %w", err)
	}

	var fileStructureVersion byte
	r.Seek(offset+881, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &fileStructureVersion); err != nil {
		return nil, fmt.Errorf("error reading primary descriptor file structure version: %w", err)
	}

	if fileStructureVersion != 0x01 {
		return nil, fmt.Errorf("invalid primary descriptor file structure version: %d", fileStructureVersion)
	}

	return &vdPrimary{
		vdBase{vType(vtPrimary)},
		logicalBlockSize,
		rootDirEntry,
	}, nil
}

func readVdSupplementary(r *reader, offset int64) (*vdSupplementary, error) {
	var version vVersion
	r.Seek(offset+6, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("error reading supplemtary descriptor version: %w", err)
	}

	var flags byte
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, fmt.Errorf("error reading supplemtary descriptor flags: %w", err)
	}

	escapeSequences, err := readBytes(r, offset+88, 32)
	if err != nil {
		return nil, fmt.Errorf("error reading supplementary descriptor escape sequences: %w", err)
	}

	var logicalBlockSize uint16
	r.Seek(offset+128, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &logicalBlockSize); err != nil {
		return nil, fmt.Errorf("error reading supplementary descriptor logical block size: %w", err)
	}

	rootDirEntry, err := readDirEntry(r, offset+156, false)
	if err != nil {
		return nil, fmt.Errorf("error reading supplementary root directory entry: %w", err)
	}

	var fileStructureVersion byte
	r.Seek(offset+881, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &fileStructureVersion); err != nil {
		return nil, fmt.Errorf("error reading supplementary descriptor file structure version: %w", err)
	}

	if fileStructureVersion != 0x01 {
		return nil, fmt.Errorf("invalid supplementary descriptor file structure version: %d", fileStructureVersion)
	}

	return &vdSupplementary{
		vdBase{vType(vtSupplementary)},
		version,
		flags,
		escapeSequences,
		logicalBlockSize,
		rootDirEntry,
	}, nil
}

func eachVolumeDescriptor(r *reader, fn func(vd vDescriptor) (stop bool)) error {
	var offset int64 = 16 * sectSize

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

		offset += sectSize
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
	ctime    time.Time
	mode     fs.FileMode
	name     string
}

func readTime(r *reader, offset int64) (time.Time, error) {
	r.Seek(offset+18, io.SeekStart)

	var year, month, day, hour, minute, second uint8
	var tz int8

	if err := binary.Read(r, binary.LittleEndian, &year); err != nil {
		return time.Time{}, fmt.Errorf("error reading year: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &month); err != nil {
		return time.Time{}, fmt.Errorf("error reading month: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &day); err != nil {
		return time.Time{}, fmt.Errorf("error reading day: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &hour); err != nil {
		return time.Time{}, fmt.Errorf("error reading hour: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &minute); err != nil {
		return time.Time{}, fmt.Errorf("error reading minute: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &second); err != nil {
		return time.Time{}, fmt.Errorf("error reading second: %w", err)
	}

	if err := binary.Read(r, binary.LittleEndian, &tz); err != nil {
		return time.Time{}, fmt.Errorf("error reading time zone offset: %w", err)
	}

	var tzName string
	tzSeconds := 15 * 60 * int(tz)
	if tzSeconds == 0 {
		tzName = "UTC"
	} else if tzSeconds > 0 && tzSeconds%3600 == 0 {
		tzName = fmt.Sprintf("UTC+%d", tzSeconds/3600)
	} else if tzSeconds > 0 {
		tzName = fmt.Sprintf("UTC+%d:%0d", tzSeconds/3600, tzSeconds/60)
	} else if tzSeconds < 0 && tzSeconds%3600 == 0 {
		tzName = fmt.Sprintf("UTC-%d", -tzSeconds/3600)
	} else {
		tzName = fmt.Sprintf("UTC-%d:%0d", -tzSeconds/3600, -tzSeconds/60)
	}

	location := time.FixedZone(tzName, tzSeconds)

	return time.Date(1900+int(year), time.Month(month), int(day), int(hour), int(minute), int(second), 0, location), nil
}

func readDirEntry(r *reader, offset int64, joliet bool) (*dirEntry, error) {
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
	ctime, err := readTime(r, offset)
	if err != nil {
		return nil, fmt.Errorf("error reading directory entry created at: %w", err)
	}

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

	var name string
	if joliet {
		name, err = readStringJoliet(r, offset+33, int(nameLen))
	} else {
		name, err = readString(r, offset+33, int(nameLen))
	}
	if err != nil {
		return nil, fmt.Errorf("error reading file name: %w", err)
	}

	return &dirEntry{len, eaLen, lba, fileSize, ctime, mode, name}, nil
}

func (d *dirEntry) Name() string {
	if d.name == "\x00" {
		return "."
	} else if d.name == "\x01" {
		return ".."
	} else if strings.HasSuffix(d.name, ".;1") {
		return d.name[:len(d.name)-3]
	} else if strings.HasSuffix(d.name, ";1") {
		return d.name[:len(d.name)-2]
	} else {
		return d.name
	}
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
	return d.ctime
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

type file struct {
	fs *FS
	*dirEntry
	offset int64
}

func (f *file) Stat() (fs.FileInfo, error) {
	return f.dirEntry, nil
}

// returns first byte of the file in the file system
func (f *file) start() int64 {
	return int64(f.dirEntry.lba) * int64(f.fs.pvd.logicalBlockSize)
}

func (f *file) Read(p []byte) (int, error) {
	if f.dirEntry.IsDir() {
		return 0, fmt.Errorf("can't call Read on a directory")
	}

	if len(p) == 0 {
		return 0, nil
	} else if f.offset >= f.dirEntry.Size() {
		return 0, io.EOF
	}

	start := f.start()

	n, err := f.fs.r.ReadAt(p, start+f.offset)
	f.offset += int64(n)
	return n, err
}

func (f *file) Close() error {
	return nil
}

func ceil(n, m int64) int64 {
	return m * ((n + (m - 1)) / m)
}

func (f *file) peek() (byte, error) {
	buf := make([]byte, 1)

	_, err := f.fs.r.ReadAt(buf, f.start()+f.offset)
	if err != nil {
		return 0, err
	}

	return buf[0], nil
}

func (f *file) ReadDir(n int) ([]fs.DirEntry, error) {
	if !f.dirEntry.IsDir() {
		return nil, fmt.Errorf("can't call ReadDir on a file")
	}

	var entries []fs.DirEntry
	if n > 0 {
		entries = make([]fs.DirEntry, 0, n)
	} else {
		entries = make([]fs.DirEntry, 0, 100)
	}

	start := f.start()

	for len(entries) < n || n <= 0 {
		len, err := f.peek()
		if err != nil {
			return nil, err
		}

		if len == 0 {
			f.offset = ceil(f.offset, sectSize)
		}

		if f.offset >= f.dirEntry.Size() {
			break
		}

		dirent, err := readDirEntry(f.fs.r, start+f.offset, f.fs.isJoliet())
		if err != nil {
			return entries, err
		}

		f.offset += int64(dirent.len)

		if dirent.Name() == "." || dirent.Name() == ".." {
			continue
		}

		entries = append(entries, dirent)
	}

	if n > 0 && len(entries) == 0 {
		return nil, io.EOF
	}

	return entries, nil
}

type FS struct {
	r      *reader
	pvd    *vdPrimary
	joliet *vdSupplementary
}

func Open(name string) (*FS, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	return NewFS(f, info.Size())
}

func NewFS(readerAt io.ReaderAt, size int64) (*FS, error) {
	r := newReader(readerAt, size)

	var primary *vdPrimary = nil
	var joliet *vdSupplementary = nil
	err := eachVolumeDescriptor(r, func(vd vDescriptor) (stop bool) {
		if vd.vType() == vtPrimary {
			primary = vd.(*vdPrimary)
		} else if vd.vType() == vtSupplementary {
			svd := vd.(*vdSupplementary)

			if svd.isJoliet() {
				joliet = svd
			}
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
		r:      r,
		pvd:    primary,
		joliet: joliet,
	}, nil
}

func contains(a []string, s string) bool {
	for _, e := range a {
		if e == s {
			return true
		}
	}
	return false
}

func (fsys *FS) isJoliet() bool {
	return fsys.joliet != nil
}

func (fsys *FS) root() *dirEntry {
	if fsys.joliet != nil {
		return fsys.joliet.root
	} else {
		return fsys.pvd.root
	}
}

func (fsys *FS) walk(name string) (*dirEntry, error) {
	pathComponents := strings.Split(name, "/")

	if pathComponents[0] == "." {
		pathComponents = pathComponents[1:]
	}

	dirent := fsys.root()

	for i, component := range pathComponents {
		last := i == len(pathComponents)-1

		candidates := []string{component, component + ";1"}

		f := &file{fsys, dirent, 0}
		for {
			child, err := f.ReadDir(1)
			if err == io.EOF {
				return nil, fs.ErrNotExist
			} else if err != nil {
				return nil, err
			}

			if contains(candidates, child[0].Name()) {
				dirent = child[0].(*dirEntry)
				break
			}
		}

		if !last && !dirent.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", component)
		}
	}

	return dirent, nil
}

func (fsys *FS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	dirent, err := fsys.walk(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return &file{fsys, dirent, 0}, nil
}

func (fsys *FS) Close() error {
	if c, ok := fsys.r.ReaderAt.(io.Closer); ok {
		return c.Close()
	}

	return nil
}

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <iso9660 image>\n", os.Args[0])
	}

	fname := os.Args[1]

	r, err := mmap.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	fsys, err := NewFS(r, int64(r.Len()))
	if err != nil {
		log.Fatal(err)
	}

	// f, err := fsys.Open(".")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// dir, ok := f.(fs.ReadDirFile)
	// if !ok {
	// 	log.Fatal("not a directory")
	// }

	// entries, err := dir.ReadDir(-1)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// entries, err := fs.ReadDir(fsys, ".")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for _, dirent := range entries {
	// 	if dirent.IsDir() {
	// 		log.Printf("%s/\n", dirent.Name())
	// 	} else {
	// 		log.Printf("%s\n", dirent.Name())
	// 	}
	// }

	err = fs.WalkDir(fsys, ".", func(path string, dirent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := dirent.Info()
		if err != nil {
			return err
		}

		if dirent.IsDir() {
			fmt.Printf("%s\t%s/\n", info.ModTime(), path)
		} else {
			fmt.Printf("%s\t%s\n", info.ModTime(), path)
		}

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	// 	buf, err := fs.ReadFile(fsys, "bin/awk")
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	//
	// 	fmt.Println(string(buf))
}
