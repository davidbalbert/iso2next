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

type ReadReadAtSeeker interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

type readerAtReader struct {
	io.ReaderAt
	size   int64
	offset int64
}

func newReaderAtReader(r io.ReaderAt, size int64) *readerAtReader {
	return &readerAtReader{
		ReaderAt: r,
		size:     size,
		offset:   0,
	}
}

func (r *readerAtReader) Seek(offset int64, whence int) (int64, error) {
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

func (r *readerAtReader) Read(p []byte) (n int, err error) {
	n, err = r.ReadAt(p, r.offset)
	r.offset += int64(n)

	return n, err
}

func readBytes(r ReadReadAtSeeker, offset int64, n int) ([]byte, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("error reading bytes: %w", err)
	}

	return buf, nil
}

func readString(r ReadReadAtSeeker, offset int64, n int) (string, error) {
	buf, err := readBytes(r, offset, n)
	if err != nil {
		return "", err
	}

	buf = bytes.TrimRight(buf, " ")

	return string(buf), nil
}

func readStringJoliet(r ReadReadAtSeeker, offset int64, n int) (string, error) {
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

func readVDescriptor(r ReadReadAtSeeker, offset int64) (vDescriptor, error) {
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

func readVdPrimary(r ReadReadAtSeeker, offset int64) (*vdPrimary, error) {
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

	rootDirEntry, err := readDirEntry(r, offset+156, int64(logicalBlockSize), false)
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

func readVdSupplementary(r ReadReadAtSeeker, offset int64) (*vdSupplementary, error) {
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

	rootDirEntry, err := readDirEntry(r, offset+156, int64(logicalBlockSize), false)
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

func eachVolumeDescriptor(r ReadReadAtSeeker, fn func(vd vDescriptor) (stop bool)) error {
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

type systemUseEntry interface {
	Tag() string
	Len() byte
	Version() byte
}

type baseSystemUseEntry struct {
	tag     string
	len     byte
	version byte
}

func (e baseSystemUseEntry) Tag() string {
	return e.tag
}

func (e baseSystemUseEntry) Len() byte {
	return e.len
}

func (e baseSystemUseEntry) Version() byte {
	return e.version
}

type spEntry struct {
	baseSystemUseEntry
	check []byte
	nSkip byte
}

func (sp *spEntry) valid() bool {
	return sp.Version() == 7 && sp.check[0] == 0xbe && sp.check[1] == 0xef
}

type ceEntry struct {
	baseSystemUseEntry
	lba    uint32
	offset uint32
	len    uint32
}

func (ce *ceEntry) start(blockSize int64) int64 {
	return int64(ce.lba)*blockSize + int64(ce.offset)
}

type erEntry struct {
	baseSystemUseEntry
	extensionVersion    byte
	extensionId         string
	extensionDescriptor string
	extensionSource     string
}

type unknownSystemUseEntry struct {
	baseSystemUseEntry
	data []byte
}

func parseErEntry(base baseSystemUseEntry, data []byte) *erEntry {
	lenId := data[4]
	lenDesc := data[5]
	lenSource := data[6]

	return &erEntry{
		baseSystemUseEntry:  base,
		extensionVersion:    data[7],
		extensionId:         string(data[8 : 8+lenId]),
		extensionDescriptor: string(data[8+lenId : 8+lenId+lenDesc]),
		extensionSource:     string(data[8+lenId+lenDesc : 8+lenId+lenDesc+lenSource]),
	}
}

func readSystemUseEntry(r ReadReadAtSeeker, offset int64) (systemUseEntry, error) {
	sig, err := readBytes(r, offset, 2)
	if err != nil {
		return nil, fmt.Errorf("error reading system use entry signature: %w", err)
	}

	r.Seek(offset+2, io.SeekStart)
	var len uint8
	if err := binary.Read(r, binary.LittleEndian, &len); err != nil {
		return nil, fmt.Errorf("error reading system use entry length: %w", err)
	}

	data, err := readBytes(r, offset, int(len))
	if err != nil {
		return nil, fmt.Errorf("error reading system use entry data: %w", err)
	}

	base := baseSystemUseEntry{
		tag:     string(sig),
		len:     len,
		version: data[2],
	}

	switch string(sig) {
	case "SP":
		return &spEntry{
			baseSystemUseEntry: base,
			check:              data[4:6],
			nSkip:              data[6],
		}, nil
	case "CE":
		return &ceEntry{
			baseSystemUseEntry: base,
			lba:                binary.LittleEndian.Uint32(data[4:8]),
			offset:             binary.LittleEndian.Uint32(data[12:16]),
			len:                binary.LittleEndian.Uint32(data[20:24]),
		}, nil
	case "ER":
		return parseErEntry(base, data), nil
	default:
		return &unknownSystemUseEntry{
			baseSystemUseEntry: base,
			data:               data,
		}, nil
	}
}

func usingSUSP(r ReadReadAtSeeker, offset, len int64) (bool, error) {
	spSize := 7
	end := offset + len

	if offset+int64(spSize) >= end {
		return false, nil
	}

	var spLen byte
	r.Seek(offset+2, io.SeekStart)
	if err := binary.Read(r, binary.LittleEndian, &spLen); err != nil {
		return false, fmt.Errorf("error reading SP length: %w", err)
	}

	if spLen != byte(spSize) {
		return false, nil
	}

	entry, err := readSystemUseEntry(r, offset)
	if err != nil {
		return false, fmt.Errorf("error reading SP system use entry: %w", err)
	}

	if entry.Tag() != "SP" || !entry.(*spEntry).valid() {
		return false, nil
	}

	return true, nil
}

// also reads continuation areas
func readSystemUseField(r ReadReadAtSeeker, offset, len int64) ([]systemUseEntry, error) {
	end := offset + len
	var entries []systemUseEntry

	for offset < end {
		entry, err := readSystemUseEntry(r, offset)
		if err != nil {
			return nil, fmt.Errorf("error reading SP system use entry: %w", err)
		}

		entries = append(entries, entry)

		if entry.Tag() == "ST" || offset+4 >= end {
			break
		}

		offset += int64(entry.Len())
	}

	return entries, nil
}

func remove(entries []systemUseEntry, i int) []systemUseEntry {
	return append(entries[:i], entries[i+1:]...)
}

func findEntry(entries []systemUseEntry, tag string) int {
	for i, entry := range entries {
		if entry.Tag() == tag {
			return i
		}
	}
	return -1
}

func readSystemUseArea(r ReadReadAtSeeker, offset, len, blockSize int64) ([]systemUseEntry, error) {
	shouldRead, err := usingSUSP(r, offset, len)
	if err != nil {
		return nil, fmt.Errorf("error reading system use area: %w", err)
	}

	if !shouldRead {
		return nil, nil
	}

	entries, err := readSystemUseField(r, offset, len)
	if err != nil {
		return nil, fmt.Errorf("error reading system use field: %w", err)
	}

	for {
		i := findEntry(entries, "CE")

		if i == -1 {
			break
		}

		ce := entries[i].(*ceEntry)
		entries = remove(entries, i)

		moreEntries, err := readSystemUseField(r, ce.start(blockSize), int64(ce.len))
		if err != nil {
			return nil, fmt.Errorf("error reading continuation area: %w", err)
		}

		entries = append(entries, moreEntries...)
	}

	return entries, nil
}

const (
	flagDir uint8 = (1 << 1)
)

type dirEntry struct {
	len         uint8
	eaLen       uint8
	lba         uint32
	fileSize    uint32
	ctime       time.Time
	mode        fs.FileMode
	name        string
	suspEntries []systemUseEntry
}

func readTime(r ReadReadAtSeeker, offset int64) (time.Time, error) {
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

func readDirEntry(r ReadReadAtSeeker, offset, blockSize int64, joliet bool) (*dirEntry, error) {
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

	var padLen int64
	if nameLen%2 == 0 {
		padLen = 1
	} else {
		padLen = 0
	}

	sysStart := offset + 33 + int64(nameLen) + padLen
	sysLen := int64(len) - (33 + int64(nameLen) + padLen)

	fmt.Println(name, offset, len, nameLen, padLen)

	entries, err := readSystemUseArea(r, sysStart, sysLen, blockSize)
	if err != nil {
		return nil, fmt.Errorf("error reading directory entry SUSP area: %w", err)
	}

	if entries != nil {
		n := name
		if n == "\x00" {
			n = "."
		} else if n == "\x01" {
			n = ".."
		}

		fmt.Println(n, "found susp", entries)
		for _, e := range entries {
			fmt.Println(e)
		}
	} else {
		fmt.Println("no susp")
	}

	return &dirEntry{len, eaLen, lba, fileSize, ctime, mode, name, entries}, nil
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
	fsys *FS
	*dirEntry
	offset int64
}

func (f *file) Stat() (fs.FileInfo, error) {
	return f.dirEntry, nil
}

// returns first byte of the file in the file system
func (f *file) start() int64 {
	return int64(f.dirEntry.lba) * f.fsys.blockSize()
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

	n, err := f.fsys.r.ReadAt(p, start+f.offset)
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

	_, err := f.fsys.r.ReadAt(buf, f.start()+f.offset)
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

		dirent, err := readDirEntry(f.fsys.r, start+f.offset, f.fsys.blockSize(), f.fsys.isJoliet())
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
	r      ReadReadAtSeeker
	pvd    *vdPrimary
	joliet *vdSupplementary
}

func Open(name string) (*FS, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	return NewFS(f)
}

func NewFS(r ReadReadAtSeeker) (*FS, error) {
	var primary *vdPrimary = nil
	var joliet *vdSupplementary = nil
	err := eachVolumeDescriptor(r, func(vd vDescriptor) (stop bool) {
		if vd.vType() == vtPrimary {
			primary = vd.(*vdPrimary)
		} else if vd.vType() == vtSupplementary {
			svd := vd.(*vdSupplementary)

			if svd.isJoliet() {
				// joliet = svd
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

func (fsys *FS) blockSize() int64 {
	if fsys.isJoliet() {
		return int64(fsys.joliet.logicalBlockSize)
	} else {
		return int64(fsys.pvd.logicalBlockSize)
	}
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
	if c, ok := fsys.r.(io.Closer); ok {
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

	// fsys, err := Open(fname)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer fsys.Close()

	r, err := mmap.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	fsys, err := NewFS(newReaderAtReader(r, int64(r.Len())))
	if err != nil {
		log.Fatal(err)
	}

	err = fs.WalkDir(fsys, "ETC", func(path string, dirent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == "." {
			fmt.Println(".")
		} else {
			fmt.Printf("./%s\n", path)
		}

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
