package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/exp/mmap"
)

const kb = 1024
const sectSize = 2 * kb

func readBytes(r io.ReaderAt, offset int64, n int) ([]byte, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("error reading bytes: %w", err)
	}

	return buf, nil
}

func readByte(r io.ReaderAt, offset int64) (byte, error) {
	buf, err := readBytes(r, offset, 1)
	if err != nil {
		return 0, err
	}

	return buf[0], nil
}

func parseString(b []byte) string {
	return string(bytes.TrimRight(b, " "))
}

func parseStringJoliet(buf []byte) (string, error) {
	if eq(buf, []byte{0x00}) || eq(buf, []byte{0x01}) {
		return string(buf), nil
	}

	buf = bytes.TrimRight(buf, "\x00")

	if len(buf)%2 == 1 {
		return "", fmt.Errorf("odd length UCS-2 string: %v", buf)
	}

	encoded := make([]uint16, len(buf)/2)
	for i := 0; i < len(buf); i += 2 {
		encoded[i/2] = binary.BigEndian.Uint16(buf[i : i+2])
	}

	return string(utf16.Decode((encoded))), nil
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

type volumeDescriptor interface {
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

func (vd *vdPrimary) detectExtensions(r io.ReaderAt) (susp bool, suspNSkip int64, rockRidge bool, err error) {
	// The "." entry in the root directory holds the root's system use field.
	rootSelf, err := readDirEntry(r, int64(vd.root.lba)*int64(vd.logicalBlockSize), false)
	if err != nil {
		return false, 0, false, err
	}

	susp = isUsingSUSP(rootSelf.systemUse)

	if susp {
		entries, err := readSystemUseArea(r, rootSelf.systemUse, int64(vd.logicalBlockSize))
		if err != nil {
			return false, 0, false, err
		}

		i := findEntry(entries, "SP")
		if i == -1 {
			return false, 0, false, fmt.Errorf("no SP entry found")
		}

		return true, int64(entries[i].(*spEntry).nSkip), isUsingRockRidge(entries), nil
	} else {
		suspNSkip = 0
		rockRidge = false

		return false, 0, false, nil
	}
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

func readVolumeDescriptor(r io.ReaderAt, offset int64) (volumeDescriptor, error) {
	buf, err := readBytes(r, offset, 2048)
	if err != nil {
		return nil, err
	}

	id := parseString(buf[1:6])
	if id != "CD001" {
		return nil, fmt.Errorf("invalid volume identifier: %s", id)
	}

	vtype := buf[0]
	if vtype > byte(vtPartition) && vtype < byte(vtTerminator) {
		return nil, fmt.Errorf("invalid volume type: %d", vtype)
	}

	vd := vdBase{vType(vtype)}
	switch vd.type_ {
	case vtBoot:
		return &vdBoot{vd}, nil
	case vtPrimary:
		return parseVdPrimary(buf)
	case vtSupplementary:
		return parseVdSupplementary(buf)
	case vtPartition:
		return &vdPartition{vd}, nil
	case vtTerminator:
		return &vdTerminator{vd}, nil
	default:
		return nil, fmt.Errorf("invalid volume type: %d", vtype)
	}
}

func parseVdPrimary(buf []byte) (*vdPrimary, error) {
	version := buf[6]
	if version != 0x01 {
		return nil, fmt.Errorf("invalid primary descriptor version: %d", version)
	}

	logicalBlockSize := binary.LittleEndian.Uint16(buf[128:130])

	rootDirEntry, err := parseDirEntry(buf[156:190], false)
	if err != nil {
		return nil, fmt.Errorf("error reading root directory entry: %w", err)
	}

	fileStructureVersion := buf[881]
	if fileStructureVersion != 0x01 {
		return nil, fmt.Errorf("invalid primary descriptor file structure version: %d", fileStructureVersion)
	}

	return &vdPrimary{
		vdBase{vType(vtPrimary)},
		logicalBlockSize,
		rootDirEntry,
	}, nil
}

func parseVdSupplementary(buf []byte) (*vdSupplementary, error) {
	version := vVersion(buf[6])
	flags := buf[7]
	escapeSequences := buf[88:120]
	logicalBlockSize := binary.LittleEndian.Uint16(buf[128:130])

	rootDirEntry, err := parseDirEntry(buf[156:190], false)
	if err != nil {
		return nil, fmt.Errorf("error reading root directory entry: %w", err)
	}

	fileStructureVersion := buf[881]
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

func readVolumeDescriptors(r io.ReaderAt) ([]volumeDescriptor, error) {
	var vds []volumeDescriptor

	var offset int64 = 16 * sectSize

	for {
		vd, err := readVolumeDescriptor(r, offset)
		if err != nil {
			return nil, err
		}

		if vd.vType() == vtTerminator {
			break
		}

		vds = append(vds, vd)

		offset += sectSize
	}

	return vds, nil
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

// System Use Sharing Protocol

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

// Rock Ridge Interchange Protocol

type pxEntry struct {
	baseSystemUseEntry
	mode  uint32
	nlink uint32
	uid   uint32
	gid   uint32
	ino   uint32
}

func parsePxEntry(base baseSystemUseEntry, data []byte) *pxEntry {
	return &pxEntry{
		baseSystemUseEntry: base,
		mode:               binary.LittleEndian.Uint32(data[4:8]),
		nlink:              binary.LittleEndian.Uint32(data[12:16]),
		uid:                binary.LittleEndian.Uint32(data[20:24]),
		gid:                binary.LittleEndian.Uint32(data[28:32]),
		ino:                binary.LittleEndian.Uint32(data[36:40]),
	}
}

type pnEntry struct {
	baseSystemUseEntry
	dev uint64
}

func parsePnEntry(base baseSystemUseEntry, data []byte) *pnEntry {
	devhi := binary.LittleEndian.Uint32(data[4:8])
	devlo := binary.LittleEndian.Uint32(data[12:16])

	return &pnEntry{
		baseSystemUseEntry: base,
		dev:                uint64(devhi)<<32 | uint64(devlo),
	}
}

const (
	slFlagContinue byte = 1 << iota
	slFlagCurrent
	slFlagParent
	slFlagRoot
)

type slComponentRecord struct {
	flags   byte
	content []byte
}

func symlinkFromSl(records []slComponentRecord) string {
	var buf bytes.Buffer
	for i, rec := range records {
		if rec.flags&slFlagRoot != 0 {
			buf.WriteString("/")
		} else if rec.flags&slFlagParent != 0 {
			buf.WriteString("../")
		} else if rec.flags&slFlagCurrent != 0 {
			buf.WriteString("./")
		} else if rec.flags&slFlagContinue != 0 {
			buf.Write(rec.content)
		} else {
			buf.Write(rec.content)

			if i != len(records)-1 {
				buf.WriteString("/")
			}
		}
	}
	return buf.String()
}

type slEntry struct {
	baseSystemUseEntry
	flags            byte
	componentRecords []slComponentRecord
}

func parseSlEntry(base baseSystemUseEntry, data []byte) *slEntry {
	flags := data[4]

	var componentRecords []slComponentRecord
	offset := 5
	for offset < len(data) {
		flags := data[offset]
		contentLen := int(data[offset+1])
		content := data[offset+2 : offset+2+contentLen]
		componentRecords = append(componentRecords, slComponentRecord{flags, content})
		offset += 2 + contentLen
	}

	return &slEntry{
		baseSystemUseEntry: base,
		flags:              flags,
		componentRecords:   componentRecords,
	}
}

const (
	nmFlagContinue byte = 1 << iota
	nmFlagCurrent
	nmFlagParent
)

type nmEntry struct {
	baseSystemUseEntry
	flags byte
	name  string
}

func parseNmEntry(base baseSystemUseEntry, data []byte) *nmEntry {
	flags := data[4]

	var name string
	if flags&nmFlagCurrent != 0 {
		name = "."
	} else if flags&nmFlagParent != 0 {
		name = ".."
	} else {
		name = string(data[5:])
	}

	return &nmEntry{
		baseSystemUseEntry: base,
		flags:              flags,
		name:               name,
	}
}

const (
	tfFlagCreation byte = 1 << iota
	tfFlagModify
	tfFlagAccess
	tfFlagAttributes
	tfFlagBackup
	tfFlagExpiration
	tfFlagEffective
	tfFlagLongForm
)

type tfEntry struct {
	baseSystemUseEntry
	flags               byte
	creationTime        *time.Time
	modifyTime          *time.Time
	accessTime          *time.Time
	attributeChangeTime *time.Time
	backupTime          *time.Time
	expirationTime      *time.Time
	effectiveTime       *time.Time
}

func parseTfEntry(base baseSystemUseEntry, data []byte) (*tfEntry, error) {
	flags := data[4]

	var format timeFormat
	if flags&tfFlagLongForm == tfFlagLongForm {
		format = tfLong
	} else {
		format = tfShort
	}

	offset := 5
	size := format.size()
	var err error

	var creationTime *time.Time
	if flags&tfFlagCreation == tfFlagCreation {
		creationTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	var modifyTime *time.Time
	if flags&tfFlagModify == tfFlagModify {
		modifyTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	var accessTime *time.Time
	if flags&tfFlagAccess == tfFlagAccess {
		accessTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	var attributeChangeTime *time.Time
	if flags&tfFlagAttributes == tfFlagAttributes {
		attributeChangeTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	var backupTime *time.Time
	if flags&tfFlagBackup == tfFlagBackup {
		backupTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	var expirationTime *time.Time
	if flags&tfFlagExpiration == tfFlagExpiration {
		expirationTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	var effectiveTime *time.Time
	if flags&tfFlagEffective == tfFlagEffective {
		effectiveTime = parseTime(data[offset:offset+size], format, &err)
		offset += size
	}

	if err != nil {
		return nil, fmt.Errorf("can't parse tf entry: %w", err)
	}

	return &tfEntry{
		baseSystemUseEntry:  base,
		flags:               flags,
		creationTime:        creationTime,
		modifyTime:          modifyTime,
		accessTime:          accessTime,
		attributeChangeTime: attributeChangeTime,
		backupTime:          backupTime,
		expirationTime:      expirationTime,
		effectiveTime:       effectiveTime,
	}, nil
}

func (tf *tfEntry) String() string {
	return fmt.Sprintf("{%v %d %v %v %v %v %v %v %v}", tf.baseSystemUseEntry, tf.flags, tf.creationTime, tf.modifyTime, tf.accessTime, tf.attributeChangeTime, tf.backupTime, tf.expirationTime, tf.effectiveTime)
}

type unknownSystemUseEntry struct {
	baseSystemUseEntry
	data []byte
}

func isUsingSUSP(rootSystemUseField []byte) bool {
	spSize := 7

	if spSize >= len(rootSystemUseField) {
		return false
	}

	len := rootSystemUseField[2]
	if len != byte(spSize) {
		return false
	}

	entry, err := parseSystemUseEntry(rootSystemUseField)

	// parsing an SP entry should never fail, but if something weird happens
	// and we get an error, just assume we're not using SUSP.
	if err != nil || entry.Tag() != "SP" || !entry.(*spEntry).valid() {
		return false
	}

	return true
}

func isUsingRockRidge(rootEntries []systemUseEntry) bool {
	for _, entry := range rootEntries {
		if entry.Tag() == "ER" && entry.(*erEntry).extensionId == "RRIP_1991A" {
			return true
		}
	}

	return false
}

func parseSystemUseEntry(buf []byte) (systemUseEntry, error) {
	sig := buf[0:2]
	len := buf[2]
	data := buf[0:len]

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
	case "PX":
		return parsePxEntry(base, data), nil
	case "PN":
		return parsePnEntry(base, data), nil
	case "NM":
		return parseNmEntry(base, data), nil
	case "TF":
		return parseTfEntry(base, data)
	case "SL":
		return parseSlEntry(base, data), nil
	default:
		return &unknownSystemUseEntry{
			baseSystemUseEntry: base,
			data:               data,
		}, nil
	}
}

func parseSystemUseEntries(buf []byte) ([]systemUseEntry, error) {
	var entries []systemUseEntry

	offset := int64(0)
	end := int64(len(buf))
	for offset < end {
		entry, err := parseSystemUseEntry(buf[offset:])
		if err != nil {
			return nil, err
		}

		if entry.Tag() == "ST" {
			break
		}

		entries = append(entries, entry)

		offset += int64(entry.Len())

		if offset+4 >= end {
			break
		}
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

func readSystemUseArea(r io.ReaderAt, field []byte, blockSize int64) ([]systemUseEntry, error) {
	entries, err := parseSystemUseEntries(field)
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

		continuationArea, err := readBytes(r, ce.start(blockSize), int(ce.len))
		if err != nil {
			return nil, fmt.Errorf("error reading continuation area: %w", err)
		}

		moreEntries, err := parseSystemUseEntries(continuationArea)
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

type ReadlinkDirEntry interface {
	fs.DirEntry
	Readlink() (string, error)
}

type DevDirEntry interface {
	fs.DirEntry
	Device() (uint64, error)
}

type dirEntry struct {
	len              uint8
	eaLen            uint8
	lba              uint32
	fileSize         uint32
	ctime            time.Time
	mode             fs.FileMode
	name             string
	systemUse        []byte
	systemUseEntries []systemUseEntry

	// Rock Ridge fields

	nlink uint32
	uid   uint32
	gid   uint32
	ino   uint32

	symlink string

	dev uint64
}

func (d *dirEntry) Readlink() (string, error) {
	if d.mode&fs.ModeSymlink == 0 {
		return "", fmt.Errorf("not a symlink: %s", d.name)
	}

	return d.symlink, nil
}

func (d *dirEntry) Device() (uint64, error) {
	if d.mode&fs.ModeDevice == 0 {
		return 0, fmt.Errorf("not a device: %s", d.name)
	}

	return d.dev, nil
}

func location(tzSeconds int) *time.Location {
	var tzName string
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

	return time.FixedZone(tzName, tzSeconds)
}

type timeFormat int

const (
	tfShort timeFormat = iota
	tfLong
)

func (f timeFormat) size() int {
	if f == tfLong {
		return 17
	} else {
		return 7
	}
}

func parseTime(buf []byte, format timeFormat, errp *error) *time.Time {
	if *errp != nil {
		return nil
	}

	if format == tfLong {
		t, err := parseLongFormTime(buf)
		if err != nil {
			*errp = err
			return nil
		}

		return &t
	} else if format == tfShort {
		t := parseShortFormTime(buf)
		return &t
	} else {
		*errp = fmt.Errorf("unknown time format: %d", format)
		return nil
	}
}

func parseShortFormTime(buf []byte) time.Time {
	year := buf[0]
	month := buf[1]
	day := buf[2]
	hour := buf[3]
	minute := buf[4]
	second := buf[5]
	tz := buf[6]

	return time.Date(1900+int(year), time.Month(month), int(day), int(hour), int(minute), int(second), 0, location(15*60*int(tz)))
}

func pow(x, y int64) int64 {
	res := int64(1)

	for y > 0 {
		res *= x
		y -= 1
	}

	return res
}

func parseLongFormTime(buf []byte) (time.Time, error) {
	year, err := strconv.Atoi(parseString(buf[0:4]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse year: %w", err)
	}

	month, err := strconv.Atoi(parseString(buf[4:6]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse month: %w", err)
	}

	day, err := strconv.Atoi(parseString(buf[6:8]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse day: %w", err)
	}

	hour, err := strconv.Atoi(parseString(buf[8:10]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse day: %w", err)
	}

	minute, err := strconv.Atoi(parseString(buf[10:12]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse minute: %w", err)
	}

	second, err := strconv.Atoi(parseString(buf[12:14]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse second: %w", err)
	}

	hundredth, err := strconv.Atoi(parseString(buf[14:16]))
	if err != nil {
		return time.Time{}, fmt.Errorf("can't parse hundreths: %w", err)
	}

	tz := buf[16]

	return time.Date(year, time.Month(month), day, hour, minute, second, hundredth*int(pow(10, 7)), location(15*60*int(tz))), nil
}

func parseDirEntry(buf []byte, joliet bool) (*dirEntry, error) {
	eaLen := buf[1]
	lba := binary.LittleEndian.Uint32(buf[2:6])
	fileSize := binary.LittleEndian.Uint32(buf[10:14])
	ctime := parseShortFormTime(buf[18:25])
	flags := buf[25]

	// mode todo:
	// - files with multiple directory entries
	// - extended attribute record (+ owner and group permissions)
	// - "associated files" (?)

	mode := fs.FileMode(0)
	if flags&flagDir != 0 {
		mode |= fs.ModeDir
	}

	nameLen := buf[32]
	var name string
	var err error
	if joliet {
		name, err = parseStringJoliet(buf[33 : 33+int64(nameLen)])
	} else {
		name = parseString(buf[33 : 33+int64(nameLen)])
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

	sysStart := 33 + int64(nameLen) + padLen

	return &dirEntry{
		len:       uint8(len(buf)),
		eaLen:     eaLen,
		lba:       lba,
		fileSize:  fileSize,
		ctime:     ctime,
		mode:      mode,
		name:      name,
		systemUse: buf[sysStart:],
	}, nil
}

func readDirEntry(r io.ReaderAt, offset int64, joliet bool) (*dirEntry, error) {
	len, err := readByte(r, offset)
	if err != nil {
		return nil, fmt.Errorf("error reading dir entry length: %w", err)
	}

	buf, err := readBytes(r, offset, int(len))
	if err != nil {
		return nil, fmt.Errorf("error reading dir entry: %w", err)
	}

	return parseDirEntry(buf, joliet)
}

func (fsys *FS) readDirEntry(offset int64) (*dirEntry, error) {
	dirent, err := readDirEntry(fsys.r, offset, fsys.joliet)
	if err != nil {
		return nil, err
	}

	if fsys.rockRidge {
		err := dirent.readRockRidge(fsys)
		if err != nil {
			return nil, err
		}
	}

	return dirent, nil
}

func (d *dirEntry) readRockRidge(fsys *FS) error {
	var toRead *dirEntry

	// The "." entry in the root directory holds the root's system use field.
	if d == fsys.root {
		var err error
		toRead, err = readDirEntry(fsys.r, int64(fsys.root.lba)*int64(fsys.logicalBlockSize), false)
		if err != nil {
			return fmt.Errorf("couldn't read rock ridge extensions for volume root: %w", err)
		}
	} else {
		toRead = d
	}

	entries, err := readSystemUseArea(fsys.r, toRead.systemUse, fsys.logicalBlockSize)
	if err != nil {
		return fmt.Errorf("error reading rock ridge: %w", err)
	}

	name := ""
	var slComponentRecords []slComponentRecord

	for _, entry := range entries {
		if entry.Tag() == "PX" {
			px := entry.(*pxEntry)

			d.mode |= fs.FileMode(px.mode & 0777)

			if px.mode&syscall.S_IFSOCK == syscall.S_IFSOCK {
				d.mode |= fs.ModeSocket
			} else if px.mode&syscall.S_IFLNK == syscall.S_IFLNK {
				d.mode |= fs.ModeSymlink
			} else if px.mode&syscall.S_IFBLK == syscall.S_IFBLK {
				d.mode |= fs.ModeDevice
			} else if px.mode&syscall.S_IFCHR == syscall.S_IFCHR {
				d.mode |= fs.ModeDevice | fs.ModeCharDevice
			} else if px.mode&syscall.S_IFIFO == syscall.S_IFIFO {
				d.mode |= fs.ModeNamedPipe
			}

			if px.mode&syscall.S_ISUID == syscall.S_ISUID {
				d.mode |= fs.ModeSetuid
			}
			if px.mode&syscall.S_ISGID == syscall.S_ISGID {
				d.mode |= fs.ModeSetgid
			}

			d.nlink = px.nlink
			d.uid = px.uid
			d.gid = px.gid
			d.ino = px.ino
		} else if entry.Tag() == "PN" {
			pn := entry.(*pnEntry)

			d.dev = pn.dev
		} else if entry.Tag() == "NM" {
			nm := entry.(*nmEntry)

			name += nm.name
			if nm.flags&nmFlagContinue == 0 {
				d.name = entry.(*nmEntry).name
			}
		} else if entry.Tag() == "SL" {
			sl := entry.(*slEntry)

			slComponentRecords = append(slComponentRecords, sl.componentRecords...)

			if sl.flags&slFlagContinue == 0 {
				d.symlink = symlinkFromSl(slComponentRecords)
			}
		} else if entry.Tag() == "TF" {
			tf := entry.(*tfEntry)

			d.ctime = *tf.modifyTime
		}
	}

	d.systemUseEntries = entries

	return nil
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
	return int64(f.dirEntry.lba) * f.fsys.logicalBlockSize
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
	b, err := readByte(f.fsys.r, f.start()+f.offset)
	if err != nil {
		return 0, err
	}

	return b, nil
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

		dirent, err := f.fsys.readDirEntry(start + f.offset)
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
	r                io.ReaderAt
	root             *dirEntry
	logicalBlockSize int64
	susp             bool
	suspNSkip        int64
	rockRidge        bool
	joliet           bool
}

func Open(name string) (*FS, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	return NewFS(f)
}

func NewFS(r io.ReaderAt) (*FS, error) {
	vds, err := readVolumeDescriptors(r)
	if err != nil {
		return nil, err
	}

	var primary *vdPrimary
	// var supplementary *vdSupplementary

	for _, vd := range vds {
		if vd.vType() == vtPrimary {
			primary = vd.(*vdPrimary)
		} else if vd.vType() == vtSupplementary && vd.(*vdSupplementary).isJoliet() {
			// supplementary = vd.(*vdSupplementary)
		}
	}

	if primary == nil {
		return nil, fmt.Errorf("no primary volume descriptor found")
	}

	root := primary.root
	logicalBlockSize := int64(primary.logicalBlockSize)

	susp, suspNSkip, rockRidge, err := primary.detectExtensions(r)
	if err != nil {
		return nil, fmt.Errorf("error detecting SUSP and Rock Ridge: %v", err)
	}

	joliet := false

	fsys := &FS{
		r:                r,
		root:             root,
		logicalBlockSize: logicalBlockSize,
		susp:             susp,
		suspNSkip:        suspNSkip,
		rockRidge:        rockRidge,
		joliet:           joliet,
	}

	if rockRidge {
		if err := root.readRockRidge(fsys); err != nil {
			return nil, err
		}
	}

	return fsys, nil
}

func contains(a []string, s string) bool {
	for _, e := range a {
		if e == s {
			return true
		}
	}
	return false
}

func (fsys *FS) walk(name string) (*dirEntry, error) {
	pathComponents := strings.Split(name, "/")

	if pathComponents[0] == "." {
		pathComponents = pathComponents[1:]
	}

	dirent := fsys.root

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

func major(dev uint64) uint64 {
	return dev >> 32
}

func minor(dev uint64) uint64 {
	return dev & 0xffffffff
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

	fsys, err := NewFS(r)
	if err != nil {
		log.Fatal(err)
	}

	err = fs.WalkDir(fsys, ".", func(path string, dirent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := dirent.Info()
		if err != nil {
			return err
		}

		if path == "." {
			fmt.Printf("%s\t.\n", info.Mode().String())
			return nil
		}

		if dirent, ok := dirent.(DevDirEntry); info.Mode()&fs.ModeDevice != 0 && ok {
			dev, err := dirent.Device()
			if err != nil {
				return err
			}

			fmt.Printf("%s\t%d, %d\t./%s", info.Mode().String(), major(dev), minor(dev), path)
		} else {
			fmt.Printf("%s\t%d\t./%s", info.Mode().String(), info.Size(), path)
		}

		if dirent, ok := dirent.(ReadlinkDirEntry); info.Mode()&fs.ModeSymlink != 0 && ok {
			target, err := dirent.Readlink()
			if err != nil {
				return err
			}

			fmt.Printf(" -> %s", target)
		}
		fmt.Println()

		// fmt.Print(" [")
		// for _, entry := range dirent.(*dirEntry).systemUseEntries {
		// 	fmt.Printf("%v ", entry)
		// }
		// fmt.Println("]")

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
