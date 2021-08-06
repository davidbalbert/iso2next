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
	dlv1 = "NeXT"
	dlv2 = "dlV2"
	dlv3 = "dlV3"
)

type diskLabel struct {
	version           string
	label             string
	flags             uint32
	tag               uint32
	driveName         string
	driveType         string
	sectsize          int32
	ntracks           int32
	nsectors          int32
	ncylinders        int32
	rpm               int32
	frontPorchSectors int16
	backPorchSectors  int16
	ngroups           int16
	agSectors         int16
	agAlts            int16
	agSectorOffset    int16
	bootBlockno       [2]int32
	kernel            string
	hostname          string
	rootPartition     string
	rwPartition       string
}

func readDiskLabel(r io.ReaderAt) (*diskLabel, error) {
	buf, err := readBytes(r, 0, diskLabelSize)
	if err != nil {
		return nil, err
	}

	version := parseString(buf[:4])

	// TODO: we only actually support version 3.
	if version != dlv1 && version != dlv2 && version != dlv3 {
		return nil, fmt.Errorf("can't find nextstep disk label")
	}

	label := parseString(buf[12:36])
	flags := binary.BigEndian.Uint32(buf[36:40])
	tag := binary.BigEndian.Uint32(buf[40:44])
	driveName := parseString(buf[44:68])
	driveType := parseString(buf[68:92])
	sectsize := int32(binary.BigEndian.Uint32(buf[92:96]))
	ntracks := int32(binary.BigEndian.Uint32(buf[96:100]))
	nsectors := int32(binary.BigEndian.Uint32(buf[100:104]))
	ncylinders := int32(binary.BigEndian.Uint32(buf[104:108]))
	rpm := int32(binary.BigEndian.Uint32(buf[108:112]))
	frontPorchSectors := int16(binary.BigEndian.Uint16(buf[112:114]))
	backPorchSectors := int16(binary.BigEndian.Uint16(buf[114:116]))
	ngroups := int16(binary.BigEndian.Uint16(buf[116:118]))
	agSectors := int16(binary.BigEndian.Uint16(buf[118:120]))
	agAlts := int16(binary.BigEndian.Uint16(buf[120:122]))
	agSectorOffset := int16(binary.BigEndian.Uint16(buf[122:124]))
	bootBlockno := [2]int32{
		int32(binary.BigEndian.Uint32(buf[124:128])),
		int32(binary.BigEndian.Uint32(buf[128:132])),
	}
	kernel := parseString(buf[132:156])
	hostname := parseString(buf[156:188])
	rootPartition := parseString(buf[188:189])
	rwPartition := parseString(buf[189:190])

	return &diskLabel{
		version:           version,
		label:             label,
		flags:             flags,
		tag:               tag,
		driveName:         driveName,
		driveType:         driveType,
		sectsize:          sectsize,
		ntracks:           ntracks,
		nsectors:          nsectors,
		ncylinders:        ncylinders,
		rpm:               rpm,
		frontPorchSectors: frontPorchSectors,
		backPorchSectors:  backPorchSectors,
		ngroups:           ngroups,
		agSectors:         agSectors,
		agAlts:            agAlts,
		agSectorOffset:    agSectorOffset,
		bootBlockno:       bootBlockno,
		kernel:            kernel,
		hostname:          hostname,
		rootPartition:     rootPartition,
		rwPartition:       rwPartition,
	}, nil
}

const (
	maxPartitions        = 8
	partitionTableOffset = int64(190)
	partitionEntrySize   = 46
)

type partition struct {
	offset            int32 // in sectors
	size              int32 // in sectors
	blocksize         int32 // in bytes
	fragsize          int32 // in bytes
	optimizationType  string
	cylindersPerGroup int16
	density           int16 // bytes per inode density
	minfree           int8
	newfs             bool
	mountpoint        string
	automount         bool
	typeName          string
}

func parsePartition(buf []byte) (*partition, error) {
	var p partition
	p.offset = int32(binary.BigEndian.Uint32(buf[:4]))
	p.size = int32(binary.BigEndian.Uint32(buf[4:8]))
	p.blocksize = int32(binary.BigEndian.Uint16(buf[8:10]))
	p.fragsize = int32(binary.BigEndian.Uint16(buf[10:12]))
	p.optimizationType = parseString(buf[12:13])
	p.cylindersPerGroup = int16(binary.BigEndian.Uint16(buf[14:16]))
	p.density = int16(binary.BigEndian.Uint16(buf[16:18]))
	p.minfree = int8(buf[18])
	p.newfs = buf[19] != 0
	p.mountpoint = parseString(buf[20:36])
	p.automount = buf[36] != 0
	p.typeName = parseString(buf[37:45])

	return &p, nil
}

type offsetReaderAt struct {
	io.ReaderAt
	offset int64
}

func newOffsetReaderAt(r io.ReaderAt, offset int64) *offsetReaderAt {
	return &offsetReaderAt{r, offset}
}

func (r *offsetReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return r.ReaderAt.ReadAt(p, r.offset+off)
}

type Disk struct {
	r          io.ReaderAt
	label      *diskLabel
	partitions []partition
}

func Open(name string) (*Disk, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	label, err := readDiskLabel(f)
	if err != nil {
		return nil, err
	}

	offset := partitionTableOffset
	var partitions []partition
	for i := 0; i < maxPartitions; i++ {
		buf, err := readBytes(f, offset, partitionEntrySize)
		if err != nil {
			return nil, fmt.Errorf("error reading partition table: %w", err)
		}

		size := int32(binary.BigEndian.Uint32(buf[4:8]))
		if size <= 0 {
			break
		}

		p, err := parsePartition(buf)
		if err != nil {
			return nil, fmt.Errorf("error parsing partition: %w", err)
		}

		partitions = append(partitions, *p)

		offset += partitionEntrySize
	}

	return &Disk{
		r:          f,
		label:      label,
		partitions: partitions,
	}, nil
}

func (d *Disk) NPart() int {
	return len(d.partitions)
}

func (d *Disk) GetPartition(i int) (*FS, error) {
	if i < 0 || i >= len(d.partitions) {
		return nil, fmt.Errorf("invalid partition index %d", i)
	}

	p := d.partitions[i]

	if p.typeName != "4.3BSD" {
		return nil, fmt.Errorf("unsupported partition type %q", p.typeName)
	}

	start := (int64(p.offset) + int64(d.label.frontPorchSectors)) * int64(d.label.sectsize)

	return NewFS(newOffsetReaderAt(d.r, start))
}

func (d *Disk) Close() error {
	if c, ok := d.r.(io.Closer); ok {
		return c.Close()
	}

	return nil
}

const (
	ufsMagic uint32 = 0x011954
	sbsize   int    = 1376
)

type superblock struct {
	sblkno      uint32
	cblkno      uint32
	iblkno      uint32
	dblkno      uint32
	cgoffset    uint32
	cgmask      uint32
	nfrag       uint32
	ngroup      uint32
	blocksize   uint32
	fragsize    uint32
	ipg         uint32 // inodes per group
	fpg         uint32 // fragments per group
	symlinkMax  uint32
	inodeFormat uint32
	signature   uint32
}

func parseSuperblock(buf []byte) (*superblock, error) {
	var s superblock

	signature := binary.BigEndian.Uint32(buf[1372:1376])
	if signature != ufsMagic {
		return nil, fmt.Errorf("invalid UFS signature %x", signature)
	}

	s.sblkno = binary.BigEndian.Uint32(buf[8:12])
	s.cblkno = binary.BigEndian.Uint32(buf[12:16])
	s.iblkno = binary.BigEndian.Uint32(buf[16:20])
	s.dblkno = binary.BigEndian.Uint32(buf[20:24])
	s.cgoffset = binary.BigEndian.Uint32(buf[24:28])
	s.cgmask = binary.BigEndian.Uint32(buf[28:32])

	s.nfrag = binary.BigEndian.Uint32(buf[36:40])
	s.ngroup = binary.BigEndian.Uint32(buf[44:48])
	s.blocksize = binary.BigEndian.Uint32(buf[48:52])
	s.fragsize = binary.BigEndian.Uint32(buf[52:56])

	s.ipg = binary.BigEndian.Uint32(buf[184:188])
	s.fpg = binary.BigEndian.Uint32(buf[188:192])

	s.symlinkMax = binary.BigEndian.Uint32(buf[1320:1324])
	s.inodeFormat = binary.BigEndian.Uint32(buf[1324:1328])

	s.signature = signature

	if s.inodeFormat != 0xffffffff {
		return nil, fmt.Errorf("unsupported inode format %x", s.inodeFormat)
	}

	return &s, nil
}

func (sb *superblock) groupBase(group int) int {
	return group*int(sb.fpg) + int(sb.cgoffset*(uint32(group) & ^sb.cgmask))
}

func (sb *superblock) sblockno(group int) int {
	return sb.groupBase(group) + int(sb.sblkno)
}

func (sb *superblock) cblockno(group int) int {
	return sb.groupBase(group) + int(sb.cblkno)
}

func (sb *superblock) iblockno(group int) int {
	return sb.groupBase(group) + int(sb.iblkno)
}

func (sb *superblock) dblockno(group int) int {
	return sb.groupBase(group) + int(sb.dblkno)
}

type FS struct {
	r  io.ReaderAt
	sb *superblock
}

func NewFS(r io.ReaderAt) (*FS, error) {
	buf, err := readBytes(r, 8*kb, sbsize)
	if err != nil {
		return nil, fmt.Errorf("error reading superblock: %w", err)
	}

	sb, err := parseSuperblock(buf)
	if err != nil {
		return nil, fmt.Errorf("error parsing superblock: %w", err)
	}

	for i := 0; i < int(sb.ngroup); i++ {
		fmt.Println(sb.sblockno(i))
	}

	return &FS{
		r:  r,
		sb: sb,
	}, nil
}

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <iso9660 image>\n", os.Args[0])
	}

	fname := os.Args[1]

	disk, err := Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer disk.Close()

	fmt.Println(disk.GetPartition(0))
	// fmt.Println(disk.label.frontPorchSectors, disk.label.sectsize, disk.partitions)

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
