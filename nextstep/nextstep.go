package nextstep

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"
)

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

func NewDisk(r io.ReaderAt) (*Disk, error) {
	label, err := readDiskLabel(r)
	if err != nil {
		return nil, err
	}

	offset := partitionTableOffset
	var partitions []partition
	for i := 0; i < maxPartitions; i++ {
		buf, err := readBytes(r, offset, partitionEntrySize)
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
		r:          r,
		label:      label,
		partitions: partitions,
	}, nil
}

func (d *Disk) NPart() int {
	return len(d.partitions)
}

func (d *Disk) GetPartition(i int) (fs.FS, error) {
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

const (
	ufsMagic uint32 = 0x011954
	sbsize   int    = 1376
)

type superblock struct {
	sblkno    uint32
	cblkno    uint32
	iblkno    uint32
	dblkno    uint32
	cgoffset  uint32
	cgmask    uint32
	nfrag     uint32
	ngroup    uint32
	blocksize uint32
	fragsize  uint32
	fpb       uint32 // fragments per block

	ipb uint32 // inodes per block

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
	s.fpb = binary.BigEndian.Uint32(buf[56:60])

	s.ipb = binary.BigEndian.Uint32(buf[120:124])

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

func (sb *superblock) groupBase(group uint32) uint32 {
	return group*sb.fpg + sb.cgoffset*(group & ^sb.cgmask)
}

func (sb *superblock) sblockno(group uint32) uint32 {
	return sb.groupBase(group) + sb.sblkno
}

func (sb *superblock) cblockno(group uint32) uint32 {
	return sb.groupBase(group) + sb.cblkno
}

func (sb *superblock) iblockno(group uint32) uint32 {
	return sb.groupBase(group) + sb.iblkno
}

func (sb *superblock) dblockno(group uint32) uint32 {
	return sb.groupBase(group) + sb.dblkno
}

type nextfs struct {
	r  io.ReaderAt
	sb *superblock
}

func NewFS(r io.ReaderAt) (fs.FS, error) {
	buf, err := readBytes(r, 8*kb, sbsize)
	if err != nil {
		return nil, fmt.Errorf("error reading superblock: %w", err)
	}

	sb, err := parseSuperblock(buf)
	if err != nil {
		return nil, fmt.Errorf("error parsing superblock: %w", err)
	}

	return &nextfs{
		r:  r,
		sb: sb,
	}, nil
}

func (fsys *nextfs) readInode(ino uint32, name string) (*inode, error) {
	if ino > fsys.sb.ipg*fsys.sb.ngroup {
		return nil, fmt.Errorf("invalid inode number %d", ino)
	}

	group := ino / fsys.sb.ipg
	first := group * fsys.sb.ipg
	ipf := fsys.sb.ipb / fsys.sb.fpb
	frag := fsys.sb.iblockno(group) + (ino-first)/ipf

	offset := int64(frag)*int64(fsys.sb.fragsize) + int64(ino%ipf)*int64(inodeSize)

	buf, err := readBytes(fsys.r, offset, inodeSize)
	if err != nil {
		return nil, fmt.Errorf("can't read inode: %w", err)
	}

	inode := parseInode(buf, name, ino, fsys)

	return inode, nil
}

func (fsys *nextfs) walk(name string) (*inode, error) {
	pathComponents := strings.Split(name, "/")

	if pathComponents[0] == "." {
		pathComponents = pathComponents[1:]
	}

	inode, err := fsys.readInode(rootInode, ".")
	if err != nil {
		return nil, fmt.Errorf("error reading root inode: %w", err)
	}

	for i, component := range pathComponents {
		last := i == len(pathComponents)-1

		f := newFile(fsys, inode)
		for {
			children, err := f.ReadDir(1)
			if err == io.EOF {
				return nil, fs.ErrNotExist
			} else if err != nil {
				return nil, err
			}

			child, ok := children[0].(*dirEntry)
			if !ok {
				return nil, fmt.Errorf("unexpected directory entry type %T", children[0])
			}

			if child.Name() == component {
				// For new-format directory entries, we need to read the inode here
				inode = child.inode
				break
			}
		}

		if !last && !inode.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", component)
		}
	}

	return inode, nil
}

func (fsys *nextfs) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	inode, err := fsys.walk(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}

	return newFile(fsys, inode), nil
}

type dirEntry struct {
	inode *inode

	ino uint32
	len uint16

	// 4.4 BSD uses half of the namlen field for filetype.
	// NeXTSTEP uses the older dirent format that has a 2 byte
	// namlen, even though we shouldn't expect to same names
	// longer than 255 bytes. We use the old format.
	//
	// If we ever support the new format, the File System
	// Forensic Analysis book has namelen coming before
	// filetype, but the Linux source and the NetBSD source
	// have filetype before namelen. The book is probably wrong.
	// implement it like this:
	//
	// filetype byte
	// nameLen byte
	nameLen uint16

	name string
}

func (fsys *nextfs) readDirEntry(r io.ReaderAt, offset int64) (*dirEntry, error) {
	buf, err := readBytes(r, offset+6, 2)
	if err != nil {
		return nil, fmt.Errorf("can't read directory entry name length: %w", err)
	}

	nameLen := binary.BigEndian.Uint16(buf)

	buf, err = readBytes(r, offset, 8+int(nameLen))
	if err != nil {
		return nil, fmt.Errorf("can't read directory entry: %w", err)
	}

	dirent := parseDirEntry(buf)

	// NeXTSTEP's UFS uses the old directory entry format, which doesn't
	// include file type. Because fs.DirEntry has a Type() method, we have
	// to read the inode so that we can get the type. This is unfortunate.
	//
	// If we ever add support for the new-format directory entries, we can
	// return early without reading the inode.

	ip, err := fsys.readInode(dirent.ino, dirent.name)
	if err != nil {
		return nil, err
	}

	dirent.inode = ip

	return dirent, nil
}

func parseDirEntry(buf []byte) *dirEntry {
	nameLen := binary.BigEndian.Uint16(buf[6:8])

	return &dirEntry{
		ino:     binary.BigEndian.Uint32(buf[0:4]),
		len:     binary.BigEndian.Uint16(buf[4:6]),
		nameLen: nameLen,
		name:    string(buf[8 : 8+int(nameLen)]),
	}
}

func (d *dirEntry) Info() (fs.FileInfo, error) {
	// If we add support for new-format directory entries, we can
	// delay reading of the inode until here. Something like
	//
	// if d.inode == nil {
	// 	d.inode, err := fsys.readInode(d.ino, d.name)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// }

	return d.inode, nil
}

func (d *dirEntry) IsDir() bool {
	return d.inode.IsDir()
}

func (d *dirEntry) Name() string {
	return d.name
}

func (d *dirEntry) Type() fs.FileMode {
	return d.inode.Mode().Type()
}

type file struct {
	fsys *nextfs
	*inode
	offset int64
}

func newFile(fsys *nextfs, ip *inode) *file {
	return &file{
		fsys:   fsys,
		inode:  ip,
		offset: 0,
	}
}

func (f *file) Read(p []byte) (int, error) {
	if f.inode.IsDir() {
		return 0, fmt.Errorf("can't call Read on a directory")
	}

	if len(p) == 0 {
		return 0, nil
	} else if f.offset >= f.inode.Size() {
		return 0, io.EOF
	}

	n, err := f.inode.ReadAt(p, f.offset)
	f.offset += int64(n)

	return n, err
}

func (f *file) ReadDir(n int) ([]fs.DirEntry, error) {
	if !f.inode.IsDir() {
		return nil, fmt.Errorf("can't call ReadDir on a file")
	}

	var entries []fs.DirEntry
	if n > 0 {
		entries = make([]fs.DirEntry, 0, n)
	} else {
		entries = make([]fs.DirEntry, 0, 100)
	}

	for len(entries) < n || n <= 0 {
		if f.offset >= f.inode.Size() {
			break
		}

		dirent, err := f.fsys.readDirEntry(f.inode, f.offset)
		if err != nil {
			return entries, err
		}

		f.offset += int64(dirent.len)

		if dirent.name == "." || dirent.name == ".." {
			continue
		}

		entries = append(entries, dirent)
	}

	if n > 0 && len(entries) == 0 {
		return nil, io.EOF
	}

	return entries, nil
}

func (f *file) Stat() (fs.FileInfo, error) {
	return f.inode, nil
}

func (f *file) Close() error {
	return nil
}

const (
	inodeSize = 128
	ndirect   = 12
	rootInode = 2
)

type inode struct {
	name string
	ino  uint32
	fsys *nextfs

	mode      uint16
	nlink     uint16
	size      uint64
	atime     uint32 // access time
	atimensec uint32
	mtime     uint32 // modification time
	mtimensec uint32
	ctime     uint32 // metadata change time
	ctimensec uint32

	// 12 direct block pointers followed by indirect,
	// double indirect, and triple indirect block
	// pointers.
	addrs [ndirect + 3]uint32

	flags      uint32
	blocksHeld uint32
	gen        int32
	uid        uint32
	gid        uint32
}

func parseInode(buf []byte, name string, ino uint32, fsys *nextfs) *inode {
	var inode inode

	inode.name = name
	inode.ino = ino
	inode.fsys = fsys

	inode.mode = binary.BigEndian.Uint16(buf[0:2])
	inode.nlink = binary.BigEndian.Uint16(buf[2:4])
	inode.size = binary.BigEndian.Uint64(buf[8:16])
	inode.atime = binary.BigEndian.Uint32(buf[16:20])
	inode.atimensec = binary.BigEndian.Uint32(buf[20:24])
	inode.mtime = binary.BigEndian.Uint32(buf[24:28])
	inode.mtimensec = binary.BigEndian.Uint32(buf[28:32])
	inode.ctime = binary.BigEndian.Uint32(buf[32:36])
	inode.ctimensec = binary.BigEndian.Uint32(buf[36:40])

	for i := 0; i < ndirect+3; i++ {
		addr := binary.BigEndian.Uint32(buf[40+i*4 : 44+i*4])
		inode.addrs[i] = addr
	}

	inode.flags = binary.BigEndian.Uint32(buf[100:104])
	inode.blocksHeld = binary.BigEndian.Uint32(buf[104:108])
	inode.gen = int32(binary.BigEndian.Uint32(buf[108:112]))
	inode.uid = binary.BigEndian.Uint32(buf[112:116])
	inode.gid = binary.BigEndian.Uint32(buf[116:120])

	return &inode
}

func (ip *inode) Size() int64 {
	return int64(ip.size)
}

func (ip *inode) ModTime() time.Time {
	return time.Unix(int64(ip.mtime), int64(ip.mtimensec))
}

const (
	imSticky  uint16 = 0x200
	imSgid    uint16 = 0x400
	imSuid    uint16 = 0x800
	imFifo    uint16 = 0x1000
	imChar    uint16 = 0x2000
	imDir     uint16 = 0x4000
	imBlock   uint16 = 0x6000
	imFile    uint16 = 0x8000
	imSymlink uint16 = 0xa000
	imSocket  uint16 = 0xc000
)

func (ip *inode) Mode() fs.FileMode {
	mode := fs.FileMode(ip.mode & 0777)

	if ip.mode&imSticky == imSticky {
		mode |= fs.ModeSticky
	}
	if ip.mode&imSgid == imSgid {
		mode |= fs.ModeSetgid
	}
	if ip.mode&imSuid == imSuid {
		mode |= fs.ModeSetuid
	}

	if ip.mode&imSocket == imSocket {
		mode |= fs.ModeSocket
	} else if ip.mode&imSymlink == imSymlink {
		mode |= fs.ModeSymlink
	} else if ip.mode&imBlock == imBlock {
		mode |= fs.ModeDevice
	} else if ip.mode&imDir == imDir {
		mode |= fs.ModeDir
	} else if ip.mode&imChar == imChar {
		mode |= fs.ModeCharDevice | fs.ModeDevice
	} else if ip.mode&imFifo == imFifo {
		mode |= fs.ModeNamedPipe
	} else if ip.mode&imFile != imFile {
		mode |= fs.ModeIrregular
	}

	return mode
}

func (ip *inode) IsDir() bool {
	return ip.Mode().IsDir()
}

func (ip *inode) Name() string {
	return ip.name
}

func (ip *inode) Sys() interface{} {
	return nil
}

func pow(x, y uint32) uint32 {
	res := uint32(1)

	for y > 0 {
		res *= x
		y -= 1
	}

	return res
}

// Maps a logical block number in a file to a physical
// block number on disk. Logical block numbers are
// consecutive (0, 1, 2, 3, etc.) while physical block
// numbers are numbered by their associated fragment
// (0, 4, 8, 12, etc. for 4 fragments per block).
func (ip *inode) bmap(idx uint32) (uint32, error) {
	apb := ip.fsys.sb.blocksize / 4 // addrs per block

	nindirect := pow(apb, 1) + pow(apb, 2) + pow(apb, 3)

	if idx < 0 || idx >= ndirect+nindirect {
		return 0, fmt.Errorf("inode %d: indirect block index %d out of range", ip.ino, idx)
	}

	if idx < ndirect {
		return ip.addrs[idx], nil
	}

	idx -= ndirect

	fragsize := int64(ip.fsys.sb.fragsize)

	var level int
	if idx < apb {
		level = 0
	} else if idx < pow(apb, 2) {
		level = 1
		idx -= apb
	} else {
		level = 2
		idx -= pow(apb, 2)
	}

	addr := ip.addrs[ndirect+level]

	for level >= 0 {
		// If an indirect block address is 0, is this an error, or does
		// this indicate that pow(addrsPerBlock, level) blocks are all sparse?
		//
		// For now, we assume it marks all the blocks as sparse.
		if addr == 0 {
			return 0, nil
		}

		offset := int64(addr)*fragsize + int64(idx/pow(apb, uint32(level)))*4

		buf, err := readBytes(ip.fsys.r, offset, 4)
		if err != nil {
			return 0, fmt.Errorf("inode %d: read indirect block failed: %v", ip.ino, err)
		}

		addr = binary.BigEndian.Uint32(buf)
		level -= 1
	}

	return addr, nil
}

func (ip *inode) printBlocks() error {
	blocksize := int64(ip.fsys.sb.blocksize)
	fragsize := int64(ip.fsys.sb.fragsize)
	fpb := int(ip.fsys.sb.fpb)

	for offset := int64(0); offset < ip.Size(); offset += blocksize {

		addr, err := ip.bmap(uint32(offset / blocksize))
		if err != nil {
			return err
		}

		fragsLeft := ceil(ip.Size()-offset, fragsize) / fragsize
		nfrag := min(int(fragsLeft), fpb)

		for j := 0; j < nfrag; j++ {
			fmt.Printf("%d ", int(addr)+j)
		}

		if (offset/blocksize)%2 == 1 {
			fmt.Println()
		}
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func ceil(n, m int64) int64 {
	return m * ((n + (m - 1)) / m)
}

func (ip *inode) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= ip.Size() {
		return 0, io.EOF
	}

	if off+int64(len(p)) > ip.Size() {
		p = p[:ip.Size()-off]
		err = io.EOF
	}

	blocksize := int64(ip.fsys.sb.blocksize)
	fragsize := int64(ip.fsys.sb.fragsize)

	for n < len(p) {
		addr, err := ip.bmap(uint32(off / blocksize))
		if err != nil {
			return n, err
		}

		toRead := min(int(blocksize), len(p)-n)

		m, err := ip.fsys.r.ReadAt(p[n:n+toRead], int64(addr)*fragsize+(off%blocksize))
		n += m

		if err != nil {
			return n, err
		}

		off += int64(m)
	}

	return n, err
}
