package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/davidbalbert/iso2next/fsutil"
	"github.com/davidbalbert/iso2next/iso9660"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <iso9660 image>\n", os.Args[0])
	}

	fname := os.Args[1]

	// disk, err := Open(fname)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer disk.Close()

	// fsys, err := disk.GetPartition(0)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	fsys, err := iso9660.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	// f, err := fsys.Open(".")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer f.Close()

	// if f, ok := f.(fs.ReadDirFile); ok {
	// 	dirents, err := f.ReadDir(0)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	for _, dirent := range dirents {
	// 		log.Println(dirent)
	// 	}
	// } else {
	// 	log.Fatal("not a directory")
	// }

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

	// bytes, err := fs.ReadFile(fsys, "NextAdmin/BuildDisk.app/BuildingTile.tiff")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// err = os.WriteFile("./BuildingTile.tiff", bytes, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// info, err := f.Stat()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// if inode, ok := info.(*inode); ok {
	// 	fmt.Println(inode.Name(), inode.ino)
	// 	for i, addr := range(inode.dblocks) {

	// } else {
	// 	log.Fatal("not an inode")
	// }

	err = fs.WalkDir(fsys, ".", func(path string, dirent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := dirent.Info()
		if err != nil {
			return err
		}

		fmt.Printf("%s\t", info.Mode().String())

		if dirent, ok := dirent.(fsutil.DeviceDirEntry); ok && info.Mode()&fs.ModeDevice != 0 {
			dev, err := dirent.GetDevice()
			if err != nil {
				return err
			}

			fmt.Printf("%d, %d\t", dev.Major(), dev.Minor())
		} else {
			fmt.Printf("%d\t", info.Size())
		}

		if path == "." {
			fmt.Print("/")
		} else {
			fmt.Printf("/%s", path)
		}

		if dirent, ok := dirent.(fsutil.ReadlinkDirEntry); ok && info.Mode()&fs.ModeSymlink != 0 {
			target, err := dirent.Readlink()
			if err != nil {
				return err
			}

			fmt.Printf(" -> %s", target)
		}
		fmt.Println()

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
