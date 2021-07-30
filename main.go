package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"

	"github.com/davidbalbert/iso2next/iso9660"
	"golang.org/x/exp/mmap"
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

	fsys, err := iso9660.NewFS(r)
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

		fmt.Printf("%s\t", info.Mode().String())

		if dirent, ok := dirent.(DeviceDirEntry); info.Mode()&fs.ModeDevice != 0 && ok {
			dev, err := dirent.Device()
			if err != nil {
				return err
			}

			fmt.Printf("%d, %d\t", major(dev), minor(dev))
		} else {
			fmt.Printf("%d\t", info.Size())
		}

		if path == "." {
			fmt.Print("/")
		} else {
			fmt.Printf("/%s", path)
		}

		if dirent, ok := dirent.(ReadlinkDirEntry); info.Mode()&fs.ModeSymlink != 0 && ok {
			target, err := dirent.Readlink()
			if err != nil {
				return err
			}

			fmt.Printf(" -> %s", target)
		}

		fmt.Println()

		// if dirent, ok := dirent.(*dirEntry); ok {
		// 	fmt.Print(" [")
		// 	for i, entry := range dirent.systemUseEntries {
		// 		fmt.Print(entry.Tag())

		// 		if i != len(dirent.systemUseEntries)-1 {
		// 			fmt.Print(" ")
		// 		}
		// 	}
		// 	fmt.Println("]")
		// } else {
		// 	fmt.Println()
		// }

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}
