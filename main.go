package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"

	"github.com/davidbalbert/iso2next/fsutil"
	"github.com/davidbalbert/iso2next/iso9660"
)

func usage() {
	progname := os.Args[0]

	fmt.Printf("Usage: %s <command> [options] [args]\n", progname)
	fmt.Printf("Commands:\n")
	fmt.Printf("  %s cat image_file path\n", progname)
	fmt.Printf("  %s cp image_file source_path destination_path\n", progname)
	fmt.Printf("  %s ls [-alfrF] image_file path\n", progname)
}

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "cat":
		cat()
	case "cp":
		cp()
	case "ls":
		ls()
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func cat() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s cat image_file path\n", os.Args[0])
		os.Exit(1)
	}

	image := os.Args[2]
	path := os.Args[3]

	path = strings.TrimPrefix(path, "/")
	if path == "" {
		path = "."
	}

	fsys, err := iso9660.Open(image)
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	bytes, err := fs.ReadFile(fsys, path)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(string(bytes))
}

func cp() {
	if len(os.Args) != 5 {
		fmt.Printf("Usage: %s cp image_file source_path destination_path\n", os.Args[0])
		os.Exit(1)
	}

	image := os.Args[2]
	srcPath := os.Args[3]
	dstPath := os.Args[4]

	srcPath = strings.TrimPrefix(srcPath, "/")
	if srcPath == "" {
		srcPath = "."
	}

	fsys, err := iso9660.Open(image)
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	bytes, err := fs.ReadFile(fsys, srcPath)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(dstPath, bytes, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func ls() {
	flags := flag.NewFlagSet("ls", flag.ExitOnError)

	var aflag, lflag, fflag, Fflag, rflag bool

	flags.BoolVar(&aflag, "a", false, "Show hidden files")
	flags.BoolVar(&lflag, "l", false, "List files in long format")
	flags.BoolVar(&fflag, "f", false, "Show full paths")
	flags.BoolVar(&Fflag, "F", false, "Display identifying character after file name for special files")
	flags.BoolVar(&rflag, "r", false, "Recursively list subdirectories (implies -f)")

	err := flags.Parse(os.Args[2:])
	if err == flag.ErrHelp {
		fmt.Printf("Usage: %s ls [-alfr] image_file path\n", os.Args[0])
		flags.PrintDefaults()
		os.Exit(0)
	} else if err != nil {
		log.Fatal(err)
	}

	if rflag {
		fflag = true
	}

	if flags.NArg() < 2 {
		fmt.Printf("Usage: %s ls [-alfr] image_file path\n", os.Args[0])
		flags.PrintDefaults()
		os.Exit(1)
	}

	image := flags.Arg(0)
	rootPath := flags.Arg(1)

	rootPath = strings.TrimPrefix(rootPath, "/")
	if rootPath == "" {
		rootPath = "."
	}

	fsys, err := iso9660.Open(image)
	if err != nil {
		log.Fatal(err)
	}
	defer fsys.Close()

	err = fs.WalkDir(fsys, rootPath, func(path string, dirent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if path == rootPath && dirent.IsDir() && !rflag {
			return nil
		}

		// At this point, if path is ".", rflag must be true, because the only way to get
		// path == "." is for rootPath == "." as well.
		if path == "." {
			if lflag {
				meta, err := formatMetadata(dirent)
				if err != nil {
					return err
				}

				fmt.Print(meta)
			}
			fmt.Println("/")
			return nil
		}

		skipPrint := path != rootPath && !aflag && strings.HasPrefix(dirent.Name(), ".")
		skipChildren := dirent.IsDir() && (!rflag || (!aflag && strings.HasPrefix(dirent.Name(), ".")))

		if skipPrint {
			if skipChildren {
				return fs.SkipDir
			}
			return nil
		}

		if lflag {
			meta, err := formatMetadata(dirent)
			if err != nil {
				return err
			}

			fmt.Print(meta)
		}

		fname := dirent.Name()
		if !rflag && path == rootPath && dirent.IsDir() {
			fname = "."
		}

		suffix := ""
		if Fflag {
			switch dirent.Type() {
			case fs.ModeDir:
				suffix = "/"
			case fs.ModeSymlink:
				suffix = "@"
			case fs.ModeSocket:
				suffix = "="
			case fs.ModeNamedPipe:
				suffix = "|"
			}
		}

		if fflag {
			fmt.Println("/" + path + suffix)
		} else {
			fmt.Println(fname + suffix)
		}

		if skipChildren {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
}

func formatMetadata(dirent fs.DirEntry) (string, error) {
	var sb strings.Builder

	info, err := dirent.Info()
	if err != nil {
		return "", err
	}

	sb.WriteString(info.Mode().String())
	sb.WriteString("\t")

	if info, ok := info.(fsutil.DeviceFileInfo); ok && dirent.Type() == fs.ModeDevice {
		dev, err := info.Device()
		if err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("%d, %d\t", dev.Major(), dev.Minor()))
	} else {
		sb.WriteString(fmt.Sprintf("%d\t", info.Size()))
	}

	return sb.String(), nil
}
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

		if info, ok := info.(fsutil.DeviceFileInfo); ok && dirent.Type() == fs.ModeDevice {
			dev, err := info.Device()
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

		if dirent.Type() == fs.ModeSymlink {
			target, err := fsutil.ReadLink(fsys, path)
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
