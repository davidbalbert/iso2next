package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"strings"

	"github.com/davidbalbert/iso2next/fsutil"
	"github.com/davidbalbert/iso2next/iso9660"
	"github.com/davidbalbert/iso2next/nextstep"
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

func openfs(r io.ReaderAt) (fs.FS, error) {
	fsys, err := iso9660.NewFS(r)
	if err == nil {
		return fsys, nil
	}

	disk, err := nextstep.NewDisk(r)
	if err != nil {
		return nil, err
	}

	fsys, err = disk.GetPartition(0)
	if err != nil {
		return nil, err
	}
	return fsys, nil
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

	r, err := os.Open(image)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	fsys, err := openfs(r)
	if err != nil {
		log.Fatal(err)
	}

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

	r, err := os.Open(image)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	fsys, err := openfs(r)
	if err != nil {
		log.Fatal(err)
	}

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

	r, err := os.Open(image)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	fsys, err := openfs(r)
	if err != nil {
		log.Fatal(err)
	}

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
			fmt.Print("/" + path + suffix)
		} else {
			fmt.Print(fname + suffix)
		}

		if lflag && dirent.Type() == fs.ModeSymlink {
			link, err := fsutil.ReadLink(fsys, path)
			if err == nil {
				fmt.Print(" -> " + link)
			}
		}
		fmt.Println()

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

	if devinfo, ok := info.(fsutil.DeviceFileInfo); ok && dirent.Type() == fs.ModeDevice {
		dev, err := devinfo.Device()
		if err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf("%d, %d\t", dev.Major(), dev.Minor()))
	} else {
		sb.WriteString(fmt.Sprintf("%d\t", info.Size()))
	}

	return sb.String(), nil
}
