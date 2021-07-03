package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

const kb = 1024
const sectBytes = 2 * kb

var (
	aChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!\"%&'()*+,-./:;<=>?]*$")
	dChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
)

func contains(s []byte, c byte) bool {
	for _, b := range s {
		if b == c {
			return true
		}
	}

	return false
}

func readStrA(r io.ReaderAt, offset int64, n int) (string, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return "", fmt.Errorf("error reading strA: %w", err)
	}

	for _, c := range buf {
		if !contains(aChars, c) {
			return "", fmt.Errorf("invalid strA: %s", string(buf))
		}
	}

	return string(buf), nil
}

func readStrD(r io.ReaderAt, offset int64, n int) (string, error) {
	buf := make([]byte, n)

	if _, err := r.ReadAt(buf, offset); err != nil {
		return "", fmt.Errorf("error reading strD: %w", err)
	}

	for _, c := range buf {
		if !contains(dChars, c) {
			return "", fmt.Errorf("invalid strD: %s", string(buf))
		}
	}

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
	Type() vType
	typeDescription() string
}

type vdBase struct {
	vType
}

func (vd *vdBase) Type() vType {
	return vd.vType
}

func (vd *vdBase) typeDescription() string {
	switch vd.vType {
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
}

type vdSupplementary struct {
	vdBase
}

type vdPartition struct {
	vdBase
}

func readVDescriptor(r io.ReaderAt, offset int64) (vDescriptor, error) {
	id, err := readStrA(r, offset+1, 5)
	if err != nil {
		return nil, fmt.Errorf("error reading volume identifier: %w", err)
	}

	if id != "CD001" {
		return nil, fmt.Errorf("invalid volume identifier: %s", id)
	}

	typeBuf := make([]byte, 1)
	if _, err := r.ReadAt(typeBuf, offset); err != nil {
		return nil, fmt.Errorf("error reading volume type: %w", err)
	}

	if typeBuf[0] > byte(vtPartition) && typeBuf[0] < byte(vtTerminator) {
		return nil, fmt.Errorf("invalid volume type: %d", typeBuf[0])
	}

	vd := vdBase{vType(typeBuf[0])}
	switch vd.vType {
	case vtBoot:
		return &vdBoot{vd}, nil
	case vtPrimary:
		return readVdPrimary(r, offset)
	case vtSupplementary:
		return &vdSupplementary{vd}, nil
	case vtPartition:
		return &vdPartition{vd}, nil
	default:
		return nil, fmt.Errorf("invalid volume type: %d", typeBuf[0])
	}
}

func readVdPrimary(r io.ReaderAt, offset int64) (*vdPrimary, error) {
	return &vdPrimary{vdBase{vtPrimary}}, nil
}

func eachVolume(r io.ReaderAt, fn func(vd vDescriptor, stop *bool)) error {
	var offset int64 = 16 * sectBytes

	for {
		vd, err := readVDescriptor(r, offset)
		if err != nil {
			return err
		}

		if vd.Type() == vtTerminator {
			break
		}

		stop := false
		fn(vd, &stop)

		if stop {
			break
		}

		offset += sectBytes
	}

	return nil
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

	var primary vDescriptor = nil
	err = eachVolume(f, func(vd vDescriptor, stop *bool) {
		if vd.Type() == vtPrimary {
			primary = vd
			*stop = true
		}
	})

	if err != nil {
		log.Fatalf("error reading %s: %v\n", fname, err)
	}

	if primary != nil {
		fmt.Println(primary.typeDescription())
	}
}
