# iso2next

**NOTE: iso2next is not complete. See "Current functionality" for a summary of what works.**

A computer archaeology project: a tool to convert normal (ISO 9660) CD images to NeXT formatted (NeXT disklabel + NeXT's UFS variant) CD images.

## Motivation

[NeXTSTEP 4.0 Beta](http://www.shawcomputing.net/resources/next/software/ns40_screenshots/index.html) (also known as OPENSTEP 4.0 PR1) was seeded to developers between NeXTSTEP 3.3 and OPENSTEP 4.0. The system GUI and the UI of many apps was a significant departure from earlier versions of NeXTSTEP. When OPENSTEP 4.0 was released, these changes had been reverted, though some of them reappeared in early versions of Rhapsody and Mac OS X. It's an interesting piece of computer history.

The Internet Archive has [CD images for NeXTSTEP 4.0 beta](https://archive.org/details/NeXTOSIMAGES), but they are ISO 9660 images, which are not bootable on NeXT hardware. I beleive this is true on Intel as well.

It is still possible to install NeXTSTEP 4.0 beta by upgrading from NeXTSTEP 3.3, but it's not possible to do a clean install. Iso2next is an attempt to remedy that by being able to build a bootable CD image that uses UFS and NeXT's partition table format.

## Current functionality

```
iso2next cat image_file path
iso2next cp image_file source_path destination_path
iso2next ls [-alfrF] image_file path
```

`image_file` can be the path to an ISO 9660 image or a NeXT formatted image.

Help for individual commands is also available, e.g. by running `iso2next ls -help`.

## Supported features

ISO 9660:
- Reading files and directories.
- Rock Ridge (POSIX extensions, long file names), including permissions, symlinks and device nodes.
- Joliet (UTF-16, long file names).

ISOs for UNIX systems like NeXTSTEP generally use Rock Ridge, not Joliet, which is the case here.

NeXT (Disklabel + UFS):
- Reading files and directories.
- Permissions.

## Not yet supported

NeXT (Disklabel + UFS):
- Symbolic links and device nodes.
- Creating partition tables.
- Formatting UFS partitions.
- Directory and file creation.

## License

Iso2next is copyright David Albert and released under the terms of the MIT License.
