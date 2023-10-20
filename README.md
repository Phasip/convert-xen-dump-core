# convert-xen-dump-core
Xen can create RAM dumps of virtual machines using the xl dump-core command, however
the file-format in use is uncommon (based on the elf-file format) and not supported by many tools, making forensics harder.

This script takes such dumps and outputs a raw memory dump instead.

## Dependencies
```
pip3 install pyelftools
```

## Howto
1. Create a dump usin xl dump-core command
2. Run `./convert-xen-dump-core.py input-dump-core.elf output-file.raw`

