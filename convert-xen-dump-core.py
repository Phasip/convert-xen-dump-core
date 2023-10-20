#!/usr/bin/python3
import os
import sys
import array
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment    
# Missing elftools? Run pip3 install pyelftools
    
# Dumps created using xl dump-core .... / xm dump-core

# This minimal tool converts a file in the xen dump-core format
# ( https://xenbits.xenproject.org/docs/unstable/misc/dump-core-format.txt )
# into a raw memory dump. Missing frames are replaced with zeroes

PFN_INVALID = 0xffffffffffffffff
XEN_ELFNOTE_DUMPCORE_NONE = 0x2000000
XEN_ELFNOTE_DUMPCORE_HEADER = 0x2000001
XC_CORE_MAGIC = 0xF00FEBED
XC_CORE_MAGIC_HVM = 0xF00FEBEE

def get_pagesize(elfFile):
    noteSection = elfFile.get_section_by_name(".note.Xen")
    assert(noteSection is not None)
    sections = list(noteSection.iter_notes())
    assert(sections[0].n_type == XEN_ELFNOTE_DUMPCORE_NONE)
    assert(sections[1].n_type == XEN_ELFNOTE_DUMPCORE_HEADER)
    raw_data = sections[1].n_descdata
    
    # struct xen_dumpcore_elfnote_header_desc {
    #         uint64_t    xch_magic;
    #         uint64_t    xch_nr_vcpus;
    #         uint64_t    xch_nr_pages;
    #         uint64_t    xch_page_size;
    # };
    xch_magic,xch_nr_vcpus,xch_nr_pages,xch_page_size =  struct.unpack("<QQQQ",raw_data)
    assert(xch_magic == XC_CORE_MAGIC or xch_magic == XC_CORE_MAGIC_HVM)
    
    # TODO: Verify the dump-core file version to ensure we are not doing things wrong
    return xch_nr_pages, xch_page_size
    
def convert_xen_dump(infile_fd, outfile_fd):
    elfFile = ELFFile(infile_fd)
    assert(elfFile.header['e_type'] == 'ET_CORE')
    num_pages, pagesize = get_pagesize(elfFile)
    pages = elfFile.get_section_by_name(".xen_pages")
    
    # Load list of all frame numbers into memory at once. Unlikely to need optimization
    pfn_map = elfFile.get_section_by_name(".xen_pfn")
    pfn_map_a = array.array("Q")
    pfn_map_a.frombytes(pfn_map.data())
    
    # We don't handle compressed data right now, mainly because we implement the elftools data() ourselves
    # TODO: Update elftools to support returning a stream of decompressed data
    #   https://github.com/eliben/pyelftools/blob/cf814b7adaebb0d336e863d834964b3f4b4e48e1/elftools/elf/sections.py#L71C7-L71C7
    assert(pages.compressed == 0)
    assert(len(pfn_map_a)*pagesize == pages.data_size)
    
    # This would be solved by pages.data() but that returns the whole blob which is too large for our memory
    # instead we seek and read the stream ourselves
    pages_offset = pages.header['sh_offset']
    pages.stream.seek(pages_offset)
    
    offset_at = 0
    for frame_num in pfn_map_a:
        page = pages.stream.read(pagesize)
        assert(len(page) == pagesize)
        if frame_num == PFN_INVALID:
            # TODO: PFN_INVALID should allow us to break
            continue
            
        frame_offset = frame_num*pagesize
        assert(frame_offset >= offset_at)
        if frame_offset > offset_at:
            zeroes = frame_offset-offset_at
            outfile_fd.write(b'\x00'*zeroes)
            offset_at += zeroes
            
        outfile_fd.write(page)
        offset_at += pagesize

def usage_and_exit():
    print(f"Usage: {sys.argv[0]} input-dump-core.elf output-file.raw", file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':        
    if len(sys.argv) != 3:
        usage_and_exit()
        
    infile = sys.argv[1]
    outfile = sys.argv[2]
    
    if os.path.exists(outfile):
        print(f"Error: Not touching existing file {outfile}, use a non-existing path as outfile", file=sys.stderr)
        usage_and_exit()
    
    if not os.path.exists(infile):
        print(f"Error: Could not find input file {infile}.", file=sys.stderr)
        usage_and_exit()
         
    with open(outfile, 'wb') as out:
        with open(infile, 'rb') as elffile:
            convert_xen_dump(elffile, out)
