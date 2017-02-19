from __future__ import absolute_import

from ctypes import *
from io import BytesIO
from struct import pack, unpack
import os

from .defines import *


class PE(object):
    def __init__(self, fname):
        fp = open(fname, "rb")
        buf = BytesIO(fp.read())

        self.fname = fname
        self.fp = fp
        self.buf = buf

        self.check()
        self.parse()


    # parse dos header and check bits
    def check(self):
        fp = self.fp

        fp.seek(0)

        # parse dos header
        dos_header = IMAGE_DOS_HEADER()
        assert sizeof(dos_header) == fp.readinto(dos_header), "Invalid DOS header length"
        assert pack("H", dos_header.e_magic) == 'MZ', "Invalid DOS magic"

        # parse nt header
        nt_header = IMAGE_NT_HEADERS32()
        fp.seek(dos_header.e_lfanew)
        assert sizeof(nt_header) == fp.readinto(nt_header), "Invalid PE header length"
        assert pack("I", nt_header.Signature) == 'PE\x00\x00', "Invalid PE magic"

        bits = {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC: 32,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC: 64,
        }[nt_header.OptionalHeader.Magic]

        self.dos_header = dos_header
        self.bits = bits


    # parse header and directories
    def parse(self):
        fp = self.fp
        dos_header = self.dos_header
        bits = self.bits

        nt_header = {
            32: IMAGE_NT_HEADERS32,
            64: IMAGE_NT_HEADERS64,
        }[bits]()

        fp.seek(dos_header.e_lfanew)
        assert sizeof(nt_header) == fp.readinto(nt_header), "Invalid PE header length"

        file_header = nt_header.FileHeader

        # parse sections
        section_headers = list()
        for _ in range(file_header.NumberOfSections):
            section_header = IMAGE_SECTION_HEADER()
            fp.readinto(section_header)
            section_headers.append(section_header)

        for section_header in section_headers:
            print map(chr, section_header.Name)
            print hex(section_header.Misc.PhysicalAddress)
            print hex(section_header.VirtualAddress)

        optional_header = nt_header.OptionalHeader
        entrypoint = optional_header.AddressOfEntryPoint
        imagebase = optional_header.ImageBase
        alignment = optional_header.SectionAlignment
        imagesize = optional_header.SizeOfImage
        headersize = optional_header.SizeOfHeaders
        stacksize = optional_header.SizeOfStackReserve
        heapsize = optional_header.SizeOfHeapReserve

        self.nt_header = nt_header
        self.entrypoint = entrypoint
        self.imagebase = imagebase
        self.alignment = alignment
        self.imagesize = imagesize
        self.headersize = headersize
        self.stacksize = stacksize
        self.heapsize = heapsize

        self.parse_import_directory()
        # if nt_header.FileHeader.Characteristics & IMAGE_FILE_DLL:
        #     self.parse_export_directory()


    def parse_export_directory(self):
        # parse ENTRY_EXPORT
        fp = self.fp
        bits = self.bits
        nt_header = self.nt_header
        DataDirectory = nt_header.OptionalHeader.DataDirectory
        data_directory = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

        fp.seek(data_directory.VirtualAddress)
        export_dir = IMAGE_EXPORT_DIRECTORY()
        assert sizeof(export_dir) == fp.readinto(export_dir), "Invalid IMAGE_EXPORT_DIRECTORY length"
        # assert export_dir.NumberOfFunctions == export_dir.NumberOfNames, "NumberOfFunctions != NumberOfNames"

        exports = dict()
        addr_names_dir = export_dir.AddressOfNames
        for i in range(export_dir.NumberOfFunctions):
            addr = self.getaddr(addr_names_dir + (bits/8)*i)
            name = self.getstr(addr)
            exports[name] = addr

        self.exports = exports


    def parse_import_directory(self):
        fp = self.fp
        bits = self.bits
        nt_header = self.nt_header
        DataDirectory = nt_header.OptionalHeader.DataDirectory
        data_directory = DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

        # parse ENTRY_IMPORT
        print hex(self.imagebase)
        print hex(data_directory.VirtualAddress)
        fp.seek(data_directory.VirtualAddress)
        import_dirs = list()
        while True:
            import_dir = IMAGE_IMPORT_DESCRIPTOR()
            assert sizeof(import_dir) == fp.readinto(import_dir), "Invalid IMAGE_IMPORT_DIRECTORY length"
            if import_dir.Characteristics == 0:
                break
            import_dirs.append(import_dir)

        for import_dir in import_dirs:
            print self.getstr(import_dir.Name)

            # Import Name Table
            fp.seek(import_dir.OriginalFirstThunk)
            thunk_data = {
                32: IMAGE_THUNK_DATA32,
                64: IMAGE_THUNK_DATA64,
            }[bits]()
            fp.readinto(thunk_data)

            offset = thunk_data.u1.AddressOfData
            import_by_name = IMAGE_IMPORT_BY_NAME()
            while True:
                fp.seek(offset)
                fp.readinto(import_by_name)
                offset += 2
                name = self.getstr(offset)
                if not name:
                    break
                print name
                offset += len(name)+1


    def getstr(self, offset, size=0, save=True):
        fp = self.fp
        if save:
            old_off = fp.tell()
        fp.seek(offset)

        res = ""
        if size > 0:
            res = fp.read(size)
        else:
            while not res.endswith("\x00"):
                res += fp.read(1)
            res = res[:-1]

        if save:
            fp.seek(old_off)

        return res

    def getaddr(self, offset):
        fp = self.fp
        old_off = fp.tell()

        fmt, size = {
            32: ("<I", 4),
            64: ("<Q", 8),
        }[self.bits]
        fp.seek(offset)
        res = unpack(fmt, fp.read(size))[0]

        fp.seek(old_off)

        return res
