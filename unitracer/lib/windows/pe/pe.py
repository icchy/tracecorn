from __future__ import absolute_import

from ctypes import *
from io import BytesIO
from struct import pack, unpack

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

        EntryPoint = nt_header.OptionalHeader.AddressOfEntryPoint
        ImageBase = nt_header.OptionalHeader.ImageBase
        SectionAlignment = nt_header.OptionalHeader.SectionAlignment
        SizeOfImage = nt_header.OptionalHeader.SizeOfImage
        SizeOfHeaders = nt_header.OptionalHeader.SizeOfHeaders

        SizeOfStackReserve = nt_header.OptionalHeader.SizeOfStackReserve
        SizeOfHeapReserve = nt_header.OptionalHeader.SizeOfHeapReserve

        # parse ENTRY_EXPORT
        fp.seek(nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
        export_dir = IMAGE_EXPORT_DIRECTORY()
        assert sizeof(export_dir) == fp.readinto(export_dir), "Invalid IMAGE_EXPORT_DIRECTORY length"
        assert export_dir.NumberOfFunctions == export_dir.NumberOfNames, "NumberOfFunctions != NumberOfNames"

        exports = dict()
        addr_names_dir = export_dir.AddressOfNames
        for i in range(export_dir.NumberOfFunctions):
            addr = self.getaddr(addr_names_dir + (bits/8)*i)
            name = self.getstr(addr)
            exports[name] = addr

        self.exports = exports




    def getstr(self, offset, size=0):
        fp = self.fp
        old_off = fp.tell()
        fp.seek(offset)

        res = ""
        if size > 0:
            res = fp.read(size)
        else:
            while not res.endswith("\x00"):
                res += fp.read(1)
            res = res[:-1]

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
