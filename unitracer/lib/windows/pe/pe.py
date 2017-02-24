from __future__ import absolute_import

from ctypes import *
from io import BytesIO
from struct import pack, unpack
import os

from .defines import *


MAX_DLL_NAME_LENGTH = 0x200
MAX_IMPORT_NAME_LENGTH = 0x200


class PE(object):
    def __init__(self, fname):
        fp = open(fname, "rb")

        self.fname = fname
        self.fp = fp

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

        # check characteristics
        assert nt_header.FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE, "Only exe and dll are supported"

        bits = {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC: 32,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC: 64,
        }[nt_header.OptionalHeader.Magic]

        self.dos_header = dos_header
        self.bits = bits
        self.isdll = nt_header.FileHeader.Characteristics & IMAGE_FILE_DLL


    # parse header and directories
    def parse(self):
        fp = self.fp
        dos_header = self.dos_header
        bits = self.bits
        isdll = self.isdll

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
            fp.seek(section_header.PointerToRawData)
            data = fp.read(section_header.Misc.VirtualSize)
            section_header.data = data

        optional_header = nt_header.OptionalHeader
        entrypoint = optional_header.AddressOfEntryPoint
        imagebase = optional_header.ImageBase
        alignment = optional_header.SectionAlignment
        imagesize = optional_header.SizeOfImage
        headersize = optional_header.SizeOfHeaders
        stacksize = optional_header.SizeOfStackReserve
        heapsize = optional_header.SizeOfHeapReserve

        self.entrypoint = entrypoint
        self.imagebase = imagebase
        self.alignment = alignment
        self.imagesize = imagesize
        self.headersize = headersize
        self.stacksize = stacksize
        self.heapsize = heapsize

        self.nt_header = nt_header
        self.section_headers = section_headers

        self.map_data()

        self.parse_import_directory()
        if isdll:
            self.parse_export_directory()


    def map_data(self):
        fp = self.fp
        section_headers = self.section_headers
        assert section_headers is not None, "No sections found"

        size = max(map(lambda x:x.VirtualAddress+x.SizeOfRawData, section_headers))
        mapped = BytesIO("\x00"*size)

        # map from head of file to tail of sections
        struct2str = lambda x:BytesIO(x).read()
        dos_header = self.dos_header
        nt_header = self.nt_header

        mapped.seek(0)
        mapped.write(struct2str(dos_header))
        mapped.write(struct2str(nt_header))
        for sh in section_headers:
            mapped.write(struct2str(sh))

        # map section data
        for sh in section_headers:
            mapped.seek(sh.VirtualAddress)
            fp.seek(sh.PointerToRawData)
            mapped.write(fp.read(sh.Misc.VirtualSize))

        self.mapped = mapped


    # parse ENTRY_EXPORT
    def parse_export_directory(self):
        fp = self.mapped
        bits = self.bits
        nt_header = self.nt_header
        DataDirectory = nt_header.OptionalHeader.DataDirectory
        data_directory = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        getstr = self.getstr
        getaddr = self.getaddr
        getint = self.getint

        fp.seek(data_directory.VirtualAddress)
        export_dir = IMAGE_EXPORT_DIRECTORY()
        assert sizeof(export_dir) == fp.readinto(export_dir), "Invalid IMAGE_EXPORT_DIRECTORY length"
        # assert export_dir.NumberOfFunctions == export_dir.NumberOfNames, "NumberOfFunctions != NumberOfNames"

        exports = dict()

        addr_names = export_dir.AddressOfNames
        addr_funcs = export_dir.AddressOfFunctions
        addr_ordinals = export_dir.AddressOfNameOrdinals

        infos = list()
        for i in range(export_dir.NumberOfNames):
            addr = getaddr(addr_funcs + (bits/8)*i, isrva=True)
            name = getstr(getaddr(addr_names + (bits/8)*i, isrva=True), isrva=True)
            ordinal = getint(addr_ordinals + 2*i, 2, isrva=True)
            infos.append([addr, name, ordinal])

        for addr, name, ordinal in infos:
            exports[name] = infos[ordinal][0]

        self.exports = exports


    def parse_import_directory(self):
        fp = self.mapped
        bits = self.bits
        nt_header = self.nt_header
        DataDirectory = nt_header.OptionalHeader.DataDirectory
        data_directory = DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        getstr = self.getstr
        load_cdata = self._load_cdata

        imports = dict()

        # parse ENTRY_IMPORT
        fp.seek(data_directory.VirtualAddress)
        import_dirs = list()
        while True:
            import_dir = IMAGE_IMPORT_DESCRIPTOR()
            assert sizeof(import_dir) == fp.readinto(import_dir), "Invalid IMAGE_IMPORT_DIRECTORY length"
            if import_dir.Characteristics == 0:
                break
            import_dirs.append(import_dir)


        for import_dir in import_dirs:
            dllname = getstr(import_dir.Name, isrva=True)
            imports[dllname] = dict()

            import_by_name = IMAGE_IMPORT_BY_NAME()

            # # Import Name Table (currently unused)
            # ## array of pointers to IMAGE_IMPORT_BY_NAME
            # fp.seek(v2p(import_dir.OriginalFirstThunk))
            # p = DWORD()
            # while True:
            #     fp.readinto(p)
            #     if p.value == 0:
            #         break
            #     load_cdata(v2p(p.value), import_by_name)


            # Import Address Table
            thunk_data = {
                32: IMAGE_THUNK_DATA32,
                64: IMAGE_THUNK_DATA64,
            }[bits]()

            fp.seek(import_dir.FirstThunk)
            while True:
                vaddr = self.imagebase + fp.tell()
                fp.readinto(thunk_data)

                # end of thunk_data
                if thunk_data.u1.AddressOfData == 0:
                    break
                # the data is ordinal
                if thunk_data.u1.Ordinal & 0x80000000:
                    break

                load_cdata(thunk_data.u1.AddressOfData, import_by_name, isrva=True)
                imports[dllname][import_by_name.Name] = vaddr

        self.imports = imports



    def _load_cdata(self, offset, c_data, isrva=False, check=True):
        if not isrva:
            fp = self.fp
        else:
            fp = self.mapped

        save = fp.tell()
        fp.seek(offset)
        assert sizeof(c_data) == fp.readinto(c_data) and check, "Invalid length loaded"
        fp.seek(save)


    def v2p(self, addr):
        section_headers = self.section_headers
        assert section_headers is not None, "No sections found"

        for sh in section_headers:
            offset = addr - sh.VirtualAddress
            if 0 <= offset < sh.SizeOfRawData: # aligned address (Virtual)
                return sh.PointerToRawData + offset

        raise Exception, "No suitable section found"


    def p2v(self, addr):
        section_headers = self.section_headers
        assert section_headers is not None, "No sections found"

        for sh in section_headers:
            offset = addr - sh.PointerToRawData
            if 0 <= offset < sh.SizeOfRawData:
                return sh.VirtualAddress + offset


    def getstr(self, offset, size=0, isrva=False):
        if not isrva:
            fp = self.fp
        else:
            fp = self.mapped

        save = fp.tell()
        fp.seek(offset)

        res = ""
        if size > 0:
            res = fp.read(size)
        else:
            while not res.endswith("\x00"):
                res += fp.read(1)
            res = res[:-1]

        fp.seek(save)

        return res


    def getaddr(self, offset, isrva=False):
        if not isrva:
            fp = self.fp
        else:
            fp = self.mapped

        save = fp.tell()

        fmt, size = {
            32: ("<I", 4),
            64: ("<Q", 8),
        }[self.bits]
        fp.seek(offset)
        res = unpack(fmt, fp.read(size))[0]

        fp.seek(save)

        return res


    def getint(self, offset, size, isrva=False):
        if not isrva:
            fp = self.fp
        else:
            fp = self.mapped

        save = fp.tell()

        fmt, size = {
            1: ("<B", 1),
            2: ("<H", 2),
            4: ("<I", 4),
            8: ("<Q", 8),
        }[size]
        fp.seek(offset)
        res = unpack(fmt, fp.read(size))[0]

        fp.seek(save)

        return res
