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
            IMAGE_FILE_MACHINE_I386:    32,
            IMAGE_FILE_MACHINE_IA64:    64,
            IMAGE_FILE_MACHINE_AMD64:   64,
        }[nt_header.OptionalHeader.Magic]

        if bits == 64:
            # reload nt header as 64 bit
            fp.seek(dos_header.e_lfanew)
            del(nt_header)
            nt_header = IMAGE_NT_HEADERS64()
            assert sizeof(nt_header) == fp.readinto(nt_header), "Invalid PE header length"



