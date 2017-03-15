from unicorn.x86_const import *

from .util import *


class GDT_32(object):
    def __init__(self, emu, gdt_base, size):
        emu.mem_map(gdt_base, align(size))
        emu.reg_write(UC_X86_REG_GDTR, (0, gdt_base, size, 0x0))
        self.emu = emu
        self.gdt_base = gdt_base

    @staticmethod
    def _gdt_entry(base, limit, flags):
        #  0:15 -> limit 0:15
        # 16:31 -> base 0:15
        # 32:39 -> base 16:23
        # 40:47 -> access
        # 48:51 -> limit 16:19
        # 52:55 -> flags
        # 56:63 -> base 24:31

        entry  = limit & 0xffff
        entry |= (base & 0xffff) << 16
        entry |= ((base >> 16) & 0xff) << 32
        entry |= (flags & 0xff) << 40
        entry |= ((limit >> 16) & 0xf) << 48
        entry |= ((flags >> 8) & 0xf) << 52
        entry |= ((base >> 24) & 0xff) << 56
        return struct.pack("<Q", entry)

    @staticmethod
    def gdt_entry_flags(gr, sz, pr, privl, ex, dc, rw, ac):
        flags =  ac & 1
        flags |= (rw & 1) << 1
        flags |= (dc & 1) << 2
        flags |= (ex & 1) << 3
        flags |= 1 << 4
        flags |= (privl & 0b11) << 5
        flags |= (pr & 1) << 7
        flags |= (sz & 1) << 10
        flags |= (gr & 1) << 11
        return flags

    @staticmethod
    def _seg_selector(index, ti, rpl):
        #  0: 1 -> rpl
        #  2: 2 -> ti
        #  3:15 -> index

        sel  = rpl
        sel |= ti << 2
        sel |= index << 3
        return sel

    def set_entry(self, index, base, limit, flags, ti=0, rpl=3):
        emu = self.emu
        gdt_base = self.gdt_base

        emu.mem_write(gdt_base+index*8, self._gdt_entry(base, limit, flags))
        return self._seg_selector(index, ti, rpl)
