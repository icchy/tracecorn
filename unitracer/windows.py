from __future__ import absolute_import

from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86_const import *

from .unitracer import Unitracer
from .lib.util import *
from unitracer.lib.windows.pe import *
from unitracer.lib.windows.i386 import *

import sys
import struct
import os

pck32 = p32
upck32 = u32


class Windows(Unitracer):
    ADDRESS = 0x400000
    STACK_BASE  = 0x00d00000
    STACK_LIMIT = 0x00cfd000

    GDT_BASE = 0x0
    GDT_SIZE = 0x1000
    TIB_ADDR = 0x00b7d000
    PEB_ADDR = 0x00b2f000

    DLL_BASE = 0x70000000
    DLL_CUR = DLL_BASE

    dlls = []
    dll_funcs = {}
    hooks = {}

    def __init__(self, os="Windows 7", bits=32, mem_size = 15*1024*1024):
        self.bits = bits
        self.os = os

        assert bits == 32, "currently only 32 bit is supported"

        self.emu = Uc(UC_ARCH_X86, UC_MODE_32)


    def _init_process(self):
        emu = self.emu
        bits = self.bits
        os = self.os

        self.PEB = {
            "Windows NT"        : [PEB_NT,      None],
            "Windows 2000"      : [PEB_2000,    None],
            "Windows XP"        : [PEB_XP,      PEB_XP_64],
            "Windows 2003"      : [PEB_2003,    PEB_2003_64],
            "Windows 2003 R2"   : [PEB_2003_R2, PEB_2003_R2_64],
            "Windows 2008"      : [PEB_2008,    PEB_2008_64],
            "Windows 2008 R2"   : [PEB_2008_R2, PEB_2008_R2_64],
            "Windows 7"         : [PEB_W7,      PEB_W7_64],
        }[os][bits/64]

        self.TEB = {
            "Windows NT"        : [TEB_NT,      None],
            "Windows 2000"      : [TEB_2000,    None],
            "Windows XP"        : [TEB_XP,      TEB_XP_64],
            "Windows 2003"      : [TEB_2003,    TEB_2003_64],
            "Windows 2003 R2"   : [TEB_2003_R2, TEB_2003_R2_64],
            "Windows 2008"      : [TEB_2008,    TEB_2008_64],
            "Windows 2008 R2"   : [TEB_2008_R2, TEB_2008_R2_64],
            "Windows 7"         : [TEB_W7,      TEB_W7_64],
        }[os][bits/64]


        GDT_BASE = self.GDT_BASE
        GDT_SIZE = self.GDT_SIZE
        TIB_ADDR = self.TIB_ADDR
        PEB_ADDR = self.PEB_ADDR
        TEB_ADDR = TIB_ADDR

        if bits == 32:
            # init Thread Information Block
            teb = self.TEB()
            peb = self.PEB()

            ldr = PEB_LDR_DATA()
            ldr_module = LDR_MODULE()


            teb.NtTib.Self = TIB_ADDR
            teb.ProcessEnvironmentBlock = PEB_ADDR

            emu.mem_map(PEB_ADDR, align(sizeof(peb)))
            emu.mem_write(PEB_ADDR, struct2str(peb))

            emu.mem_map(TEB_ADDR, align(sizeof(teb)))
            emu.mem_write(TEB_ADDR, struct2str(teb))


            # init Global Descriptor Table
            gdt = GDT_32(emu, GDT_BASE, GDT_SIZE)

            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=0, privl=0, ex=0, dc=0, rw=1, ac=1) # 0xcf3
            # cs : 0x0023 (index:4)
            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=1, privl=3, ex=1, dc=0, rw=1, ac=1) # 0xcfb
            selector = gdt.set_entry(4, 0x0, 0xffffffff, flags)
            emu.reg_write(UC_X86_REG_CS, selector)

            # ds, es, gs : 0x002b (index:5)
            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1) # 0xcf3
            selector = gdt.set_entry(5, 0x0, 0xffffffff, flags)
            emu.reg_write(UC_X86_REG_DS, selector)
            emu.reg_write(UC_X86_REG_ES, selector)
            emu.reg_write(UC_X86_REG_GS, selector)

            # fs : 0x0053 (index:10)
            flags = GDT_32.gdt_entry_flags(gr=0, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1) # 0x4f3
            selector = gdt.set_entry(10, TIB_ADDR, 0xfff, flags)
            emu.reg_write(UC_X86_REG_FS, selector)

            self.gdt = gdt


    def _init_ldr(self, dlls=None):
        if dlls == None:
            dlls = ["ntdll.dll", "kernel32.dll", "KernelBase.dll"]

        for dll in dlls:
            fname = os.path.join("dll", dll)
            if not os.path.exists(fname):
                print >> sys.stderr, "{} does not exist".format(dll)
            base = self.load_dll(fname)


    def load_dll(self, dllname):
        dlls = self.dlls
        emu = self.emu
        base = self.DLL_CUR

        dlldata = self._load_dll(dllname, base)
        size = align(len(dlldata))
        emu.mem_map(base, size)
        emu.mem_write(base, dlldata)
        dlls.append([dllname, base])
        self.DLL_CUR += size

        return base


    def _load_dll(self, dllname, base):
        dll_funcs = self.dll_funcs

        path = os.path.join("dll", dllname)
        dll = PE(path)
        data = bytearray(dll.mapped_data)
        for name, addr in dll.exports.items():
            data[addr] = '\xc3'
            dll_funcs[base + addr] = name

        return str(data)


    def _hook_code(self, uc, address, size, userdata):
        hooks = self.hooks
        dll_funcs = self.dll_funcs

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        code = uc.mem_read(address, size)
        asm = md.disasm(str(code), address)
        esp = uc.reg_read(UC_X86_REG_ESP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        edx = uc.reg_read(UC_X86_REG_EDX)

        for a in asm:
            print('0x%x: \t%s\t%s' % (a.address, a.mnemonic, a.op_str))

        if eip in dll_funcs:
            func = dll_funcs[eip]
            if func in hooks.keys():
                hooks[func](eip, esp, uc)
            else:
                print("unhooked function: {}".format(func))


    def load_code(self, data):
        emu = self.emu
        ADDRESS = self.ADDRESS

        self.size = len(data)
        self._init_process()

        # map shellcode
        emu.mem_map(ADDRESS, align(len(data)))
        emu.mem_write(ADDRESS, data)
        emu.reg_write(UC_X86_REG_EIP, ADDRESS)

        # mu.hook_add(UC_HOOK_CODE, self._hook_code, None, DLL_BASE, DLL_BASE + 6 * PageSize)
        emu.hook_add(UC_HOOK_CODE, self._hook_code)


    def laod_pe(self, fname):
        emu = self.emu
        ADDRESS = self.ADDRESS

        pe = PE(fname)


    def start(self, offset):
        entry = self.ADDRESS + offset
        self.emu.emu_start(entry, entry + self.size)

