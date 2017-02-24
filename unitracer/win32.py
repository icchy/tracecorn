from __future__ import absolute_import

from unicorn import *
from unicorn.x86_const import *

from capstone import *
from capstone.x86_const import *

from .unitracer import Unitracer
from util import *

import sys
import pefile
import struct
import os

pck32 = p32
upck32 = u32


class Win32(Unitracer):
    bits = 32

    FS = 0x1000
    PEB_ADD = 0x3000
    TEB_ADD = 0x6000
    LDR_ADD1 = 0x9000
    LDR_ADD2 = 0xB000
    LDR_ADD3 = 0xE000
    LDR_ADD4 = 0xF000
    PEB_LDR_ADD = 0x13000
    STACK_BASE = 0x30000
    STACK_LIMIT = 0x1000
    ADDRESS = 0x400000

    DLL_BASE = 0x550000
    DLL_CUR = DLL_BASE

    dlls = []
    dll_funcs = {}
    hooks = {}

    def __init__(self, mem_size = 15*1024*1024):
        self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
        emu = self.emu
        emu.mem_map(self.FS, mem_size)
        self.emu_init(emu)


    def emu_init(self, emu):
        DLL_BASE = self.DLL_BASE
        pack = self.pack
        unpack = self.unpack

        try:
            # init FS
            fss = x86_OS().init_FS()
            emu.mem_write(self.FS, fss)
            emu.reg_write(UC_X86_REG_FS, self.FS)

            # load dll
            kernel32_base = self.load_dll("kernel32.dll")

            # Initialize PEB, TIB, LDR, etc.
            TIB = self.FS
            PEB = TIB + 0x30
            LDR = PEB + 0x0C
            InInitOrder = LDR + 0x1C
            BaseName = InInitOrder + 0x20
            # map PEB & LDR Structure to memory
            emu.mem_write(PEB, pack(PEB))
            emu.mem_write(LDR, pack(LDR))
            emu.mem_write(InInitOrder, pack(InInitOrder))
            emu.mem_write(InInitOrder + 8, pack(kernel32_base))
            emu.mem_write(BaseName, pack(BaseName + 4))
            emu.mem_write(BaseName + 4, "kernelkernel32.dll")

            # Initialize stack of emulator
            emu.reg_write(UC_X86_REG_EBP, STACK_BASE)
            emu.reg_write(UC_X86_REG_ESP, STACK_BASE)

        except UcError as e:
            print("ERROR: %s" % e)


    def load_dll(self, dllname):
        dlls = self.dlls
        emu = self.emu
        base = self.DLL_CUR

        dlldata = self._load_dll(dllname, base)
        size = (len(dlldata) + 0x1000) & 0xfffff000
        emu.mem_map(base, size)
        emu.mem_write(base, dlldata)
        dlls.append([dllname, base])
        self.DLL_CUR += size

        return base


    def _load_dll(self, dllname, base):
        dll_funcs = self.dll_funcs

        path = os.path.join("dll", dllname)
        dll = pefile.PE(path, fast_load=True)
        dll.parse_data_directories()
        data = bytearray(dll.get_memory_mapped_image())
        for ent in dll.DIRECTORY_ENTRY_EXPORT.symbols:
            data[ent.address] = '\xc3' # ret
            dll_funcs[base + ent.address] = ent.name

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
        emu.mem_write(ADDRESS, data)
        emu.reg_write(UC_X86_REG_EIP, ADDRESS)
        # mu.hook_add(UC_HOOK_CODE, self._hook_code, None, DLL_BASE, DLL_BASE + 6 * PageSize)
        emu.hook_add(UC_HOOK_CODE, self._hook_code)


    def laod_pe(self, data):
        pass


    def start(self, offset):
        entry = self.ADDRESS + offset
        self.emu.emu_start(entry, entry + self.size)



########################################
CK = 0
FS_0 = 0x1000
PEB_ADD = 0x3000
TEB_ADD = 0x6000
LDR_ADD1 = 0x9000
LDR_ADD2 = 0xB000
LDR_ADD3 = 0xE000
LDR_ADD4 = 0xF000
PEB_LDR_ADD = 0x13000
STACK_BASE = 0x30000
STACK_LIMIT = 0x1000
ADDRESS = 0x400000
DLL_BASE = 0x550000
kernel32_base = 0
urlmon_base = 0
PageSize = 0x80000
strKerBase = 0x2500
strKernl = 'kernelkernel32.dll'
strUmonBase = strKerBase + 200
strUmon = "urlmon.dll"
strAdvBase = strUmonBase + 200
strAdvp = "advapi32.dll"
strUser32Base = strAdvBase + 200
strUser32 = 'user32.dll'
pe_struct = {
    'imageBase': 0x0,
    'codeBase': 0x0,
    'dataBase': 0x0,
    'entryPoint': 0x0,
    'eop': 0x0,
    'textSection': 0x0,
    'textSectionSize': 0x0,
    'dataSection': 0x0,
}

kernel32_struct = {
    'imageBase': 0x0,
    'sizeOfImage': 0x0,
    'entryPoint': 0x0,
}

urlmon_struct = {
    'imageBase': 0x0,
    'sizeOfImage': 0x0,
    'entryPoint': 0x0,
}
advapi32_struct = {
    'imageBase': 0x0,
    'sizeOfImage': 0x0,
    'entryPoint': 0x0,
}
User32_struct = {
    'imageBase': 0x0,
    'sizeOfImage': 0x0,
    'entryPoint': 0x0,
}

class x86_OS:
    def init_ldr(seft, FLoad, Bload, FMem, BMem, FInit, BInit, DllBase, EntryPoint, DllName, addrofnamedll):
        # InOrder
        ldr = ''
        ldr += pck32(FLoad)  # flink
        ldr += pck32(Bload)  # blink
        # Inmem
        ldr += pck32(FMem)  # flink
        ldr += pck32(BMem)  # blink
        # InInit
        ldr += pck32(FInit)  # flink 0x10
        ldr += pck32(BInit)  # blink 0x14

        ldr += pck32(DllBase)  # baseOfdll 0x18
        ldr += pck32(EntryPoint)  # entryPoint 0x1c
        ldr += pck32(0x0)  # sizeOfImage 0x20
        ldr += pck32(0x0) * 2  # Fullname 0x28
        # basename
        ldr += pck32(0x0)  # 0x2c
        ldr += pck32(addrofnamedll)  # 0x30
        return ldr

    def init_teb(seft):
        teb = ''
        teb += pck32(0x0) * 7
        teb += pck32(0x0)  # EnvironmentPointer
        teb += pck32(0x0)  # ClientId
        teb += pck32(0x0)  # ThreadLocalStoragePointer
        teb += pck32(PEB_ADD)  # ProcessEnvironmentBlock
        teb += pck32(0x0)  # LastErrorValue
        return teb

    def init_peb(seft):
        peb = ''
        peb += pck32(0x0) * 2  # InheritedAddressSpace
        peb += pck32(pe_struct['imageBase'])  # imageBaseAddress
        peb += pck32(PEB_LDR_ADD)  # Ldr
        peb += pck32(0x0)  # process parameter
        return peb

    def init_peb_ldr_data(self):
        peb_ldr_data = ''
        peb_ldr_data += pck32(0x0) * 3  # 0x8
        peb_ldr_data += pck32(LDR_ADD1)  # 0x0c
        peb_ldr_data += pck32(LDR_ADD1 + 0x4)
        peb_ldr_data += pck32(LDR_ADD1 + 0x8)  # 0x14
        peb_ldr_data += pck32(LDR_ADD1 + 0xc)
        peb_ldr_data += pck32(LDR_ADD1 + 0x10)  # 0x1C
        peb_ldr_data += pck32(LDR_ADD1 + 0x14)
        return peb_ldr_data

    def init_FS(self):
        FS = ''
        FS += pck32(0x0)  # 0x0
        FS += pck32(STACK_BASE)  # 0x4
        FS += pck32(STACK_LIMIT)  # 0x8
        FS += pck32(0x0) * 3  # 0x14
        FS += pck32(FS_0)
        FS += pck32(0x0) * 4
        FS += pck32(TEB_ADD)
        FS += pck32(PEB_ADD)
        FS += pck32(0x0)
        return FS
