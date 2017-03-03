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


class Windows(Unitracer):
    ADDRESS = 0x400000

    STACK_BASE = 0x00d00000
    STACK_SIZE = 0x10000

    GDT_BASE = 0x80000000
    GDT_SIZE = 0x1000

    TIB_ADDR = 0x00b7d000
    TEB_ADDR = TIB_ADDR
    PEB_ADDR = 0x00b2f000
    PEB_LDR_ADDR = 0x77dff000

    HEAP_BASE = 0x00d50000
    HEAP_CUR = HEAP_BASE

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

        if bits == 32:
            # init Thread Information Block
            teb = self.TEB()
            peb = self.PEB()

            # setup peb, teb
            peb.ImageBaseAddress = self.ADDRESS
            peb.Ldr = self.PEB_LDR_ADDR
            peb.ProcessHeap = self.HEAP_BASE

            teb.NtTib.StackBase = self.STACK_BASE
            teb.NtTib.StackLimit = self.STACK_BASE - self.STACK_SIZE
            teb.NtTib.Self = self.TEB_ADDR
            teb.ThreadLocalStoragePointer = self.TEB_ADDR
            teb.ProcessEnvironmentBlock = self.PEB_ADDR

            emu.mem_map(self.PEB_ADDR, align(sizeof(peb)))
            emu.mem_write(self.PEB_ADDR, struct2str(peb))

            emu.mem_map(self.TEB_ADDR, align(sizeof(teb)))
            emu.mem_write(self.TEB_ADDR, struct2str(teb))

            # init Global Descriptor Table
            gdt = GDT_32(emu, self.GDT_BASE, self.GDT_SIZE)

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

            # ss
            flags = GDT_32.gdt_entry_flags(gr=1, sz=1, pr=1, privl=0, ex=0, dc=1, rw=1, ac=1) # 0xcf3
            selector = gdt.set_entry(6, 0x0, 0xffffffff, flags, rpl=0)
            emu.reg_write(UC_X86_REG_SS, selector)

            # fs : 0x0053 (index:10)
            flags = GDT_32.gdt_entry_flags(gr=0, sz=1, pr=1, privl=3, ex=0, dc=0, rw=1, ac=1) # 0x4f3
            selector = gdt.set_entry(10, self.TIB_ADDR, 0xfff, flags)
            emu.reg_write(UC_X86_REG_FS, selector)

            self.gdt = gdt


    def _init_ldr(self, dlls=None):
        emu = self.emu
        containsPE = False

        if dlls == None:
            dlls = ["ntdll.dll", "ntdll.dll", "kernel32.dll"]

        # allocate processheap
        emu.mem_map(self.HEAP_BASE, 0x10000)

        # create LDR_DATA_TABLE_ENTRY
        ldrs = []
        for dll in dlls:
            if not os.path.exists(dll):
                print >> sys.stderr, "{} does not exist".format(dll)

            pe = PE(dll)

            dllbase = self.load_dll(dll)
            fulldllname = "C:\\Windows\\System32\\{}".format(dll).encode("UTF-16LE")
            basedllname = dll.encode("UTF-16LE")

            ldr_module = LDR_MODULE()

            ldr_module.addr = self._alloc(sizeof(ldr_module))
            ldr_module.fulldllname = fulldllname
            ldr_module.basedllname = basedllname

            ldr_module.BaseAddress = dllbase
            ldr_module.EntryPoint = pe.entrypoint
            ldr_module.SizeOfImage = pe.imagesize

            ldr_module.FullDllName.Length = len(fulldllname)
            ldr_module.FullDllName.MaximumLength = len(fulldllname)+2
            ldr_module.FullDllName.Buffer = self._alloc(len(fulldllname)+2)
            ldr_module.BaseDllName.Length = len(basedllname)
            ldr_module.BaseDllName.MaximumLength = len(basedllname)+2
            ldr_module.BaseDllName.Buffer = self._alloc(len(basedllname)+2)

            ldrs.append(ldr_module)

        # setup PEB_LDR_DATA
        ldr_data = PEB_LDR_DATA()
        ldr_data.addr = self.PEB_LDR_ADDR
        ldr_data.InLoadOrderModuleList.Flink = ldrs[0].addr
        ldr_data.InLoadOrderModuleList.Blink = ldrs[-1].addr
        ldr_data.InMemoryOrderModuleList.Flink = ldrs[0].addr+0x8
        ldr_data.InMemoryOrderModuleList.Blink = ldrs[-1].addr+0x8
        ldr_data.InInitializationOrderModuleList.Flink = ldrs[0].addr+0x10
        ldr_data.InInitializationOrderModuleList.Blink = ldrs[-1].addr+0x10

        # link table entries
        for i in range(len(ldrs)):
            n = (i+1)%len(ldrs)
            p = (i-1+len(ldrs))%len(ldrs)

            ldrs[i].InLoadOrderModuleList.Flink = ldrs[n].addr
            ldrs[i].InLoadOrderModuleList.Blink = ldrs[p].addr
            ldrs[i].InMemoryOrderModuleList.Flink = ldrs[n].addr+0x8
            ldrs[i].InMemoryOrderModuleList.Blink = ldrs[p].addr+0x8
            ldrs[i].InInitializationOrderModuleList.Flink = ldrs[n].addr+0x10
            ldrs[i].InInitializationOrderModuleList.Blink = ldrs[p].addr+0x10

        ldrs[0].InLoadOrderModuleList.Blink = ldr_data.addr+0xc
        ldrs[-1].InLoadOrderModuleList.Flink = ldr_data.addr+0xc
        ldrs[0].InMemoryOrderModuleList.Blink = ldr_data.addr+0x14
        ldrs[-1].InMemoryOrderModuleList.Flink = ldr_data.addr+0x14
        ldrs[0].InInitializationOrderModuleList.Blink = ldr_data.addr+0x1c
        ldrs[-1].InInitializationOrderModuleList.Flink = ldr_data.addr+0x1c


        # write data
        emu.mem_map(self.PEB_LDR_ADDR, align(sizeof(ldr_data)))
        emu.mem_write(self.PEB_LDR_ADDR, struct2str(ldr_data))

        for ldr_module in ldrs:
            emu.mem_write(ldr_module.FullDllName.Buffer, ldr_module.fulldllname)
            emu.mem_write(ldr_module.BaseDllName.Buffer, ldr_module.basedllname)
            emu.mem_write(ldr_module.addr, struct2str(ldr_module))


    def _alloc(self, size):
        ret = self.HEAP_CUR
        self.HEAP_CUR += size
        return ret


    def load_dll(self, path):
        dlls = self.dlls
        emu = self.emu
        base = self.DLL_CUR
        dllname = os.path.basename(path)

        dlldata = self._load_dll(path, base)
        size = align(len(dlldata))
        emu.mem_map(base, size)
        emu.mem_write(base, dlldata)
        dlls.append([dllname, base])
        self.DLL_CUR += size

        print("{0} is loaded @ 0x{1:08x}".format(dllname, base))

        return base


    def _load_dll(self, path, base):
        dll_funcs = self.dll_funcs

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
        eip = uc.reg_read(UC_X86_REG_EIP)
        self.eip = eip

        eax = uc.reg_read(UC_X86_REG_EAX)
        ebx = uc.reg_read(UC_X86_REG_EBX)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        edx = uc.reg_read(UC_X86_REG_EDX)
        edi = uc.reg_read(UC_X86_REG_EDI)
        esi = uc.reg_read(UC_X86_REG_ESI)
        esp = uc.reg_read(UC_X86_REG_ESP)
        ebp = uc.reg_read(UC_X86_REG_EBP)
        print("eax: 0x{0:08x}".format(eax))
        print("ebx: 0x{0:08x}".format(ebx))
        print("edx: 0x{0:08x}".format(edx))
        print("esi: 0x{0:08x}".format(esi))

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
        self.entry = self.ADDRESS + 0
        self._init_ldr(["dll/ntdll.dll", "dll/ntdll.dll", "dll/kernel32.dll"])
        self._init_process()

        # map shellcode
        emu.mem_map(ADDRESS, align(len(data)))
        emu.mem_write(ADDRESS, data)
        emu.reg_write(UC_X86_REG_EIP, ADDRESS)

        # init stack
        STACK_BASE = self.STACK_BASE
        STACK_SIZE = self.STACK_SIZE
        emu.mem_map(STACK_BASE - STACK_SIZE, align(STACK_SIZE))
        emu.reg_write(UC_X86_REG_ESP, STACK_BASE)
        emu.reg_write(UC_X86_REG_EBP, STACK_BASE)

        # mu.hook_add(UC_HOOK_CODE, self._hook_code, None, DLL_BASE, DLL_BASE + 6 * PageSize)
        emu.hook_add(UC_HOOK_CODE, self._hook_code)


    def load_pe(self, fname):
        emu = self.emu
        ADDRESS = self.ADDRESS

        pe = PE(fname)
        dlls = pe.imports.keys()

        self.STACK_SIZE = pe.stacksize

        self._init_ldr(map(lambda x:"dll/"+x, dlls))
        self._init_process()

        # map PE
        data = pe.mapped_data
        emu.mem_map(ADDRESS, align(len(data)))
        emu.mem_write(ADDRESS, data)
        emu.reg_write(UC_X86_REG_EIP, ADDRESS)
        self.size = len(data)
        self.entry = ADDRESS + pe.entrypoint

        # init stack
        STACK_BASE = self.STACK_BASE
        STACK_SIZE = self.STACK_SIZE
        emu.mem_map(STACK_BASE - STACK_SIZE, align(STACK_SIZE))
        print("stack: 0x{0:08x}-0x{1:08x}".format(STACK_BASE - STACK_SIZE, STACK_BASE))
        emu.reg_write(UC_X86_REG_EBP, STACK_BASE)
        emu.reg_write(UC_X86_REG_ESP, STACK_BASE)

        # mu.hook_add(UC_HOOK_CODE, self._hook_code, None, DLL_BASE, DLL_BASE + 6 * PageSize)
        emu.hook_add(UC_HOOK_CODE, self._hook_code)


    def start(self, offset):
        emu = self.emu
        entry = self.entry

        try:
            emu.emu_start(entry, entry + self.size)
        except UcError as e:
            print("ERROR: %s" % e)
            eax = emu.reg_read(UC_X86_REG_EAX)
            ebx = emu.reg_read(UC_X86_REG_EBX)
            ecx = emu.reg_read(UC_X86_REG_ECX)
            edx = emu.reg_read(UC_X86_REG_EDX)
            edi = emu.reg_read(UC_X86_REG_EDI)
            esi = emu.reg_read(UC_X86_REG_ESI)
            esp = emu.reg_read(UC_X86_REG_ESP)
            ebp = emu.reg_read(UC_X86_REG_EBP)
            eip = self.eip
            print("eax: 0x{0:08x}".format(eax))
            print("ebx: 0x{0:08x}".format(ebx))
            print("ecx: 0x{0:08x}".format(ecx))
            print("edx: 0x{0:08x}".format(edx))
            print("edi: 0x{0:08x}".format(edi))
            print("esi: 0x{0:08x}".format(esi))
            print("esp: 0x{0:08x}".format(esp))
            print("ebp: 0x{0:08x}".format(ebp))
            print("eip: 0x{0:08x}".format(eip))
