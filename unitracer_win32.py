from unicorn import *
from unicorn.x86_const import *

from capstone import *
from capstone.x86_const import *

from unitracer import Unitracer

from util import *

import sys
import pefile
import struct
import os


class Win32(Unitracer):
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
            emu.mem_write(PEB, struct.pack('<i', PEB))
            emu.mem_write(LDR, struct.pack('<i', LDR))
            emu.mem_write(InInitOrder, struct.pack('<i', InInitOrder))
            emu.mem_write(InInitOrder + 8, struct.pack('<i', kernel32_base))
            emu.mem_write(BaseName, struct.pack('<i', BaseName + 4))
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
            print('0x%x: \t%s\t%s\n edx = 0x%x' % (a.address, a.mnemonic, a.op_str, edx))

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

imp_dll = {}


def pops(uc, ESP):
    esp = uc.mem_read(ESP, 4)
    esp = upck32(esp)
    return esp


def string_pack(argv):
    s = ''
    for c in argv:
        if (c == 0):
            break
        s += chr(c)
    return s


def hook_IsDebuggerPresent(id, esp, uc):
    eip_saved = pops(uc, esp)
    print('0x%0.2x:\tCall IsDebuggerPresent')
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.mem_write(esp, pck32(eip_saved))


def hook_Sleep(id, esp, uc):
    eip_saved = pops(uc, esp)
    dwMilliseconds = pops(uc, esp + 4)
    print("0x%0.2x:\tCall Sleep (%x)" % (eip_saved, dwMilliseconds))

    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_CloseHandle(id, esp, uc):
    eip_saved = pops(uc, esp)
    handle = pops(uc, esp + 4)
    print("0x%0.2x:\tCall CloseHandle (0x%x)" %(eip_saved,handle))
    global CK
    '''if (CK == 1):
        uc.emu_stop()
    CK += 1'''
    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_SetFilePointer(id, esp, uc):
    eip_saved = pops(uc, esp)
    hFile = pops(uc, esp + 4)
    plDistanceToMove = pops(uc, esp + 8)
    plpDistanceToMoveHigh = pops(uc, esp + 0xc)
    dwMoveMethod = pops(uc, esp + 0x10)
    print(
        "0x%0.2x:\tCall SetFilePointer (hFile = 0x%x, lDistanceToMove = 0x%x, lpDistanceToMoveHigh = 0x%x, dwMoveMethod = 0x%x)" % (eip_saved,
        hFile, plDistanceToMove, plpDistanceToMoveHigh, dwMoveMethod))
    uc.mem_write(esp + 0x10, pck32(eip_saved))


def hook_GetAsyncKeyState(id, esp, uc):
    eip_saved = pops(uc, esp)
    vKey = pops(uc, esp + 4)
    print("0x%0.2x:\tCall GetAsyncKeyState (vKey = 0x%x)" % (eip_saved, vKey))
    uc.reg_write(UC_X86_REG_EAX, 0x1)
    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_GetKeyNameTextA(id, esp, uc):
    eip_saved = pops(uc, esp)
    lParam = pops(uc, esp +4)
    lpString = pops(uc, esp + 8)
    cchSize = pops(uc, esp + 0xc)
    print("0x%0.2x:\tCall GetKeyNameTextA (lParam = 0x%x, lpString = 0x%x, cchSize = 0x%x)" %(eip_saved, lParam, lpString, cchSize))
    uc.reg_write(UC_X86_REG_EAX, 0x1)
    uc.mem_write(esp + 0xc, pck32(eip_saved))


def hook_MapVirtualKeyA(id, esp, uc):
    eip_saved = pops(uc, esp)
    uCode = pops(uc, esp + 4)
    uMapType = pops(uc, esp + 8)
    print("0x%0.2x:\tCall MapVirtualKeyA (uCode = 0x%x, uMapType = 0x%x)" %(eip_saved,uCode, uMapType))
    uc.reg_write(UC_X86_REG_EAX, 0x0)
    uc.mem_write(esp +8, pck32(eip_saved))


def hook_lstrlenA(id, esp, uc):
    eip_saved = pops(uc, esp)
    plpString = pops(uc, esp + 4)
    lpString = uc.mem_read(plpString, 0x100)
    print("0x%0.2x:\tCall lstrlenA (lpString = %s)" %(eip_saved, string_pack(lpString)))
    uc.reg_write(UC_X86_REG_EAX, len(string_pack(lpString)))
    uc.reg_write(esp + 4, eip_saved)


def hook_GetTempPathA(id, esp, uc):
    lBuffer = pops(uc, esp + 4)
    pBuffer = pops(uc, esp + 8)
    eip_saved = pops(uc, esp)
    tempPath = '\\temp\\'
    uc.mem_write(pBuffer, tempPath)
    uc.reg_write(UC_X86_REG_ESP, esp + 0x08)
    uc.reg_write(UC_X86_REG_EAX, len(tempPath))
    print('0x%0.2x:\tCall GetTempPathA\t(len=0x%0.2x, buf=0x%0.2x)' % (eip_saved, lBuffer, pBuffer))
    uc.mem_write(esp + 0x08, pck32(eip_saved))


def hook_CreateFileA(id, esp, uc):
    CreationDisposition = {1: 'CREATE_AWAYS', 2: 'CREATE_NEW', 3: 'OPEN_EXISTING', 4: 'OPEN_ALWAYS',
                           5: 'TRUNCATE_EXISTING'}
    eip_saved = pops(uc, esp)
    lpFileName = pops(uc, esp + 4)
    dwCreationDisposition = pops(uc, esp + 0x14)
    szFileName = uc.mem_read(lpFileName, 0x100)
    FileName = string_pack(szFileName)
    print('0x%0.2x:\tCall CreateFileA (filename=%s,creationDisposition=%s)' % (
        eip_saved, FileName, CreationDisposition[dwCreationDisposition]))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x1c)
    uc.reg_write(UC_X86_REG_EAX, 0x69)
    eip_packed = struct.pack('<I', eip_saved)
    uc.mem_write(esp + 0x1c, eip_packed)


def hook_LoadLibraryA(id, esp, uc):
    pLib = pops(uc, esp + 4)
    eip_saved = pops(uc, esp)
    LIB = uc.mem_read(pLib, 0x100)
    lib = string_pack(LIB)
    print('0x%0.2x:\tCall LoadLibraryA (\'%s\')' % (eip_saved, lib))
    if (lib == 'kernel32.dll'):
        uc.reg_write(UC_X86_REG_EAX, kernel32_base)
    elif (lib == 'urlmon.dll'):
        uc.reg_write(UC_X86_REG_EAX, urlmon_base)
    elif (lib == 'advapi32.dll'):
        uc.reg_write(UC_X86_REG_EAX, DLL_BASE)
    else:
        baseLB = 0x900000
        LB = dll_loader(lib, baseLB)
        uc.mem_write(baseLB, LB)
    uc.reg_write(UC_X86_REG_ESP, esp + 4)
    uc.mem_write(esp + 4, pck32(eip_saved))


def hook_WinExec(id, esp, uc):
    pCmd = pops(uc, esp + 4)
    nshow = pops(uc, esp + 8)
    eip_saved = pops(uc, esp)
    CMD = uc.mem_read(pCmd, 0x100)
    cmd = string_pack(CMD)
    uc.reg_write(UC_X86_REG_ESP, esp + 0x08)
    print('0x%0.2x:\tCall WinExec (\'%s\', %d)' % (eip_saved, cmd, nshow))
    uc.mem_write(esp + 0x08, pck32(eip_saved))


def hook_WriteFile(id, esp, uc):
    eip_saved = pops(uc, esp)
    hFile = pops(uc, esp + 4)
    lpBuff = pops(uc, esp + 8)
    nNumberOfBytesWrite = pops(uc, esp + 0x0c)
    lpNumberOfBytesWritten = pops(uc, esp + 0x10)
    print('0x%0.2x:\tCall WriteFile (hFile=0x%0.2x, lpBuff=0x%0.2x, nNumberOfBytesWrite=0x%0.2x)' % (eip_saved,hFile,lpBuff,nNumberOfBytesWrite))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x14)
    uc.mem_write(esp + 0x14, pck32(eip_saved))
    uc.mem_write(lpNumberOfBytesWritten, struct.pack('<I', nNumberOfBytesWrite))


def hook_ReadFile(id, esp, uc):
    eip_saved = pops(uc, esp)
    hFile = pops(uc, esp + 4)
    lpBuff = pops(uc, esp + 8)
    nNumberOfBytesToRead = pops(uc, esp + 0x0c)
    lpNumberOfBytesRead = pops(uc, esp + 0x10)
    print('0x%0.2x:\tCall ReadFile With (hFile=0x%0.2x,lpBuff=0x%0.2x,nNumberOfBytesToRead=0x%0.2x)' % (
        hFile, lpBuff, nNumberOfBytesToRead))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x14)
    uc.reg_write(UC_X86_REG_EAX, 0x69)
    uc.mem_write(lpNumberOfBytesRead, struct.pack('<I', nNumberOfBytesToRead))
    uc.mem_write(esp + 0x14, pck32(eip_saved))


def hook_URLDownloadToFileA(id, esp, uc):
    eip_saved = pops(uc, esp)
    pUrl = pops(uc, esp + 8)
    pFileName = pops(uc, esp + 0x0c)
    szUrl = uc.mem_read(pUrl, 0x100)
    szFileName = uc.mem_read(pFileName, 0x100)
    Url = string_pack(szUrl)
    FileName = string_pack(szFileName)
    print('0x%0.2x:\tCall URLDownloadToFileA (Url=%s, LocalPath=%s)\n' % (eip_saved, Url, FileName))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x14)
    uc.mem_write(esp + 0x14, pck32(eip_saved))


def hook_ExitProcess(eip, esp, uc):
    eip_saved = pops(uc, esp)
    uExitcode = pops(uc, esp + 4)
    print('0x%0.2x:\tCall ExitProcess (0x%0.2x)' % (eip_saved, uExitcode))
    uc.emu_stop()


def hook_GetWindowsDirectoryA(id, esp, uc):
    eip_saved = pops(uc, esp)
    buf = pops(uc, esp + 0x4)
    uSize = pops(uc, esp + 0x8)
    print("0x%x:\tCall GetWindowsDirectoryA (buf = 0x%x)" % (eip_saved, buf))
    uc.mem_write(buf, struct.pack('10s', "C:\Windows"))
    uc.reg_write(UC_X86_REG_EAX, 0xa)
    uc.reg_write(UC_X86_REG_ESP, esp + 8)
    uc.mem_write(esp + 0x8, pck32(eip_saved))


def hook_lstrcatA(eip, esp, uc):
    eip_saved = pops(uc, esp)
    plString1 = pops(uc, esp + 0x4)
    arg1 = uc.mem_read(plString1, 0x100)
    plString2 = pops(uc, esp + 0x8)
    arg2 = uc.mem_read(plString2, 0x100)
    lString1 = string_pack(arg1)
    lString2 = string_pack(arg2)
    print("0x%x:\tCall lstrcatA (String2: \'%s\', String1: \'%s\')" % (eip_saved, lString2, lString1))
    lString1 += lString2
    uc.mem_write(plString1, lString1)
    uc.reg_write(UC_X86_REG_ESP, esp + 0x8)
    uc.mem_write(esp + 0x8, pck32(eip_saved))


def hook_RegCreateKeyA(eip, esp, uc):
    hkey = {2147483648: 'HKEY_CLASSES_ROOT', 2147483649: 'HKEY_CURRENT_USER', 2147483650: 'HKEY_LOCAL_MACHINE',
            2147483651: 'HKEY_USERS', 2147483652: 'HKEY_PERFORMANCE_DATA', 2147483653: 'HKEY_CURRENT_CONFIG',
            2147483654: 'HKEY_DYN_DATA'}
    eip_saved = pops(uc, esp)
    hKey = pops(uc, esp + 4)
    lpSubKey = pops(uc, esp + 8)
    phkResult = pops(uc, esp + 0xc)
    SubKey = uc.mem_read(lpSubKey, 0x100)
    subkey = string_pack(SubKey)
    print("0x%x:\tCall RegCreateKeyA function With key: %s\%s\n" % (eip_saved, hkey[hKey], subkey))
    uc.mem_write(phkResult, pck32(0x69))
    uc.reg_write(UC_X86_REG_EAX, 0)
    uc.reg_write(UC_X86_REG_ESP, esp + 0xc)
    uc.mem_write(esp + 0xc, pck32(eip_saved))


def hook_RegCloseKey(eip, esp, uc):
    eip_saved = pops(uc, esp)
    hKey = pops(uc, esp +4)
    print("0x%x:\tCall RegCloseKey function (hKey= 0x%x)" % (eip_saved, hKey))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x4)
    uc.mem_write(esp + 0x4, pck32(eip_saved))


def hook_RegSetValueExA(eip, esp, uc):
    eip_saved = pops(uc, esp)
    hKey = pops(uc, esp + 0x4)
    lpValueName = pops(uc, esp + 0x8)
    Reserved = pops(uc, esp + 0xc)
    dwType = pops(uc, esp + 0x10)
    lpData = pops(uc, esp + 0x14)
    cbData = pops(uc, esp + 0x18)
    ValueName = uc.mem_read(lpValueName, 0x100)
    Data = uc.mem_read(lpData, 0x100)
    print("0x%x:\tCall RegSetValueExA (hKey = 0x%x, ValueName: %s, Registry data: %s)\n" % (
        eip_saved, hKey, string_pack(ValueName), string_pack(Data)))
    uc.reg_write(UC_X86_REG_ESP, esp + 0x18)
    uc.mem_write(esp + 0x18, pck32(eip_saved))


def hook_GetProcAddress(id, esp, uc):
    eip_saved = pops(uc, esp)
    hModule = pops(uc, esp + 4)
    lpProcName = pops(uc, esp + 8)
    procName = string_pack(uc.mem_read(lpProcName, 0x100))
    print("0x%x: \tCall GetProcAddress (Hmodule = %x, ProcName = %s)" % (eip_saved, hModule, procName))
    for e in imp_dll:
        if imp_dll[e] == procName:
            uc.reg_write(UC_X86_REG_EAX, e)
            break
    uc.reg_write(UC_X86_REG_ESP, esp + 0x8)
    uc.mem_write(esp + 0x8, pck32(eip_saved))


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


def input_shellcode(shellname):
    # get shellcode for emulation
    fShell = open(shellname, 'rb')
    shellcode = fShell.read()
    fShell.close()
    return shellcode


def input_pe(argv):
    exename = argv
    if exename:
        pef = pefile.PE(exename, fast_load=True)
    else:
        print("[!] Blank filename specified")
        sys.exit(2)
    pef.parse_data_directories()
    pe_struct['imageBase'] = pef.OPTIONAL_HEADER.ImageBase
    pe_struct['codeBase'] = pef.OPTIONAL_HEADER.BaseOfCode
    pe_struct['dataBase'] = pef.OPTIONAL_HEADER.BaseOfData
    pe_struct['entryPoint'] = pef.OPTIONAL_HEADER.AddressOfEntryPoint

    for section in pef.sections:
        if section.contains_rva(pe_struct['entryPoint']):
            pe_struct['textSection'] = section
            pe_struct['textSectionSize'] = section.SizeOfRawData
            break
    pe = bytearray(pef.get_memory_mapped_image())
    # rewrite IAT
    for entry in pef.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            for impr in imp_dll:
                # Find imported function in IAT
                if (imp.name == imp_dll[impr]):
                    temp = bytearray(struct.pack('<I', impr))
                    for j in range(len(temp)):
                        pe[imp.address + j - pe_struct['imageBase']] = temp[j]
                    break
    return str(pe)


def dll_loader(dllName, dll_base):
    path = 'dll\\' + dllName
    dll = pefile.PE(path)
    dll.parse_data_directories()
    data = bytearray(dll.get_memory_mapped_image())
    if dllName == "kernel32.dll":
        kernel32_struct['sizeOfImage'] = dll.OPTIONAL_HEADER.SizeOfImage
        kernel32_struct['entryPoint'] = dll.OPTIONAL_HEADER.AddressOfEntryPoint
    elif dllName == "urlmon.dll":
        urlmon_struct['sizeOfImage'] = dll.OPTIONAL_HEADER.SizeOfImage
        urlmon_struct['entryPoint'] = dll.OPTIONAL_HEADER.AddressOfEntryPoint
    elif dllName == "advapi32.dll":
        advapi32_struct['sizeOfImage'] = dll.OPTIONAL_HEADER.SizeOfImage
        advapi32_struct['entryPoint'] = dll.OPTIONAL_HEADER.AddressOfEntryPoint
    elif dllName == "User32.dll":
        User32_struct['sizeOfImage'] = dll.OPTIONAL_HEADER.SizeOfImage
        User32_struct['entryPoint'] = dll.OPTIONAL_HEADER.AddressOfEntryPoint
    for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:
        data[entry.address] = '\xc3'
        imp_dll[dll_base + entry.address] = entry.name
    return str(data)


def hook_code(uc, address, size, userdata):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = uc.mem_read(address, size)
    asm = md.disasm(str(code), address)
    esp = uc.reg_read(UC_X86_REG_ESP)
    eip = uc.reg_read(UC_X86_REG_EIP)
    edx = uc.reg_read(UC_X86_REG_EDX)
    #for a in asm:
    #    print('0x%x: \t%s\t%s\n edx = 0x%x' % (a.address, a.mnemonic, a.op_str, edx))
    if ((eip in imp_dll)):
        globals()['hook_' + imp_dll[eip]](eip, esp, uc)




def main(argv):
    check = 1
    inputfile = ''
    try:
        opts, args = getopt.getopt(argv, "s:p:", ["option=", "input="])
    except getopt.GetoptError:
        print('\n[+] Usage: ' + sys.argv[0] + ' [-s / -p] [ shellcode / pefile ]\n')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-s':
            inputfile = sys.argv[2]
        elif opt == '-p':
            inputfile = sys.argv[2]
            check = 0
        else:
            print('\n[+] Usage: ' + sys.argv[0] + ' [-s / -p] [ shellcode / pefile ]\n')
            sys.exit(2)
    print("Emulate i386 code\nEmulating...\n=======Creating Report=======")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        # map 10MB memory for this emulation
        mu.mem_map(FS_0, 15 * 1024 * 1024)
        if check == 1:
            simulator_initialisation(mu)
            print("Emulation done...")
        elif check == 0:
            simulator_initialisation(mu)
            pe = input_pe(inputfile)
            mu.mem_write(ADDRESS, pe)
            mu.reg_write(UC_X86_REG_EIP, ADDRESS + pe_struct['entryPoint'])
            mu.hook_add(UC_HOOK_CODE, hook_code)#, None, DLL_BASE, DLL_BASE + 6 * PageSize)
            mu.emu_start(ADDRESS + pe_struct['entryPoint'],
                         ADDRESS + pe_struct['entryPoint'] + pe_struct['textSectionSize'])
            print("Emulation done...")
    except UcError as e:
        print("ERROR: %s" % e)
        mu.emu_stop()


# if __name__ == '__main__':
#     main(sys.argv[1:])
