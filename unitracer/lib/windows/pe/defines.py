from __future__ import absolute_import

from ctypes import *
from .types import *


class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ("e_magic",             WORD),
        ("e_cblp",              WORD),
        ("e_cp",                WORD),
        ("e_crlc",              WORD),
        ("e_cparhdr",           WORD),
        ("e_minalloc",          WORD),
        ("e_maxalloc",          WORD),
        ("e_ss",                WORD),
        ("e_sp",                WORD),
        ("e_csum",              WORD),
        ("e_ip",                WORD),
        ("e_cs",                WORD),
        ("e_lfarlc",            WORD),
        ("e_ovno",              WORD),
        ("e_res",               WORD * 4),
        ("e_oemid",             WORD),
        ("e_oeminfo",           WORD),
        ("e_res2",              WORD * 10),
        ("e_lfanew",            LONG),
    ]


class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ("Machine",                 WORD),
        ("NumberOfSections",        WORD),
        ("TimeDateStamp",           DWORD),
        ("PointerToSymbolTable",    DWORD),
        ("NumberOfSymbols",         DWORD),
        ("SizeOfOptionalHeader",    WORD),
        ("Characteristics",         WORD),
    ]
PIMAGE_FILE_HEADER = POINTER(IMAGE_FILE_HEADER)

IMAGE_FILE_MACHINE_I386     = 0x014c
IMAGE_FILE_MACHINE_IA64     = 0x0200
IMAGE_FILE_MACHINE_AMD64    = 0x8664

IMAGE_FILE_RELOCS_STRIPPED          = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED       = 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED      = 0x0008
IMAGE_FILE_AGGRESIVE_WS_TRIM        = 0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE      = 0x0020
IMAGE_FILE_BYTES_REVERSED_LO        = 0x0080
IMAGE_FILE_32BIT_MACHINE            = 0x0100
IMAGE_FILE_DEBUG_STRIPPED           = 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  = 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP        = 0x0800
IMAGE_FILE_SYSTEM                   = 0x1000
IMAGE_FILE_DLL                      = 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY           = 0x4000
IMAGE_FILE_BYTES_REVERSED_HI        = 0x8000


class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ("VirtualAddress",              DWORD),
        ("Size",                        DWORD),
    ]
PIMAGE_DATA_DIRECTORY = POINTER(IMAGE_DATA_DIRECTORY)

IMAGE_DIRECTORY_ENTRY_EXPORT            = 0
IMAGE_DIRECTORY_ENTRY_IMPORT            = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE          = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION         = 3
IMAGE_DIRECTORY_ENTRY_SECURITY          = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC         = 5
IMAGE_DIRECTORY_ENTRY_DEBUG             = 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR         = 8
IMAGE_DIRECTORY_ENTRY_TLS               = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      = 11
IMAGE_DIRECTORY_ENTRY_IAT               = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    = 14


IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
class IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_ = [
        ("Magic",                       WORD), 
        ("MajorLinkerVersion",          BYTE), 
        ("MinorLinkerVersion",          BYTE), 
        ("SizeOfCode",                  DWORD), 
        ("SizeOfInitializedData",       DWORD), 
        ("SizeOfUninitializedData",     DWORD), 
        ("AddressOfEntryPoint",         DWORD), 
        ("BaseOfCode",                  DWORD), 
        ("BaseOfData",                  DWORD), 
        ("ImageBase",                   DWORD), 
        ("SectionAlignment",            DWORD), 
        ("FileAlignment",               DWORD), 
        ("MajorOperatingSystemVersion", WORD), 
        ("MinorOperatingSystemVersion", WORD), 
        ("MajorImageVersion",           WORD), 
        ("MinorImageVersion",           WORD), 
        ("MajorSubsystemVersion",       WORD), 
        ("MinorSubsystemVersion",       WORD), 
        ("Win32VersionValue",           DWORD), 
        ("SizeOfImage",                 DWORD), 
        ("SizeOfHeaders",               DWORD), 
        ("CheckSum",                    DWORD), 
        ("Subsystem",                   WORD), 
        ("DllCharacteristics",          WORD), 
        ("SizeOfStackReserve",          DWORD), 
        ("SizeOfStackCommit",           DWORD), 
        ("SizeOfHeapReserve",           DWORD), 
        ("SizeOfHeapCommit",            DWORD), 
        ("LoaderFlags",                 DWORD), 
        ("NumberOfRvaAndSizes",         DWORD), 
        ("DataDirectory",               IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES), 
    ]
PIMAGE_OPTIONAL_HEADER32 = POINTER(IMAGE_OPTIONAL_HEADER32)

class IMAGE_OPTIONAL_HEADER64(Structure):
    _fields_ = [
        ("Magic",                       WORD), 
        ("MajorLinkerVersion",          BYTE), 
        ("MinorLinkerVersion",          BYTE), 
        ("SizeOfCode",                  DWORD), 
        ("SizeOfInitializedData",       DWORD), 
        ("SizeOfUninitializedData",     DWORD), 
        ("AddressOfEntryPoint",         DWORD), 
        ("BaseOfCode",                  DWORD), 
        ("ImageBase",                   ULONGLONG), 
        ("SectionAlignment",            DWORD), 
        ("FileAlignment",               DWORD), 
        ("MajorOperatingSystemVersion", WORD), 
        ("MinorOperatingSystemVersion", WORD), 
        ("MajorImageVersion",           WORD), 
        ("MinorImageVersion",           WORD), 
        ("MajorSubsystemVersion",       WORD), 
        ("MinorSubsystemVersion",       WORD), 
        ("Win32VersionValue",           DWORD), 
        ("SizeOfImage",                 DWORD), 
        ("SizeOfHeaders",               DWORD), 
        ("CheckSum",                    DWORD), 
        ("Subsystem",                   WORD), 
        ("DllCharacteristics",          WORD), 
        ("SizeOfStackReserve",          ULONGLONG), 
        ("SizeOfStackCommit",           ULONGLONG), 
        ("SizeOfHeapReserve",           ULONGLONG), 
        ("SizeOfHeapCommit",            ULONGLONG), 
        ("LoaderFlags",                 DWORD), 
        ("NumberOfRvaAndSizes",         DWORD), 
        ("DataDirectory",               IMAGE_DATA_DIRECTORY*IMAGE_NUMBEROF_DIRECTORY_ENTRIES), 
    ]
PIMAGE_OPTIONAL_HEADER64 = POINTER(IMAGE_OPTIONAL_HEADER64)

IMAGE_NT_OPTIONAL_HDR32_MAGIC   = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC   = 0x20b
IMAGE_ROM_OPTIONAL_HDR_MAGIC    = 0x107

IMAGE_SUBSYSTEM_UNKNOWN                     = 0
IMAGE_SUBSYSTEM_NATIVE                      = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI                 = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI                 = 3
IMAGE_SUBSYSTEM_OS2_CUI                     = 5
IMAGE_SUBSYSTEM_POSIX_CUI                   = 7
IMAGE_SUBSYSTEM_WINDOWS_CE_GUI              = 9
IMAGE_SUBSYSTEM_EFI_APPLICATION             = 10
IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER     = 11
IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER          = 12
IMAGE_SUBSYSTEM_EFI_ROM                     = 13
IMAGE_SUBSYSTEM_XBOX                        = 14
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION    = 16

IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE           = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY        = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT              = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_ISOLATION           = 0x0200
IMAGE_DLLCHARACTERISTICS_NO_SEH                 = 0x0400
IMAGE_DLLCHARACTERISTICS_NO_BIND                = 0x0800
IMAGE_DLLCHARACTERISTICS_WDM_DRIVER             = 0x2000
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE  = 0x000


class IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ("Signature",       DWORD),
        ("FileHeader",      IMAGE_FILE_HEADER),
        ("OptionalHeader",  IMAGE_OPTIONAL_HEADER32),
    ]
PIMAGE_NT_HEADERS32 = POINTER(IMAGE_NT_HEADERS32)

class IMAGE_NT_HEADERS64(Structure):
    _fields_ = [
        ("Signature",       DWORD),
        ("FileHeader",      IMAGE_FILE_HEADER),
        ("OptionalHeader",  IMAGE_OPTIONAL_HEADER32),
    ]
PIMAGE_NT_HEADERS64 = POINTER(IMAGE_NT_HEADERS64)


class IMAGE_SECTION_HEADER(Structure):
    class Misc(Union):
        _fields_ = [
            ("PhysicalAddress",  DWORD),
            ("VirtualSize",      DWORD),
        ]
    _fields_ = [
        ("Name",                    BYTE * 8), 
        ("Misc",                    Misc), 
        ("VirtualAddress",          DWORD), 
        ("SizeOfRawData",           DWORD), 
        ("PointerToRawData",        DWORD), 
        ("PointerToRelocations",    DWORD), 
        ("PointerToLinenumbers",    DWORD), 
        ("NumberOfRelocations",     WORD), 
        ("NumberOfLinenumbers",     WORD), 
        ("Characteristics",         DWORD), 
    ]
PIMAGE_SECTION_HEADER = POINTER(IMAGE_SECTION_HEADER)


class IMAGE_EXPORT_DIRECTORY(Structure):
    _fields_ = [
        ("Characteristics",        DWORD),
        ("TimeDateStamp",          DWORD),
        ("MajorVersion",           WORD),
        ("MinorVersion",           WORD),
        ("Name",                   DWORD),
        ("Base",                   DWORD),
        ("NumberOfFunctions",      DWORD),
        ("NumberOfNames",          DWORD),
        ("AddressOfFunctions",     DWORD),
        ("AddressOfNames",         DWORD),
        ("AddressOfNameOrdinals",  DWORD),
    ]
PIMAGE_EXPORT_DIRECTORY = POINTER(IMAGE_EXPORT_DIRECTORY)


class IMAGE_IMPORT_DESCRIPTOR(Structure):
    class _U(Union):
        _fields_ = [
            ("Characteristics",     DWORD),
            ("OriginalFirstThunk",  DWORD),
        ]

    _anonymous_ = ("_u",)
    _fields_ = [
        ("_u",              _U),
        ("TimeDateStamp",   DWORD),
        ("ForwarderChain",  DWORD),
        ("Name",            DWORD),
        ("FirstThunk",      DWORD),
    ]

class IMAGE_THUNK_DATA32(Structure):
    class _U(Union):
        _fields_ = [
            ("ForwarderString", DWORD),
            ("Function",        DWORD),
            ("Ordinal",         DWORD),
            ("AddressOfData",   DWORD),
        ]
    _fields_ = [
        ("u1",  _U),
    ]
PIMAGE_THUNK_DATA32 = POINTER(IMAGE_THUNK_DATA32)

class IMAGE_THUNK_DATA64(Structure):
    class _U(Union):
        _fields_ = [
            ("ForwarderString", ULONGLONG),
            ("Function",        ULONGLONG),
            ("Ordinal",         ULONGLONG),
            ("AddressOfData",   ULONGLONG),
        ]
    _fileds_ = [
        ("u1",  _U),
    ]
PIMAGE_THUNK_DATA64 = POINTER(IMAGE_THUNK_DATA64)


class IMAGE_IMPORT_BY_NAME(Structure):
    _fields_ = [
        ("Hint",    WORD),
        ("Name",    BYTE * 16),
    ]
PIMAGE_IMPORT_BY_NAME = POINTER(IMAGE_IMPORT_BY_NAME)
