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
