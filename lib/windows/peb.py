from ctypes import *



class LIST_ENTRY(Structure):
    pass
LIST_ENTRY._fields_ = [
    ("Flink",                       POINTER(LIST_ENTRY)),
    ("Blink",                       POINTER(LIST_ENTRY)),
]

class PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Reserved1",                   c_byte*8),
        ("Reserved2",                   c_void_p*3),
        ("InMemoryOrderModuleList",     LIST_ENTRY),
    ]
PPEB_LDR_DATA = POINTER(PEB_LDR_DATA)

class LDR_DATA_TABLE_ENTRY(Structure):
    class _U(Union):
        _fields_ = [
            ("CheckSum", c_ulong),
            ("Reserved6", c_void_p),
        ]

    _anonymous_ = ("_u",)
    _fields_ = [
        ("Reserved1",                   c_void_p*2),
        ("InMemoryOrderLinks",          LIST_ENTRY),
        ("Reserved2",                   c_void_p*2),
        ("DllBase",                     c_void_p),
        ("EntryPoint",                  c_void_p),
        ("Reserved3",                   c_void_p),
        ("FullDllName",                 c_wchar_p),
        ("Reserved4",                   c_byte*8),
        ("Reserved5",                   c_void_p*3),
        ("_u",                            _U),
        ("TimeDateStamp",               c_ulong),
    ]
PLDR_DATA_TABLE_ENTRY = POINTER(LDR_DATA_TABLE_ENTRY)


class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved1",                   c_byte*16),
        ("Reserved2",                   c_void_p*10),
        ("ImagePathName",               c_wchar_p),
        ("CommandLine",                 c_wchar_p),
    ]
PRTL_USER_PROCESS_PARAMETERS = POINTER(RTL_USER_PROCESS_PARAMETERS)



class PEB(Structure):
    _fields_ = [
        ("Reserved1",                   c_byte*2),
        ("BeingDebugged",               c_byte),
        ("Reserved2",                   c_byte*1),
        ("Reserved3",                   c_void_p*2),
        ("Ldr",                         PPEB_LDR_DATA),
        ("ProcessParameters",           PRTL_USER_PROCESS_PARAMETERS),
        ("Reserved4",                   c_byte*104),
        ("Reserved5",                   c_byte*52),
        ("PostProcessInitRoutine",      c_void_p),
        ("Reserved6",                   c_byte*128),
        ("Reserved7",                   c_void_p*1),
        ("SessionId",                   c_ulong),
    ]


