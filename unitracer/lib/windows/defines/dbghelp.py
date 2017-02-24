#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2014, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Wrapper for dbghelp.dll in ctypes.
"""

__revision__ = "$Id: dbghelp.py 1299 2013-12-20 09:30:55Z qvasimodo $"

from defines import *
from version import *
from kernel32 import *

# DbgHelp versions and features list:
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms679294(v=vs.85).aspx

#------------------------------------------------------------------------------
# Tries to load the newest version of dbghelp.dll if available.

def _load_latest_dbghelp_dll():

    from os import getenv
    from os.path import join

    if arch == ARCH_AMD64:
        if wow64:
            pathname = join(
                            getenv("ProgramFiles(x86)",
                                getenv("ProgramFiles")),
                            "Debugging Tools for Windows (x86)",
                            "dbghelp.dll")
        else:
            pathname = join(
                            getenv("ProgramFiles"),
                            "Debugging Tools for Windows (x64)",
                            "dbghelp.dll")
    elif arch == ARCH_I386:
        pathname = join(
                        getenv("ProgramFiles"),
                        "Debugging Tools for Windows (x86)",
                        "dbghelp.dll")
    else:
        pathname = None

    if pathname:
        try:
            _dbghelp = ctypes.windll.LoadLibrary(pathname)
            ctypes.windll.dbghelp = _dbghelp
        except Exception:
            pass

_load_latest_dbghelp_dll()

# Recover the old binding of the "os" symbol.
# XXX FIXME not sure if I really need to do this!
##from version import os

#------------------------------------------------------------------------------

#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
#==============================================================================

# SymGetHomeDirectory "type" values
hdBase = 0
hdSym  = 1
hdSrc  = 2

UNDNAME_32_BIT_DECODE           = 0x0800
UNDNAME_COMPLETE                = 0x0000
UNDNAME_NAME_ONLY               = 0x1000
UNDNAME_NO_ACCESS_SPECIFIERS    = 0x0080
UNDNAME_NO_ALLOCATION_LANGUAGE  = 0x0010
UNDNAME_NO_ALLOCATION_MODEL     = 0x0008
UNDNAME_NO_ARGUMENTS            = 0x2000
UNDNAME_NO_CV_THISTYPE          = 0x0040
UNDNAME_NO_FUNCTION_RETURNS     = 0x0004
UNDNAME_NO_LEADING_UNDERSCORES  = 0x0001
UNDNAME_NO_MEMBER_TYPE          = 0x0200
UNDNAME_NO_MS_KEYWORDS          = 0x0002
UNDNAME_NO_MS_THISTYPE          = 0x0020
UNDNAME_NO_RETURN_UDT_MODEL     = 0x0400
UNDNAME_NO_SPECIAL_SYMS         = 0x4000
UNDNAME_NO_THISTYPE             = 0x0060
UNDNAME_NO_THROW_SIGNATURES     = 0x0100

#--- IMAGEHLP_MODULE structure and related ------------------------------------

SYMOPT_ALLOW_ABSOLUTE_SYMBOLS       = 0x00000800
SYMOPT_ALLOW_ZERO_ADDRESS           = 0x01000000
SYMOPT_AUTO_PUBLICS                 = 0x00010000
SYMOPT_CASE_INSENSITIVE             = 0x00000001
SYMOPT_DEBUG                        = 0x80000000
SYMOPT_DEFERRED_LOADS               = 0x00000004
SYMOPT_DISABLE_SYMSRV_AUTODETECT    = 0x02000000
SYMOPT_EXACT_SYMBOLS                = 0x00000400
SYMOPT_FAIL_CRITICAL_ERRORS         = 0x00000200
SYMOPT_FAVOR_COMPRESSED             = 0x00800000
SYMOPT_FLAT_DIRECTORY               = 0x00400000
SYMOPT_IGNORE_CVREC                 = 0x00000080
SYMOPT_IGNORE_IMAGEDIR              = 0x00200000
SYMOPT_IGNORE_NT_SYMPATH            = 0x00001000
SYMOPT_INCLUDE_32BIT_MODULES        = 0x00002000
SYMOPT_LOAD_ANYTHING                = 0x00000040
SYMOPT_LOAD_LINES                   = 0x00000010
SYMOPT_NO_CPP                       = 0x00000008
SYMOPT_NO_IMAGE_SEARCH              = 0x00020000
SYMOPT_NO_PROMPTS                   = 0x00080000
SYMOPT_NO_PUBLICS                   = 0x00008000
SYMOPT_NO_UNQUALIFIED_LOADS         = 0x00000100
SYMOPT_OVERWRITE                    = 0x00100000
SYMOPT_PUBLICS_ONLY                 = 0x00004000
SYMOPT_SECURE                       = 0x00040000
SYMOPT_UNDNAME                      = 0x00000002

##SSRVOPT_DWORD
##SSRVOPT_DWORDPTR
##SSRVOPT_GUIDPTR
##
##SSRVOPT_CALLBACK
##SSRVOPT_DOWNSTREAM_STORE
##SSRVOPT_FLAT_DEFAULT_STORE
##SSRVOPT_FAVOR_COMPRESSED
##SSRVOPT_NOCOPY
##SSRVOPT_OVERWRITE
##SSRVOPT_PARAMTYPE
##SSRVOPT_PARENTWIN
##SSRVOPT_PROXY
##SSRVOPT_RESET
##SSRVOPT_SECURE
##SSRVOPT_SETCONTEXT
##SSRVOPT_TRACE
##SSRVOPT_UNATTENDED

#    typedef enum
#    {
#        SymNone = 0,
#        SymCoff,
#        SymCv,
#        SymPdb,
#        SymExport,
#        SymDeferred,
#        SymSym,
#        SymDia,
#        SymVirtual,
#        NumSymTypes
#    } SYM_TYPE;
SymNone     = 0
SymCoff     = 1
SymCv       = 2
SymPdb      = 3
SymExport   = 4
SymDeferred = 5
SymSym      = 6
SymDia      = 7
SymVirtual  = 8
NumSymTypes = 9

#    typedef struct _IMAGEHLP_MODULE64 {
#      DWORD    SizeOfStruct;
#      DWORD64  BaseOfImage;
#      DWORD    ImageSize;
#      DWORD    TimeDateStamp;
#      DWORD    CheckSum;
#      DWORD    NumSyms;
#      SYM_TYPE SymType;
#      TCHAR    ModuleName[32];
#      TCHAR    ImageName[256];
#      TCHAR    LoadedImageName[256];
#      TCHAR    LoadedPdbName[256];
#      DWORD    CVSig;
#      TCHAR    CVData[MAX_PATH*3];
#      DWORD    PdbSig;
#      GUID     PdbSig70;
#      DWORD    PdbAge;
#      BOOL     PdbUnmatched;
#      BOOL     DbgUnmatched;
#      BOOL     LineNumbers;
#      BOOL     GlobalSymbols;
#      BOOL     TypeInfo;
#      BOOL     SourceIndexed;
#      BOOL     Publics;
#    } IMAGEHLP_MODULE64, *PIMAGEHLP_MODULE64;

class IMAGEHLP_MODULE (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
    ]
PIMAGEHLP_MODULE = POINTER(IMAGEHLP_MODULE)

class IMAGEHLP_MODULE64 (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
        ("LoadedPdbName",   CHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          CHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]
PIMAGEHLP_MODULE64 = POINTER(IMAGEHLP_MODULE64)

class IMAGEHLP_MODULEW (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
    ]
PIMAGEHLP_MODULEW = POINTER(IMAGEHLP_MODULEW)

class IMAGEHLP_MODULEW64 (Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
        ("LoadedPdbName",   WCHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          WCHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]
PIMAGEHLP_MODULEW64 = POINTER(IMAGEHLP_MODULEW64)


#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
#==============================================================================
