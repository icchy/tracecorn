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


import ctypes


#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
#==============================================================================


#--- Types --------------------------------------------------------------------
# http://msdn.microsoft.com/en-us/library/aa383751(v=vs.85).aspx

# Map of basic C types to Win32 types
LPVOID      = ctypes.c_void_p
CHAR        = ctypes.c_char
WCHAR       = ctypes.c_wchar
BYTE        = ctypes.c_ubyte
SBYTE       = ctypes.c_byte
WORD        = ctypes.c_uint16
SWORD       = ctypes.c_int16
DWORD       = ctypes.c_uint32
SDWORD      = ctypes.c_int32
QWORD       = ctypes.c_uint64
SQWORD      = ctypes.c_int64
SHORT       = ctypes.c_short
USHORT      = ctypes.c_ushort
INT         = ctypes.c_int
UINT        = ctypes.c_uint
LONG        = ctypes.c_int32
ULONG       = ctypes.c_uint32
LONGLONG    = ctypes.c_int64        # c_longlong
ULONGLONG   = ctypes.c_uint64       # c_ulonglong
LPSTR       = ctypes.c_char_p
LPWSTR      = ctypes.c_wchar_p
INT8        = ctypes.c_int8
INT16       = ctypes.c_int16
INT32       = ctypes.c_int32
INT64       = ctypes.c_int64
UINT8       = ctypes.c_uint8
UINT16      = ctypes.c_uint16
UINT32      = ctypes.c_uint32
UINT64      = ctypes.c_uint64
LONG32      = ctypes.c_int32
LONG64      = ctypes.c_int64
ULONG32     = ctypes.c_uint32
ULONG64     = ctypes.c_uint64
DWORD32     = ctypes.c_uint32
DWORD64     = ctypes.c_uint64
BOOL        = ctypes.c_int
FLOAT       = ctypes.c_float

#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
##__all__ = [_x for _x in _all if not _x.startswith('_')]
##__all__.sort()
#==============================================================================
