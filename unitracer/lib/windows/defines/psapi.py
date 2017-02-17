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
Wrapper for psapi.dll in ctypes.
"""

__revision__ = "$Id: psapi.py 1299 2013-12-20 09:30:55Z qvasimodo $"

from defines import *

#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
#==============================================================================

#--- PSAPI structures and constants -------------------------------------------

LIST_MODULES_DEFAULT    = 0x00
LIST_MODULES_32BIT      = 0x01
LIST_MODULES_64BIT      = 0x02
LIST_MODULES_ALL        = 0x03

# typedef struct _MODULEINFO {
#   LPVOID lpBaseOfDll;
#   DWORD  SizeOfImage;
#   LPVOID EntryPoint;
# } MODULEINFO, *LPMODULEINFO;
class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll",     LPVOID),    # remote pointer
        ("SizeOfImage",     DWORD),
        ("EntryPoint",      LPVOID),    # remote pointer
]
LPMODULEINFO = POINTER(MODULEINFO)


#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
#==============================================================================
