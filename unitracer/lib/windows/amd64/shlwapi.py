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
Wrapper for shlwapi.dll in ctypes.
"""

__revision__ = "$Id: shlwapi.py 1299 2013-12-20 09:30:55Z qvasimodo $"

from defines import *
from kernel32 import *

#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
#==============================================================================

OS_WINDOWS                  = 0
OS_NT                       = 1
OS_WIN95ORGREATER           = 2
OS_NT4ORGREATER             = 3
OS_WIN98ORGREATER           = 5
OS_WIN98_GOLD               = 6
OS_WIN2000ORGREATER         = 7
OS_WIN2000PRO               = 8
OS_WIN2000SERVER            = 9
OS_WIN2000ADVSERVER         = 10
OS_WIN2000DATACENTER        = 11
OS_WIN2000TERMINAL          = 12
OS_EMBEDDED                 = 13
OS_TERMINALCLIENT           = 14
OS_TERMINALREMOTEADMIN      = 15
OS_WIN95_GOLD               = 16
OS_MEORGREATER              = 17
OS_XPORGREATER              = 18
OS_HOME                     = 19
OS_PROFESSIONAL             = 20
OS_DATACENTER               = 21
OS_ADVSERVER                = 22
OS_SERVER                   = 23
OS_TERMINALSERVER           = 24
OS_PERSONALTERMINALSERVER   = 25
OS_FASTUSERSWITCHING        = 26
OS_WELCOMELOGONUI           = 27
OS_DOMAINMEMBER             = 28
OS_ANYSERVER                = 29
OS_WOW6432                  = 30
OS_WEBSERVER                = 31
OS_SMALLBUSINESSSERVER      = 32
OS_TABLETPC                 = 33
OS_SERVERADMINUI            = 34
OS_MEDIACENTER              = 35
OS_APPLIANCE                = 36


#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
#==============================================================================
