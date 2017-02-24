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
Wrapper for kernel32.dll in ctypes.
"""

__revision__ = "$Id: kernel32.py 1299 2013-12-20 09:30:55Z qvasimodo $"

import warnings

from defines import *

import context_i386
# import context_amd64

#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
_all.add('version')
#==============================================================================

from version import *

#------------------------------------------------------------------------------

# This can't be defined in defines.py because it calls GetLastError().
def RaiseIfLastError(result, func = None, arguments = ()):
    """
    Error checking for Win32 API calls with no error-specific return value.

    Regardless of the return value, the function calls GetLastError(). If the
    code is not C{ERROR_SUCCESS} then a C{WindowsError} exception is raised.

    For this to work, the user MUST call SetLastError(ERROR_SUCCESS) prior to
    calling the API. Otherwise an exception may be raised even on success,
    since most API calls don't clear the error status code.
    """
    code = GetLastError()
    if code != ERROR_SUCCESS:
        raise ctypes.WinError(code)
    return result

#--- CONTEXT structure and constants ------------------------------------------

ContextArchMask = 0x0FFF0000    # just guessing here! seems to work, though

if   arch == ARCH_I386:
    from context_i386 import *
elif arch == ARCH_AMD64:
    if bits == 64:
        from context_amd64 import *
    else:
        from context_i386 import *
else:
    warnings.warn("Unknown or unsupported architecture: %s" % arch)

#--- Constants ----------------------------------------------------------------

STILL_ACTIVE = 259

WAIT_TIMEOUT        = 0x102
WAIT_FAILED         = -1
WAIT_OBJECT_0       = 0

EXCEPTION_NONCONTINUABLE        = 0x1       # Noncontinuable exception
EXCEPTION_MAXIMUM_PARAMETERS    = 15        # maximum number of exception parameters
MAXIMUM_WAIT_OBJECTS            = 64        # Maximum number of wait objects
MAXIMUM_SUSPEND_COUNT           = 0x7f      # Maximum times thread can be suspended

FORMAT_MESSAGE_ALLOCATE_BUFFER  = 0x00000100
FORMAT_MESSAGE_FROM_SYSTEM      = 0x00001000

GR_GDIOBJECTS  = 0
GR_USEROBJECTS = 1

PROCESS_NAME_NATIVE = 1

MAXINTATOM = 0xC000

STD_INPUT_HANDLE  = 0xFFFFFFF6      # (DWORD)-10
STD_OUTPUT_HANDLE = 0xFFFFFFF5      # (DWORD)-11
STD_ERROR_HANDLE  = 0xFFFFFFF4      # (DWORD)-12

ATTACH_PARENT_PROCESS = 0xFFFFFFFF  # (DWORD)-1

# LoadLibraryEx constants
DONT_RESOLVE_DLL_REFERENCES         = 0x00000001
LOAD_LIBRARY_AS_DATAFILE            = 0x00000002
LOAD_WITH_ALTERED_SEARCH_PATH       = 0x00000008
LOAD_IGNORE_CODE_AUTHZ_LEVEL        = 0x00000010
LOAD_LIBRARY_AS_IMAGE_RESOURCE      = 0x00000020
LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE  = 0x00000040

# SetSearchPathMode flags
# TODO I couldn't find these constants :(
##BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE     = ???
##BASE_SEARCH_PATH_DISABLE_SAFE_SEARCHMODE    = ???
##BASE_SEARCH_PATH_PERMANENT                  = ???

# Console control events
CTRL_C_EVENT        = 0
CTRL_BREAK_EVENT    = 1
CTRL_CLOSE_EVENT    = 2
CTRL_LOGOFF_EVENT   = 5
CTRL_SHUTDOWN_EVENT = 6

# Heap flags
HEAP_NO_SERIALIZE           = 0x00000001
HEAP_GENERATE_EXCEPTIONS    = 0x00000004
HEAP_ZERO_MEMORY            = 0x00000008
HEAP_CREATE_ENABLE_EXECUTE  = 0x00040000

# Standard access rights
DELETE                      = (0x00010000L)
READ_CONTROL                = (0x00020000L)
WRITE_DAC                   = (0x00040000L)
WRITE_OWNER                 = (0x00080000L)
SYNCHRONIZE                 = (0x00100000L)
STANDARD_RIGHTS_REQUIRED    = (0x000F0000L)
STANDARD_RIGHTS_READ        = (READ_CONTROL)
STANDARD_RIGHTS_WRITE       = (READ_CONTROL)
STANDARD_RIGHTS_EXECUTE     = (READ_CONTROL)
STANDARD_RIGHTS_ALL         = (0x001F0000L)
SPECIFIC_RIGHTS_ALL         = (0x0000FFFFL)

# Mutex access rights
MUTEX_ALL_ACCESS   = 0x1F0001
MUTEX_MODIFY_STATE = 1

# Event access rights
EVENT_ALL_ACCESS   = 0x1F0003
EVENT_MODIFY_STATE = 2

# Semaphore access rights
SEMAPHORE_ALL_ACCESS   = 0x1F0003
SEMAPHORE_MODIFY_STATE = 2

# Timer access rights
TIMER_ALL_ACCESS   = 0x1F0003
TIMER_MODIFY_STATE = 2
TIMER_QUERY_STATE  = 1

# Process access rights for OpenProcess
PROCESS_TERMINATE                 = 0x0001
PROCESS_CREATE_THREAD             = 0x0002
PROCESS_SET_SESSIONID             = 0x0004
PROCESS_VM_OPERATION              = 0x0008
PROCESS_VM_READ                   = 0x0010
PROCESS_VM_WRITE                  = 0x0020
PROCESS_DUP_HANDLE                = 0x0040
PROCESS_CREATE_PROCESS            = 0x0080
PROCESS_SET_QUOTA                 = 0x0100
PROCESS_SET_INFORMATION           = 0x0200
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_SUSPEND_RESUME            = 0x0800
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Thread access rights for OpenThread
THREAD_TERMINATE                 = 0x0001
THREAD_SUSPEND_RESUME            = 0x0002
THREAD_ALERT                     = 0x0004
THREAD_GET_CONTEXT               = 0x0008
THREAD_SET_CONTEXT               = 0x0010
THREAD_SET_INFORMATION           = 0x0020
THREAD_QUERY_INFORMATION         = 0x0040
THREAD_SET_THREAD_TOKEN          = 0x0080
THREAD_IMPERSONATE               = 0x0100
THREAD_DIRECT_IMPERSONATION      = 0x0200
THREAD_SET_LIMITED_INFORMATION   = 0x0400
THREAD_QUERY_LIMITED_INFORMATION = 0x0800

# The values of PROCESS_ALL_ACCESS and THREAD_ALL_ACCESS were changed in Vista/2008
PROCESS_ALL_ACCESS_NT = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF)
PROCESS_ALL_ACCESS_VISTA = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
THREAD_ALL_ACCESS_NT = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x3FF)
THREAD_ALL_ACCESS_VISTA = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
if NTDDI_VERSION < NTDDI_VISTA:
    PROCESS_ALL_ACCESS = PROCESS_ALL_ACCESS_NT
    THREAD_ALL_ACCESS = THREAD_ALL_ACCESS_NT
else:
    PROCESS_ALL_ACCESS = PROCESS_ALL_ACCESS_VISTA
    THREAD_ALL_ACCESS = THREAD_ALL_ACCESS_VISTA

# Process priority classes

IDLE_PRIORITY_CLASS         = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS       = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS         = 0x00000080
REALTIME_PRIORITY_CLASS     = 0x00000100

PROCESS_MODE_BACKGROUND_BEGIN   = 0x00100000
PROCESS_MODE_BACKGROUND_END     = 0x00200000

# dwCreationFlag values

DEBUG_PROCESS                     = 0x00000001
DEBUG_ONLY_THIS_PROCESS           = 0x00000002
CREATE_SUSPENDED                  = 0x00000004    # Threads and processes
DETACHED_PROCESS                  = 0x00000008
CREATE_NEW_CONSOLE                = 0x00000010
NORMAL_PRIORITY_CLASS             = 0x00000020
IDLE_PRIORITY_CLASS               = 0x00000040
HIGH_PRIORITY_CLASS               = 0x00000080
REALTIME_PRIORITY_CLASS           = 0x00000100
CREATE_NEW_PROCESS_GROUP          = 0x00000200
CREATE_UNICODE_ENVIRONMENT        = 0x00000400
CREATE_SEPARATE_WOW_VDM           = 0x00000800
CREATE_SHARED_WOW_VDM             = 0x00001000
CREATE_FORCEDOS                   = 0x00002000
BELOW_NORMAL_PRIORITY_CLASS       = 0x00004000
ABOVE_NORMAL_PRIORITY_CLASS       = 0x00008000
INHERIT_PARENT_AFFINITY           = 0x00010000
STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000    # Threads only
INHERIT_CALLER_PRIORITY           = 0x00020000    # Deprecated
CREATE_PROTECTED_PROCESS          = 0x00040000
EXTENDED_STARTUPINFO_PRESENT      = 0x00080000
PROCESS_MODE_BACKGROUND_BEGIN     = 0x00100000
PROCESS_MODE_BACKGROUND_END       = 0x00200000
CREATE_BREAKAWAY_FROM_JOB         = 0x01000000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL  = 0x02000000
CREATE_DEFAULT_ERROR_MODE         = 0x04000000
CREATE_NO_WINDOW                  = 0x08000000
PROFILE_USER                      = 0x10000000
PROFILE_KERNEL                    = 0x20000000
PROFILE_SERVER                    = 0x40000000
CREATE_IGNORE_SYSTEM_DEFAULT      = 0x80000000

# Thread priority values

THREAD_BASE_PRIORITY_LOWRT  = 15    # value that gets a thread to LowRealtime-1
THREAD_BASE_PRIORITY_MAX    = 2     # maximum thread base priority boost
THREAD_BASE_PRIORITY_MIN    = (-2)  # minimum thread base priority boost
THREAD_BASE_PRIORITY_IDLE   = (-15) # value that gets a thread to idle

THREAD_PRIORITY_LOWEST          = THREAD_BASE_PRIORITY_MIN
THREAD_PRIORITY_BELOW_NORMAL    = (THREAD_PRIORITY_LOWEST+1)
THREAD_PRIORITY_NORMAL          = 0
THREAD_PRIORITY_HIGHEST         = THREAD_BASE_PRIORITY_MAX
THREAD_PRIORITY_ABOVE_NORMAL    = (THREAD_PRIORITY_HIGHEST-1)
THREAD_PRIORITY_ERROR_RETURN    = (0xFFFFFFFFL)

THREAD_PRIORITY_TIME_CRITICAL   = THREAD_BASE_PRIORITY_LOWRT
THREAD_PRIORITY_IDLE            = THREAD_BASE_PRIORITY_IDLE

# Memory access
SECTION_QUERY                = 0x0001
SECTION_MAP_WRITE            = 0x0002
SECTION_MAP_READ             = 0x0004
SECTION_MAP_EXECUTE          = 0x0008
SECTION_EXTEND_SIZE          = 0x0010
SECTION_MAP_EXECUTE_EXPLICIT = 0x0020 # not included in SECTION_ALL_ACCESS

SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                             SECTION_MAP_WRITE |      \
                             SECTION_MAP_READ |       \
                             SECTION_MAP_EXECUTE |    \
                             SECTION_EXTEND_SIZE)
PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD            = 0x100
PAGE_NOCACHE          = 0x200
PAGE_WRITECOMBINE     = 0x400
MEM_COMMIT           = 0x1000
MEM_RESERVE          = 0x2000
MEM_DECOMMIT         = 0x4000
MEM_RELEASE          = 0x8000
MEM_FREE            = 0x10000
MEM_PRIVATE         = 0x20000
MEM_MAPPED          = 0x40000
MEM_RESET           = 0x80000
MEM_TOP_DOWN       = 0x100000
MEM_WRITE_WATCH    = 0x200000
MEM_PHYSICAL       = 0x400000
MEM_LARGE_PAGES  = 0x20000000
MEM_4MB_PAGES    = 0x80000000
SEC_FILE           = 0x800000
SEC_IMAGE         = 0x1000000
SEC_RESERVE       = 0x4000000
SEC_COMMIT        = 0x8000000
SEC_NOCACHE      = 0x10000000
SEC_LARGE_PAGES  = 0x80000000
MEM_IMAGE         = SEC_IMAGE
WRITE_WATCH_FLAG_RESET = 0x01
FILE_MAP_ALL_ACCESS = 0xF001F

SECTION_QUERY                   = 0x0001
SECTION_MAP_WRITE               = 0x0002
SECTION_MAP_READ                = 0x0004
SECTION_MAP_EXECUTE             = 0x0008
SECTION_EXTEND_SIZE             = 0x0010
SECTION_MAP_EXECUTE_EXPLICIT    = 0x0020 # not included in SECTION_ALL_ACCESS

SECTION_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED|SECTION_QUERY|\
                 SECTION_MAP_WRITE |      \
                 SECTION_MAP_READ |       \
                 SECTION_MAP_EXECUTE |    \
                 SECTION_EXTEND_SIZE)

FILE_MAP_COPY       = SECTION_QUERY
FILE_MAP_WRITE      = SECTION_MAP_WRITE
FILE_MAP_READ       = SECTION_MAP_READ
FILE_MAP_ALL_ACCESS = SECTION_ALL_ACCESS
FILE_MAP_EXECUTE    = SECTION_MAP_EXECUTE_EXPLICIT  # not included in FILE_MAP_ALL_ACCESS

GENERIC_READ                     = 0x80000000
GENERIC_WRITE                    = 0x40000000
GENERIC_EXECUTE                  = 0x20000000
GENERIC_ALL                      = 0x10000000

FILE_SHARE_READ                  = 0x00000001
FILE_SHARE_WRITE                 = 0x00000002
FILE_SHARE_DELETE                = 0x00000004

CREATE_NEW                       = 1
CREATE_ALWAYS                    = 2
OPEN_EXISTING                    = 3
OPEN_ALWAYS                      = 4
TRUNCATE_EXISTING                = 5

FILE_ATTRIBUTE_READONLY          = 0x00000001
FILE_ATTRIBUTE_NORMAL            = 0x00000080
FILE_ATTRIBUTE_TEMPORARY         = 0x00000100

FILE_FLAG_WRITE_THROUGH          = 0x80000000
FILE_FLAG_NO_BUFFERING           = 0x20000000
FILE_FLAG_RANDOM_ACCESS          = 0x10000000
FILE_FLAG_SEQUENTIAL_SCAN        = 0x08000000
FILE_FLAG_DELETE_ON_CLOSE        = 0x04000000
FILE_FLAG_OVERLAPPED             = 0x40000000

FILE_ATTRIBUTE_READONLY          = 0x00000001
FILE_ATTRIBUTE_HIDDEN            = 0x00000002
FILE_ATTRIBUTE_SYSTEM            = 0x00000004
FILE_ATTRIBUTE_DIRECTORY         = 0x00000010
FILE_ATTRIBUTE_ARCHIVE           = 0x00000020
FILE_ATTRIBUTE_DEVICE            = 0x00000040
FILE_ATTRIBUTE_NORMAL            = 0x00000080
FILE_ATTRIBUTE_TEMPORARY         = 0x00000100

# Debug events
EXCEPTION_DEBUG_EVENT       = 1
CREATE_THREAD_DEBUG_EVENT   = 2
CREATE_PROCESS_DEBUG_EVENT  = 3
EXIT_THREAD_DEBUG_EVENT     = 4
EXIT_PROCESS_DEBUG_EVENT    = 5
LOAD_DLL_DEBUG_EVENT        = 6
UNLOAD_DLL_DEBUG_EVENT      = 7
OUTPUT_DEBUG_STRING_EVENT   = 8
RIP_EVENT                   = 9

# Debug status codes (ContinueDebugEvent)
DBG_EXCEPTION_HANDLED           = 0x00010001L
DBG_CONTINUE                    = 0x00010002L
DBG_REPLY_LATER                 = 0x40010001L
DBG_UNABLE_TO_PROVIDE_HANDLE    = 0x40010002L
DBG_TERMINATE_THREAD            = 0x40010003L
DBG_TERMINATE_PROCESS           = 0x40010004L
DBG_CONTROL_C                   = 0x40010005L
DBG_PRINTEXCEPTION_C            = 0x40010006L
DBG_RIPEXCEPTION                = 0x40010007L
DBG_CONTROL_BREAK               = 0x40010008L
DBG_COMMAND_EXCEPTION           = 0x40010009L
DBG_EXCEPTION_NOT_HANDLED       = 0x80010001L
DBG_NO_STATE_CHANGE             = 0xC0010001L
DBG_APP_NOT_IDLE                = 0xC0010002L

# Status codes
STATUS_WAIT_0                   = 0x00000000L
STATUS_ABANDONED_WAIT_0         = 0x00000080L
STATUS_USER_APC                 = 0x000000C0L
STATUS_TIMEOUT                  = 0x00000102L
STATUS_PENDING                  = 0x00000103L
STATUS_SEGMENT_NOTIFICATION     = 0x40000005L
STATUS_GUARD_PAGE_VIOLATION     = 0x80000001L
STATUS_DATATYPE_MISALIGNMENT    = 0x80000002L
STATUS_BREAKPOINT               = 0x80000003L
STATUS_SINGLE_STEP              = 0x80000004L
STATUS_INVALID_INFO_CLASS       = 0xC0000003L
STATUS_ACCESS_VIOLATION         = 0xC0000005L
STATUS_IN_PAGE_ERROR            = 0xC0000006L
STATUS_INVALID_HANDLE           = 0xC0000008L
STATUS_NO_MEMORY                = 0xC0000017L
STATUS_ILLEGAL_INSTRUCTION      = 0xC000001DL
STATUS_NONCONTINUABLE_EXCEPTION = 0xC0000025L
STATUS_INVALID_DISPOSITION      = 0xC0000026L
STATUS_ARRAY_BOUNDS_EXCEEDED    = 0xC000008CL
STATUS_FLOAT_DENORMAL_OPERAND   = 0xC000008DL
STATUS_FLOAT_DIVIDE_BY_ZERO     = 0xC000008EL
STATUS_FLOAT_INEXACT_RESULT     = 0xC000008FL
STATUS_FLOAT_INVALID_OPERATION  = 0xC0000090L
STATUS_FLOAT_OVERFLOW           = 0xC0000091L
STATUS_FLOAT_STACK_CHECK        = 0xC0000092L
STATUS_FLOAT_UNDERFLOW          = 0xC0000093L
STATUS_INTEGER_DIVIDE_BY_ZERO   = 0xC0000094L
STATUS_INTEGER_OVERFLOW         = 0xC0000095L
STATUS_PRIVILEGED_INSTRUCTION   = 0xC0000096L
STATUS_STACK_OVERFLOW           = 0xC00000FDL
STATUS_CONTROL_C_EXIT           = 0xC000013AL
STATUS_FLOAT_MULTIPLE_FAULTS    = 0xC00002B4L
STATUS_FLOAT_MULTIPLE_TRAPS     = 0xC00002B5L
STATUS_REG_NAT_CONSUMPTION      = 0xC00002C9L
STATUS_SXS_EARLY_DEACTIVATION   = 0xC015000FL
STATUS_SXS_INVALID_DEACTIVATION = 0xC0150010L

STATUS_STACK_BUFFER_OVERRUN     = 0xC0000409L
STATUS_WX86_BREAKPOINT          = 0x4000001FL
STATUS_HEAP_CORRUPTION          = 0xC0000374L

STATUS_POSSIBLE_DEADLOCK        = 0xC0000194L

STATUS_UNWIND_CONSOLIDATE       = 0x80000029L

# Exception codes

EXCEPTION_ACCESS_VIOLATION          = STATUS_ACCESS_VIOLATION
EXCEPTION_ARRAY_BOUNDS_EXCEEDED     = STATUS_ARRAY_BOUNDS_EXCEEDED
EXCEPTION_BREAKPOINT                = STATUS_BREAKPOINT
EXCEPTION_DATATYPE_MISALIGNMENT     = STATUS_DATATYPE_MISALIGNMENT
EXCEPTION_FLT_DENORMAL_OPERAND      = STATUS_FLOAT_DENORMAL_OPERAND
EXCEPTION_FLT_DIVIDE_BY_ZERO        = STATUS_FLOAT_DIVIDE_BY_ZERO
EXCEPTION_FLT_INEXACT_RESULT        = STATUS_FLOAT_INEXACT_RESULT
EXCEPTION_FLT_INVALID_OPERATION     = STATUS_FLOAT_INVALID_OPERATION
EXCEPTION_FLT_OVERFLOW              = STATUS_FLOAT_OVERFLOW
EXCEPTION_FLT_STACK_CHECK           = STATUS_FLOAT_STACK_CHECK
EXCEPTION_FLT_UNDERFLOW             = STATUS_FLOAT_UNDERFLOW
EXCEPTION_ILLEGAL_INSTRUCTION       = STATUS_ILLEGAL_INSTRUCTION
EXCEPTION_IN_PAGE_ERROR             = STATUS_IN_PAGE_ERROR
EXCEPTION_INT_DIVIDE_BY_ZERO        = STATUS_INTEGER_DIVIDE_BY_ZERO
EXCEPTION_INT_OVERFLOW              = STATUS_INTEGER_OVERFLOW
EXCEPTION_INVALID_DISPOSITION       = STATUS_INVALID_DISPOSITION
EXCEPTION_NONCONTINUABLE_EXCEPTION  = STATUS_NONCONTINUABLE_EXCEPTION
EXCEPTION_PRIV_INSTRUCTION          = STATUS_PRIVILEGED_INSTRUCTION
EXCEPTION_SINGLE_STEP               = STATUS_SINGLE_STEP
EXCEPTION_STACK_OVERFLOW            = STATUS_STACK_OVERFLOW

EXCEPTION_GUARD_PAGE                = STATUS_GUARD_PAGE_VIOLATION
EXCEPTION_INVALID_HANDLE            = STATUS_INVALID_HANDLE
EXCEPTION_POSSIBLE_DEADLOCK         = STATUS_POSSIBLE_DEADLOCK
EXCEPTION_WX86_BREAKPOINT           = STATUS_WX86_BREAKPOINT

CONTROL_C_EXIT                      = STATUS_CONTROL_C_EXIT

DBG_CONTROL_C                       = 0x40010005L
MS_VC_EXCEPTION                     = 0x406D1388L

# Access violation types
ACCESS_VIOLATION_TYPE_READ      = EXCEPTION_READ_FAULT
ACCESS_VIOLATION_TYPE_WRITE     = EXCEPTION_WRITE_FAULT
ACCESS_VIOLATION_TYPE_DEP       = EXCEPTION_EXECUTE_FAULT

# RIP event types
SLE_ERROR      = 1
SLE_MINORERROR = 2
SLE_WARNING    = 3

# DuplicateHandle constants
DUPLICATE_CLOSE_SOURCE      = 0x00000001
DUPLICATE_SAME_ACCESS       = 0x00000002

# GetFinalPathNameByHandle constants
FILE_NAME_NORMALIZED        = 0x0
FILE_NAME_OPENED            = 0x8
VOLUME_NAME_DOS             = 0x0
VOLUME_NAME_GUID            = 0x1
VOLUME_NAME_NONE            = 0x4
VOLUME_NAME_NT              = 0x2

# GetProductInfo constants
PRODUCT_BUSINESS = 0x00000006
PRODUCT_BUSINESS_N = 0x00000010
PRODUCT_CLUSTER_SERVER = 0x00000012
PRODUCT_DATACENTER_SERVER = 0x00000008
PRODUCT_DATACENTER_SERVER_CORE = 0x0000000C
PRODUCT_DATACENTER_SERVER_CORE_V = 0x00000027
PRODUCT_DATACENTER_SERVER_V = 0x00000025
PRODUCT_ENTERPRISE = 0x00000004
PRODUCT_ENTERPRISE_E = 0x00000046
PRODUCT_ENTERPRISE_N = 0x0000001B
PRODUCT_ENTERPRISE_SERVER = 0x0000000A
PRODUCT_ENTERPRISE_SERVER_CORE = 0x0000000E
PRODUCT_ENTERPRISE_SERVER_CORE_V = 0x00000029
PRODUCT_ENTERPRISE_SERVER_IA64 = 0x0000000F
PRODUCT_ENTERPRISE_SERVER_V = 0x00000026
PRODUCT_HOME_BASIC = 0x00000002
PRODUCT_HOME_BASIC_E = 0x00000043
PRODUCT_HOME_BASIC_N = 0x00000005
PRODUCT_HOME_PREMIUM = 0x00000003
PRODUCT_HOME_PREMIUM_E = 0x00000044
PRODUCT_HOME_PREMIUM_N = 0x0000001A
PRODUCT_HYPERV = 0x0000002A
PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT = 0x0000001E
PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING = 0x00000020
PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY = 0x0000001F
PRODUCT_PROFESSIONAL = 0x00000030
PRODUCT_PROFESSIONAL_E = 0x00000045
PRODUCT_PROFESSIONAL_N = 0x00000031
PRODUCT_SERVER_FOR_SMALLBUSINESS = 0x00000018
PRODUCT_SERVER_FOR_SMALLBUSINESS_V = 0x00000023
PRODUCT_SERVER_FOUNDATION = 0x00000021
PRODUCT_SMALLBUSINESS_SERVER = 0x00000009
PRODUCT_STANDARD_SERVER = 0x00000007
PRODUCT_STANDARD_SERVER_CORE = 0x0000000D
PRODUCT_STANDARD_SERVER_CORE_V = 0x00000028
PRODUCT_STANDARD_SERVER_V = 0x00000024
PRODUCT_STARTER = 0x0000000B
PRODUCT_STARTER_E = 0x00000042
PRODUCT_STARTER_N = 0x0000002F
PRODUCT_STORAGE_ENTERPRISE_SERVER = 0x00000017
PRODUCT_STORAGE_EXPRESS_SERVER = 0x00000014
PRODUCT_STORAGE_STANDARD_SERVER = 0x00000015
PRODUCT_STORAGE_WORKGROUP_SERVER = 0x00000016
PRODUCT_UNDEFINED = 0x00000000
PRODUCT_UNLICENSED = 0xABCDABCD
PRODUCT_ULTIMATE = 0x00000001
PRODUCT_ULTIMATE_E = 0x00000047
PRODUCT_ULTIMATE_N = 0x0000001C
PRODUCT_WEB_SERVER = 0x00000011
PRODUCT_WEB_SERVER_CORE = 0x0000001D

# DEP policy flags
PROCESS_DEP_ENABLE = 1
PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION = 2

# Error modes
SEM_FAILCRITICALERRORS      = 0x001
SEM_NOGPFAULTERRORBOX       = 0x002
SEM_NOALIGNMENTFAULTEXCEPT  = 0x004
SEM_NOOPENFILEERRORBOX      = 0x800

# GetHandleInformation / SetHandleInformation
HANDLE_FLAG_INHERIT             = 0x00000001
HANDLE_FLAG_PROTECT_FROM_CLOSE  = 0x00000002

#--- Handle wrappers ----------------------------------------------------------

class Handle (object):
    """
    Encapsulates Win32 handles to avoid leaking them.

    @type inherit: bool
    @ivar inherit: C{True} if the handle is to be inherited by child processes,
        C{False} otherwise.

    @type protectFromClose: bool
    @ivar protectFromClose: Set to C{True} to prevent the handle from being
        closed. Must be set to C{False} before you're done using the handle,
        or it will be left open until the debugger exits. Use with care!

    @see:
        L{ProcessHandle}, L{ThreadHandle}, L{FileHandle}, L{SnapshotHandle}
    """

    # XXX DEBUG
    # When this private flag is True each Handle will print a message to
    # standard output when it's created and destroyed. This is useful for
    # detecting handle leaks within WinAppDbg itself.
    __bLeakDetection = False

    def __init__(self, aHandle = None, bOwnership = True):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle value.

        @type  bOwnership: bool
        @param bOwnership:
           C{True} if we own the handle and we need to close it.
           C{False} if someone else will be calling L{CloseHandle}.
        """
        super(Handle, self).__init__()
        self._value     = self._normalize(aHandle)
        self.bOwnership = bOwnership
        if Handle.__bLeakDetection:     # XXX DEBUG
            print "INIT HANDLE (%r) %r" % (self.value, self)

    @property
    def value(self):
        return self._value

    def __del__(self):
        """
        Closes the Win32 handle when the Python object is destroyed.
        """
        try:
            if Handle.__bLeakDetection:     # XXX DEBUG
                print "DEL HANDLE %r" % self
            self.close()
        except Exception:
            pass

    def __enter__(self):
        """
        Compatibility with the "C{with}" Python statement.
        """
        if Handle.__bLeakDetection:     # XXX DEBUG
            print "ENTER HANDLE %r" % self
        return self

    def __exit__(self, type, value, traceback):
        """
        Compatibility with the "C{with}" Python statement.
        """
        if Handle.__bLeakDetection:     # XXX DEBUG
            print "EXIT HANDLE %r" % self
        try:
            self.close()
        except Exception:
            pass

    def __copy__(self):
        """
        Duplicates the Win32 handle when copying the Python object.

        @rtype:  L{Handle}
        @return: A new handle to the same Win32 object.
        """
        return self.dup()

    def __deepcopy__(self):
        """
        Duplicates the Win32 handle when copying the Python object.

        @rtype:  L{Handle}
        @return: A new handle to the same win32 object.
        """
        return self.dup()

    @property
    def _as_parameter_(self):
        """
        Compatibility with ctypes.
        Allows passing transparently a Handle object to an API call.
        """
        return HANDLE(self.value)

    @staticmethod
    def from_param(value):
        """
        Compatibility with ctypes.
        Allows passing transparently a Handle object to an API call.

        @type  value: int
        @param value: Numeric handle value.
        """
        return HANDLE(value)

    def close(self):
        """
        Closes the Win32 handle.
        """
        if self.bOwnership and self.value not in (None, INVALID_HANDLE_VALUE):
            if Handle.__bLeakDetection:     # XXX DEBUG
                print "CLOSE HANDLE (%d) %r" % (self.value, self)
            try:
                self._close()
            finally:
                self._value = None

    def _close(self):
        """
        Low-level close method.
        This is a private method, do not call it.
        """
        CloseHandle(self.value)

    def dup(self):
        """
        @rtype:  L{Handle}
        @return: A new handle to the same Win32 object.
        """
        if self.value is None:
            raise ValueError("Closed handles can't be duplicated!")
        new_handle = DuplicateHandle(self.value)
        if Handle.__bLeakDetection:     # XXX DEBUG
            print "DUP HANDLE (%d -> %d) %r %r" % \
                            (self.value, new_handle.value, self, new_handle)
        return new_handle

    @staticmethod
    def _normalize(value):
        """
        Normalize handle values.
        """
        if hasattr(value, 'value'):
            value = value.value
        if value is not None:
            value = long(value)
        return value

    def wait(self, dwMilliseconds = None):
        """
        Wait for the Win32 object to be signaled.

        @type  dwMilliseconds: int
        @param dwMilliseconds: (Optional) Timeout value in milliseconds.
            Use C{INFINITE} or C{None} for no timeout.
        """
        if self.value is None:
            raise ValueError("Handle is already closed!")
        if dwMilliseconds is None:
            dwMilliseconds = INFINITE
        r = WaitForSingleObject(self.value, dwMilliseconds)
        if r != WAIT_OBJECT_0:
            raise ctypes.WinError(r)

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.value)

    def __get_inherit(self):
        if self.value is None:
            raise ValueError("Handle is already closed!")
        return bool( GetHandleInformation(self.value) & HANDLE_FLAG_INHERIT )

    def __set_inherit(self, value):
        if self.value is None:
            raise ValueError("Handle is already closed!")
        flag = (0, HANDLE_FLAG_INHERIT)[ bool(value) ]
        SetHandleInformation(self.value, flag, flag)

    inherit = property(__get_inherit, __set_inherit)

    def __get_protectFromClose(self):
        if self.value is None:
            raise ValueError("Handle is already closed!")
        return bool( GetHandleInformation(self.value) & HANDLE_FLAG_PROTECT_FROM_CLOSE )

    def __set_protectFromClose(self, value):
        if self.value is None:
            raise ValueError("Handle is already closed!")
        flag = (0, HANDLE_FLAG_PROTECT_FROM_CLOSE)[ bool(value) ]
        SetHandleInformation(self.value, flag, flag)

    protectFromClose = property(__get_protectFromClose, __set_protectFromClose)

class UserModeHandle (Handle):
    """
    Base class for non-kernel handles. Generally this means they are closed
    by special Win32 API functions instead of CloseHandle() and some standard
    operations (synchronizing, duplicating, inheritance) are not supported.

    @type _TYPE: C type
    @cvar _TYPE: C type to translate this handle to.
        Subclasses should override this.
        Defaults to L{HANDLE}.
    """

    # Subclasses should override this.
    _TYPE = HANDLE

    # This method must be implemented by subclasses.
    def _close(self):
        raise NotImplementedError()

    # Translation to C type.
    @property
    def _as_parameter_(self):
        return self._TYPE(self.value)

    # Translation to C type.
    @staticmethod
    def from_param(value):
        return self._TYPE(self.value)

    # Operation not supported.
    @property
    def inherit(self):
        return False

    # Operation not supported.
    @property
    def protectFromClose(self):
        return False

    # Operation not supported.
    def dup(self):
        raise NotImplementedError()

    # Operation not supported.
    def wait(self, dwMilliseconds = None):
        raise NotImplementedError()

class ProcessHandle (Handle):
    """
    Win32 process handle.

    @type dwAccess: int
    @ivar dwAccess: Current access flags to this handle.
            This is the same value passed to L{OpenProcess}.
            Can only be C{None} if C{aHandle} is also C{None}.
            Defaults to L{PROCESS_ALL_ACCESS}.

    @see: L{Handle}
    """

    def __init__(self, aHandle = None, bOwnership = True,
                       dwAccess = PROCESS_ALL_ACCESS):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle value.

        @type  bOwnership: bool
        @param bOwnership:
           C{True} if we own the handle and we need to close it.
           C{False} if someone else will be calling L{CloseHandle}.

        @type  dwAccess: int
        @param dwAccess: Current access flags to this handle.
            This is the same value passed to L{OpenProcess}.
            Can only be C{None} if C{aHandle} is also C{None}.
            Defaults to L{PROCESS_ALL_ACCESS}.
        """
        super(ProcessHandle, self).__init__(aHandle, bOwnership)
        self.dwAccess = dwAccess
        if aHandle is not None and dwAccess is None:
            msg = "Missing access flags for process handle: %x" % aHandle
            raise TypeError(msg)

    def get_pid(self):
        """
        @rtype:  int
        @return: Process global ID.
        """
        return GetProcessId(self.value)

class ThreadHandle (Handle):
    """
    Win32 thread handle.

    @type dwAccess: int
    @ivar dwAccess: Current access flags to this handle.
            This is the same value passed to L{OpenThread}.
            Can only be C{None} if C{aHandle} is also C{None}.
            Defaults to L{THREAD_ALL_ACCESS}.

    @see: L{Handle}
    """

    def __init__(self, aHandle = None, bOwnership = True,
                       dwAccess = THREAD_ALL_ACCESS):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle value.

        @type  bOwnership: bool
        @param bOwnership:
           C{True} if we own the handle and we need to close it.
           C{False} if someone else will be calling L{CloseHandle}.

        @type  dwAccess: int
        @param dwAccess: Current access flags to this handle.
            This is the same value passed to L{OpenThread}.
            Can only be C{None} if C{aHandle} is also C{None}.
            Defaults to L{THREAD_ALL_ACCESS}.
        """
        super(ThreadHandle, self).__init__(aHandle, bOwnership)
        self.dwAccess = dwAccess
        if aHandle is not None and dwAccess is None:
            msg = "Missing access flags for thread handle: %x" % aHandle
            raise TypeError(msg)

    def get_tid(self):
        """
        @rtype:  int
        @return: Thread global ID.
        """
        return GetThreadId(self.value)

class FileHandle (Handle):
    """
    Win32 file handle.

    @see: L{Handle}
    """

    def get_filename(self):
        """
        @rtype:  None or str
        @return: Name of the open file, or C{None} if unavailable.
        """
        #
        # XXX BUG
        #
        # This code truncates the first two bytes of the path.
        # It seems to be the expected behavior of NtQueryInformationFile.
        #
        # My guess is it only returns the NT pathname, without the device name.
        # It's like dropping the drive letter in a Win32 pathname.
        #
        # Note that using the "official" GetFileInformationByHandleEx
        # API introduced in Vista doesn't change the results!
        #
        dwBufferSize      = 0x1004
        lpFileInformation = ctypes.create_string_buffer(dwBufferSize)
        try:
            GetFileInformationByHandleEx(self.value,
                                        FILE_INFO_BY_HANDLE_CLASS.FileNameInfo,
                                        lpFileInformation, dwBufferSize)
        except AttributeError:
            from ntdll import NtQueryInformationFile, \
                              FileNameInformation, \
                              FILE_NAME_INFORMATION
            NtQueryInformationFile(self.value,
                                   FileNameInformation,
                                   lpFileInformation,
                                   dwBufferSize)
        FileName = unicode(lpFileInformation.raw[sizeof(DWORD):], 'U16')
        FileName = ctypes.create_unicode_buffer(FileName).value
        if not FileName:
            FileName = None
        elif FileName[1:2] != ':':
            # When the drive letter is missing, we'll assume SYSTEMROOT.
            # Not a good solution but it could be worse.
            import os
            FileName = os.environ['SYSTEMROOT'][:2] + FileName
        return FileName

class FileMappingHandle (Handle):
    """
    File mapping handle.

    @see: L{Handle}
    """
    pass

# XXX maybe add functions related to the toolhelp snapshots here?
class SnapshotHandle (Handle):
    """
    Toolhelp32 snapshot handle.

    @see: L{Handle}
    """
    pass

#--- Structure wrappers -------------------------------------------------------

class ProcessInformation (object):
    """
    Process information object returned by L{CreateProcess}.
    """

    def __init__(self, pi):
        self.hProcess    = ProcessHandle(pi.hProcess)
        self.hThread     = ThreadHandle(pi.hThread)
        self.dwProcessId = pi.dwProcessId
        self.dwThreadId  = pi.dwThreadId

# Don't psyco-optimize this class because it needs to be serialized.
class MemoryBasicInformation (object):
    """
    Memory information object returned by L{VirtualQueryEx}.
    """

    READABLE = (
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READONLY           |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
    )

    WRITEABLE = (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_READWRITE          |
                PAGE_WRITECOPY
    )

    COPY_ON_WRITE = (
                PAGE_EXECUTE_WRITECOPY  |
                PAGE_WRITECOPY
    )

    EXECUTABLE = (
                PAGE_EXECUTE            |
                PAGE_EXECUTE_READ       |
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
    )

    EXECUTABLE_AND_WRITEABLE = (
                PAGE_EXECUTE_READWRITE  |
                PAGE_EXECUTE_WRITECOPY
    )

    def __init__(self, mbi=None):
        """
        @type  mbi: L{MEMORY_BASIC_INFORMATION} or L{MemoryBasicInformation}
        @param mbi: Either a L{MEMORY_BASIC_INFORMATION} structure or another
            L{MemoryBasicInformation} instance.
        """
        if mbi is None:
            self.BaseAddress        = None
            self.AllocationBase     = None
            self.AllocationProtect  = None
            self.RegionSize         = None
            self.State              = None
            self.Protect            = None
            self.Type               = None
        else:
            self.BaseAddress        = mbi.BaseAddress
            self.AllocationBase     = mbi.AllocationBase
            self.AllocationProtect  = mbi.AllocationProtect
            self.RegionSize         = mbi.RegionSize
            self.State              = mbi.State
            self.Protect            = mbi.Protect
            self.Type               = mbi.Type

            # Only used when copying MemoryBasicInformation objects, instead of
            # instancing them from a MEMORY_BASIC_INFORMATION structure.
            if hasattr(mbi, 'content'):
                self.content = mbi.content
            if hasattr(mbi, 'filename'):
                self.content = mbi.filename

    def __contains__(self, address):
        """
        Test if the given memory address falls within this memory region.

        @type  address: int
        @param address: Memory address to test.

        @rtype:  bool
        @return: C{True} if the given memory address falls within this memory
            region, C{False} otherwise.
        """
        return self.BaseAddress <= address < (self.BaseAddress + self.RegionSize)

    def is_free(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is free.
        """
        return self.State == MEM_FREE

    def is_reserved(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is reserved.
        """
        return self.State == MEM_RESERVE

    def is_commited(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is commited.
        """
        return self.State == MEM_COMMIT

    def is_image(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region belongs to an executable
            image.
        """
        return self.Type == MEM_IMAGE

    def is_mapped(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region belongs to a mapped file.
        """
        return self.Type == MEM_MAPPED

    def is_private(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region is private.
        """
        return self.Type == MEM_PRIVATE

    def is_guard(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are guard pages.
        """
        return self.is_commited() and bool(self.Protect & PAGE_GUARD)

    def has_content(self):
        """
        @rtype:  bool
        @return: C{True} if the memory in this region has any data in it.
        """
        return self.is_commited() and not bool(self.Protect & (PAGE_GUARD | PAGE_NOACCESS))

    def is_readable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are readable.
        """
        return self.has_content() and bool(self.Protect & self.READABLE)

    def is_writeable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are writeable.
        """
        return self.has_content() and bool(self.Protect & self.WRITEABLE)

    def is_copy_on_write(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are marked as
            copy-on-write. This means the pages are writeable, but changes
            are not propagated to disk.
        @note:
            Tipically data sections in executable images are marked like this.
        """
        return self.has_content() and bool(self.Protect & self.COPY_ON_WRITE)

    def is_executable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are executable.
        @note: Executable pages are always readable.
        """
        return self.has_content() and bool(self.Protect & self.EXECUTABLE)

    def is_executable_and_writeable(self):
        """
        @rtype:  bool
        @return: C{True} if all pages in this region are executable and
            writeable.
        @note: The presence of such pages make memory corruption
            vulnerabilities much easier to exploit.
        """
        return self.has_content() and bool(self.Protect & self.EXECUTABLE_AND_WRITEABLE)

class ProcThreadAttributeList (object):
    """
    Extended process and thread attribute support.

    To be used with L{STARTUPINFOEX}.
    Only available for Windows Vista and above.

    @type AttributeList: list of tuple( int, ctypes-compatible object )
    @ivar AttributeList: List of (Attribute, Value) pairs.

    @type AttributeListBuffer: L{LPPROC_THREAD_ATTRIBUTE_LIST}
    @ivar AttributeListBuffer: Memory buffer used to store the attribute list.
        L{InitializeProcThreadAttributeList},
        L{UpdateProcThreadAttribute},
        L{DeleteProcThreadAttributeList} and
        L{STARTUPINFOEX}.
    """

    def __init__(self, AttributeList):
        """
        @type  AttributeList: list of tuple( int, ctypes-compatible object )
        @param AttributeList: List of (Attribute, Value) pairs.
        """
        self.AttributeList = AttributeList
        self.AttributeListBuffer = InitializeProcThreadAttributeList(
                                                            len(AttributeList))
        try:
            for Attribute, Value in AttributeList:
                UpdateProcThreadAttribute(self.AttributeListBuffer,
                                          Attribute, Value)
        except:
            ProcThreadAttributeList.__del__(self)
            raise

    def __del__(self):
        try:
            DeleteProcThreadAttributeList(self.AttributeListBuffer)
            del self.AttributeListBuffer
        except Exception:
            pass

    def __copy__(self):
        return self.__deepcopy__()

    def __deepcopy__(self):
        return self.__class__(self.AttributeList)

    @property
    def value(self):
        return ctypes.cast(ctypes.pointer(self.AttributeListBuffer), LPVOID)

    @property
    def _as_parameter_(self):
        return self.value

    # XXX TODO
    @staticmethod
    def from_param(value):
        raise NotImplementedError()

#--- OVERLAPPED structure -----------------------------------------------------

# typedef struct _OVERLAPPED {
#   ULONG_PTR Internal;
#   ULONG_PTR InternalHigh;
#   union {
#     struct {
#       DWORD Offset;
#       DWORD OffsetHigh;
#     } ;
#     PVOID Pointer;
#   } ;
#   HANDLE    hEvent;
# }OVERLAPPED, *LPOVERLAPPED;
class _OVERLAPPED_STRUCT(Structure):
    _fields_ = [
        ('Offset',          DWORD),
        ('OffsetHigh',      DWORD),
    ]
class _OVERLAPPED_UNION(Union):
    _fields_ = [
        ('s',               _OVERLAPPED_STRUCT),
        ('Pointer',         PVOID),
    ]
class OVERLAPPED(Structure):
    _fields_ = [
        ('Internal',        ULONG_PTR),
        ('InternalHigh',    ULONG_PTR),
        ('u',               _OVERLAPPED_UNION),
        ('hEvent',          HANDLE),
    ]
LPOVERLAPPED = POINTER(OVERLAPPED)

#--- SECURITY_ATTRIBUTES structure --------------------------------------------

# typedef struct _SECURITY_ATTRIBUTES {
#     DWORD nLength;
#     LPVOID lpSecurityDescriptor;
#     BOOL bInheritHandle;
# } SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [
        ('nLength',                 DWORD),
        ('lpSecurityDescriptor',    LPVOID),
        ('bInheritHandle',          BOOL),
    ]
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

# --- Extended process and thread attribute support ---------------------------

PPROC_THREAD_ATTRIBUTE_LIST  = LPVOID
LPPROC_THREAD_ATTRIBUTE_LIST = PPROC_THREAD_ATTRIBUTE_LIST

PROC_THREAD_ATTRIBUTE_NUMBER   = 0x0000FFFF
PROC_THREAD_ATTRIBUTE_THREAD   = 0x00010000  # Attribute may be used with thread creation
PROC_THREAD_ATTRIBUTE_INPUT    = 0x00020000  # Attribute is input only
PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000  # Attribute may be "accumulated," e.g. bitmasks, counters, etc.

# PROC_THREAD_ATTRIBUTE_NUM
ProcThreadAttributeParentProcess    = 0
ProcThreadAttributeExtendedFlags    = 1
ProcThreadAttributeHandleList       = 2
ProcThreadAttributeGroupAffinity    = 3
ProcThreadAttributePreferredNode    = 4
ProcThreadAttributeIdealProcessor   = 5
ProcThreadAttributeUmsThread        = 6
ProcThreadAttributeMitigationPolicy = 7
ProcThreadAttributeMax              = 8

PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    = ProcThreadAttributeParentProcess      |                                PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_EXTENDED_FLAGS    = ProcThreadAttributeExtendedFlags      |                                PROC_THREAD_ATTRIBUTE_INPUT | PROC_THREAD_ATTRIBUTE_ADDITIVE
PROC_THREAD_ATTRIBUTE_HANDLE_LIST       = ProcThreadAttributeHandleList         |                                PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY    = ProcThreadAttributeGroupAffinity      | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_PREFERRED_NODE    = ProcThreadAttributePreferredNode      |                                PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR   = ProcThreadAttributeIdealProcessor     | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_UMS_THREAD        = ProcThreadAttributeUmsThread          | PROC_THREAD_ATTRIBUTE_THREAD | PROC_THREAD_ATTRIBUTE_INPUT
PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = ProcThreadAttributeMitigationPolicy   |                                PROC_THREAD_ATTRIBUTE_INPUT

PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE           = 0x01
PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE = 0x02
PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE         = 0x04

#--- VS_FIXEDFILEINFO structure -----------------------------------------------

# struct VS_FIXEDFILEINFO {
#   DWORD dwSignature;
#   DWORD dwStrucVersion;
#   DWORD dwFileVersionMS;
#   DWORD dwFileVersionLS;
#   DWORD dwProductVersionMS;
#   DWORD dwProductVersionLS;
#   DWORD dwFileFlagsMask;
#   DWORD dwFileFlags;
#   DWORD dwFileOS;
#   DWORD dwFileType;
#   DWORD dwFileSubtype;
#   DWORD dwFileDateMS;
#   DWORD dwFileDateLS;
# };
class VS_FIXEDFILEINFO (Structure):
    _fields_ = [
        ("dwSignature",             DWORD),     # 0xFEEF04BD
        ("dwStrucVersion",          DWORD),
        ("dwFileVersionMS",         DWORD),
        ("dwFileVersionLS",         DWORD),
        ("dwProductVersionMS",      DWORD),
        ("dwProductVersionLS",      DWORD),
        ("dwFileFlagsMask",         DWORD),
        ("dwFileFlags",             DWORD),
        ("dwFileOS",                DWORD),
        ("dwFileType",              DWORD),
        ("dwFileSubtype",           DWORD),
        ("dwFileDateMS",            DWORD),
        ("dwFileDateLS",            DWORD),
    ]

#--- THREADNAME_INFO structure ------------------------------------------------

# typedef struct tagTHREADNAME_INFO
# {
#    DWORD dwType; // Must be 0x1000.
#    LPCSTR szName; // Pointer to name (in user addr space).
#    DWORD dwThreadID; // Thread ID (-1=caller thread).
#    DWORD dwFlags; // Reserved for future use, must be zero.
# } THREADNAME_INFO;
class THREADNAME_INFO(Structure):
    _fields_ = [
        ("dwType",      DWORD),     # 0x1000
        ("szName",      LPVOID),    # remote pointer
        ("dwThreadID",  DWORD),     # -1 usually
        ("dwFlags",     DWORD),     # 0
    ]

#--- MEMORY_BASIC_INFORMATION structure ---------------------------------------

# typedef struct _MEMORY_BASIC_INFORMATION32 {
#     DWORD BaseAddress;
#     DWORD AllocationBase;
#     DWORD AllocationProtect;
#     DWORD RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION32, *PMEMORY_BASIC_INFORMATION32;
class MEMORY_BASIC_INFORMATION32(Structure):
    _fields_ = [
        ('BaseAddress',         DWORD),         # remote pointer
        ('AllocationBase',      DWORD),         # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          DWORD),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]

# typedef struct DECLSPEC_ALIGN(16) _MEMORY_BASIC_INFORMATION64 {
#     ULONGLONG BaseAddress;
#     ULONGLONG AllocationBase;
#     DWORD     AllocationProtect;
#     DWORD     __alignment1;
#     ULONGLONG RegionSize;
#     DWORD     State;
#     DWORD     Protect;
#     DWORD     Type;
#     DWORD     __alignment2;
# } MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;
class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [
        ('BaseAddress',         ULONGLONG),     # remote pointer
        ('AllocationBase',      ULONGLONG),     # remote pointer
        ('AllocationProtect',   DWORD),
        ('__alignment1',        DWORD),
        ('RegionSize',          ULONGLONG),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
        ('__alignment2',        DWORD),
    ]

# typedef struct _MEMORY_BASIC_INFORMATION {
#     PVOID BaseAddress;
#     PVOID AllocationBase;
#     DWORD AllocationProtect;
#     SIZE_T RegionSize;
#     DWORD State;
#     DWORD Protect;
#     DWORD Type;
# } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('BaseAddress',         SIZE_T),    # remote pointer
        ('AllocationBase',      SIZE_T),    # remote pointer
        ('AllocationProtect',   DWORD),
        ('RegionSize',          SIZE_T),
        ('State',               DWORD),
        ('Protect',             DWORD),
        ('Type',                DWORD),
    ]
PMEMORY_BASIC_INFORMATION = POINTER(MEMORY_BASIC_INFORMATION)

#--- BY_HANDLE_FILE_INFORMATION structure -------------------------------------

# typedef struct _FILETIME {
#    DWORD dwLowDateTime;
#    DWORD dwHighDateTime;
# } FILETIME, *PFILETIME;
class FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime',       DWORD),
        ('dwHighDateTime',      DWORD),
    ]
LPFILETIME = POINTER(FILETIME)

# typedef struct _SYSTEMTIME {
#   WORD wYear;
#   WORD wMonth;
#   WORD wDayOfWeek;
#   WORD wDay;
#   WORD wHour;
#   WORD wMinute;
#   WORD wSecond;
#   WORD wMilliseconds;
# }SYSTEMTIME, *PSYSTEMTIME;
class SYSTEMTIME(Structure):
    _fields_ = [
        ('wYear',           WORD),
        ('wMonth',          WORD),
        ('wDayOfWeek',      WORD),
        ('wDay',            WORD),
        ('wHour',           WORD),
        ('wMinute',         WORD),
        ('wSecond',         WORD),
        ('wMilliseconds',   WORD),
    ]
LPSYSTEMTIME = POINTER(SYSTEMTIME)

# typedef struct _BY_HANDLE_FILE_INFORMATION {
#   DWORD dwFileAttributes;
#   FILETIME ftCreationTime;
#   FILETIME ftLastAccessTime;
#   FILETIME ftLastWriteTime;
#   DWORD dwVolumeSerialNumber;
#   DWORD nFileSizeHigh;
#   DWORD nFileSizeLow;
#   DWORD nNumberOfLinks;
#   DWORD nFileIndexHigh;
#   DWORD nFileIndexLow;
# } BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION;
class BY_HANDLE_FILE_INFORMATION(Structure):
    _fields_ = [
        ('dwFileAttributes',        DWORD),
        ('ftCreationTime',          FILETIME),
        ('ftLastAccessTime',        FILETIME),
        ('ftLastWriteTime',         FILETIME),
        ('dwVolumeSerialNumber',    DWORD),
        ('nFileSizeHigh',           DWORD),
        ('nFileSizeLow',            DWORD),
        ('nNumberOfLinks',          DWORD),
        ('nFileIndexHigh',          DWORD),
        ('nFileIndexLow',           DWORD),
    ]
LPBY_HANDLE_FILE_INFORMATION = POINTER(BY_HANDLE_FILE_INFORMATION)

# typedef enum _FILE_INFO_BY_HANDLE_CLASS {
#   FileBasicInfo = 0,
#   FileStandardInfo = 1,
#   FileNameInfo = 2,
#   FileRenameInfo = 3,
#   FileDispositionInfo = 4,
#   FileAllocationInfo = 5,
#   FileEndOfFileInfo = 6,
#   FileStreamInfo = 7,
#   FileCompressionInfo = 8,
#   FileAttributeTagInfo = 9,
#   FileIdBothDirectoryInfo = 10,
#   FileIdBothDirectoryRestartInfo = 11,
#   FileIoPriorityHintInfo = 12,
#   MaximumFileInfoByHandlesClass = 13
# } FILE_INFO_BY_HANDLE_CLASS, *PFILE_INFO_BY_HANDLE_CLASS;
class FILE_INFO_BY_HANDLE_CLASS(object):
    FileBasicInfo                   = 0
    FileStandardInfo                = 1
    FileNameInfo                    = 2
    FileRenameInfo                  = 3
    FileDispositionInfo             = 4
    FileAllocationInfo              = 5
    FileEndOfFileInfo               = 6
    FileStreamInfo                  = 7
    FileCompressionInfo             = 8
    FileAttributeTagInfo            = 9
    FileIdBothDirectoryInfo         = 10
    FileIdBothDirectoryRestartInfo  = 11
    FileIoPriorityHintInfo          = 12
    MaximumFileInfoByHandlesClass   = 13

# typedef struct _FILE_NAME_INFO {
#   DWORD  FileNameLength;
#   WCHAR FileName[1];
# } FILE_NAME_INFO, *PFILE_NAME_INFO;
##class FILE_NAME_INFO(Structure):
##    _fields_ = [
##        ('FileNameLength',  DWORD),
##        ('FileName',        WCHAR * 1),
##    ]

# TO DO: add more structures used by GetFileInformationByHandleEx()

#--- PROCESS_INFORMATION structure --------------------------------------------

# typedef struct _PROCESS_INFORMATION {
#     HANDLE hProcess;
#     HANDLE hThread;
#     DWORD dwProcessId;
#     DWORD dwThreadId;
# } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)

#--- STARTUPINFO and STARTUPINFOEX structures ---------------------------------

# typedef struct _STARTUPINFO {
#   DWORD  cb;
#   LPTSTR lpReserved;
#   LPTSTR lpDesktop;
#   LPTSTR lpTitle;
#   DWORD  dwX;
#   DWORD  dwY;
#   DWORD  dwXSize;
#   DWORD  dwYSize;
#   DWORD  dwXCountChars;
#   DWORD  dwYCountChars;
#   DWORD  dwFillAttribute;
#   DWORD  dwFlags;
#   WORD   wShowWindow;
#   WORD   cbReserved2;
#   LPBYTE lpReserved2;
#   HANDLE hStdInput;
#   HANDLE hStdOutput;
#   HANDLE hStdError;
# }STARTUPINFO, *LPSTARTUPINFO;
class STARTUPINFO(Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPSTR),
        ('lpDesktop',       LPSTR),
        ('lpTitle',         LPSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),    # LPBYTE
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE),
    ]
LPSTARTUPINFO = POINTER(STARTUPINFO)

# typedef struct _STARTUPINFOEX {
#   STARTUPINFO StartupInfo;
#   PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
# } STARTUPINFOEX,  *LPSTARTUPINFOEX;
class STARTUPINFOEX(Structure):
    _fields_ = [
        ('StartupInfo',     STARTUPINFO),
        ('lpAttributeList', PPROC_THREAD_ATTRIBUTE_LIST),
    ]
LPSTARTUPINFOEX = POINTER(STARTUPINFOEX)

class STARTUPINFOW(Structure):
    _fields_ = [
        ('cb',              DWORD),
        ('lpReserved',      LPWSTR),
        ('lpDesktop',       LPWSTR),
        ('lpTitle',         LPWSTR),
        ('dwX',             DWORD),
        ('dwY',             DWORD),
        ('dwXSize',         DWORD),
        ('dwYSize',         DWORD),
        ('dwXCountChars',   DWORD),
        ('dwYCountChars',   DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',         DWORD),
        ('wShowWindow',     WORD),
        ('cbReserved2',     WORD),
        ('lpReserved2',     LPVOID),    # LPBYTE
        ('hStdInput',       HANDLE),
        ('hStdOutput',      HANDLE),
        ('hStdError',       HANDLE),
    ]
LPSTARTUPINFOW = POINTER(STARTUPINFOW)

class STARTUPINFOEXW(Structure):
    _fields_ = [
        ('StartupInfo',     STARTUPINFOW),
        ('lpAttributeList', PPROC_THREAD_ATTRIBUTE_LIST),
    ]
LPSTARTUPINFOEXW = POINTER(STARTUPINFOEXW)

#--- JIT_DEBUG_INFO structure -------------------------------------------------

# typedef struct _JIT_DEBUG_INFO {
#     DWORD dwSize;
#     DWORD dwProcessorArchitecture;
#     DWORD dwThreadID;
#     DWORD dwReserved0;
#     ULONG64 lpExceptionAddress;
#     ULONG64 lpExceptionRecord;
#     ULONG64 lpContextRecord;
# } JIT_DEBUG_INFO, *LPJIT_DEBUG_INFO;
class JIT_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwSize',                  DWORD),
        ('dwProcessorArchitecture', DWORD),
        ('dwThreadID',              DWORD),
        ('dwReserved0',             DWORD),
        ('lpExceptionAddress',      ULONG64),
        ('lpExceptionRecord',       ULONG64),
        ('lpContextRecord',         ULONG64),
    ]
JIT_DEBUG_INFO32 = JIT_DEBUG_INFO
JIT_DEBUG_INFO64 = JIT_DEBUG_INFO

LPJIT_DEBUG_INFO   = POINTER(JIT_DEBUG_INFO)
LPJIT_DEBUG_INFO32 = POINTER(JIT_DEBUG_INFO32)
LPJIT_DEBUG_INFO64 = POINTER(JIT_DEBUG_INFO64)

#--- DEBUG_EVENT structure ----------------------------------------------------

# typedef struct _EXCEPTION_RECORD32 {
#     DWORD ExceptionCode;
#     DWORD ExceptionFlags;
#     DWORD ExceptionRecord;
#     DWORD ExceptionAddress;
#     DWORD NumberParameters;
#     DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;
class EXCEPTION_RECORD32(Structure):
    _fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         DWORD),
        ('ExceptionAddress',        DWORD),
        ('NumberParameters',        DWORD),
        ('ExceptionInformation',    DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

PEXCEPTION_RECORD32 = POINTER(EXCEPTION_RECORD32)

# typedef struct _EXCEPTION_RECORD64 {
#     DWORD    ExceptionCode;
#     DWORD ExceptionFlags;
#     DWORD64 ExceptionRecord;
#     DWORD64 ExceptionAddress;
#     DWORD NumberParameters;
#     DWORD __unusedAlignment;
#     DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;
class EXCEPTION_RECORD64(Structure):
    _fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         DWORD64),
        ('ExceptionAddress',        DWORD64),
        ('NumberParameters',        DWORD),
        ('__unusedAlignment',       DWORD),
        ('ExceptionInformation',    DWORD64 * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

PEXCEPTION_RECORD64 = POINTER(EXCEPTION_RECORD64)

# typedef struct _EXCEPTION_RECORD {
#     DWORD ExceptionCode;
#     DWORD ExceptionFlags;
#     LPVOID ExceptionRecord;
#     LPVOID ExceptionAddress;
#     DWORD NumberParameters;
#     LPVOID ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD, *PEXCEPTION_RECORD;
class EXCEPTION_RECORD(Structure):
    pass
PEXCEPTION_RECORD = POINTER(EXCEPTION_RECORD)
EXCEPTION_RECORD._fields_ = [
        ('ExceptionCode',           DWORD),
        ('ExceptionFlags',          DWORD),
        ('ExceptionRecord',         PEXCEPTION_RECORD),
        ('ExceptionAddress',        LPVOID),
        ('NumberParameters',        DWORD),
        ('ExceptionInformation',    LPVOID * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

# typedef struct _EXCEPTION_DEBUG_INFO {
#   EXCEPTION_RECORD ExceptionRecord;
#   DWORD dwFirstChance;
# } EXCEPTION_DEBUG_INFO;
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ('ExceptionRecord',     EXCEPTION_RECORD),
        ('dwFirstChance',       DWORD),
    ]

# typedef struct _CREATE_THREAD_DEBUG_INFO {
#   HANDLE hThread;
#   LPVOID lpThreadLocalBase;
#   LPTHREAD_START_ROUTINE lpStartAddress;
# } CREATE_THREAD_DEBUG_INFO;
class CREATE_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('hThread',             HANDLE),
        ('lpThreadLocalBase',   LPVOID),
        ('lpStartAddress',      LPVOID),
    ]

# typedef struct _CREATE_PROCESS_DEBUG_INFO {
#   HANDLE hFile;
#   HANDLE hProcess;
#   HANDLE hThread;
#   LPVOID lpBaseOfImage;
#   DWORD dwDebugInfoFileOffset;
#   DWORD nDebugInfoSize;
#   LPVOID lpThreadLocalBase;
#   LPTHREAD_START_ROUTINE lpStartAddress;
#   LPVOID lpImageName;
#   WORD fUnicode;
# } CREATE_PROCESS_DEBUG_INFO;
class CREATE_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('hProcess',                HANDLE),
        ('hThread',                 HANDLE),
        ('lpBaseOfImage',           LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpThreadLocalBase',       LPVOID),
        ('lpStartAddress',          LPVOID),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]

# typedef struct _EXIT_THREAD_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_THREAD_DEBUG_INFO;
class EXIT_THREAD_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _EXIT_PROCESS_DEBUG_INFO {
#   DWORD dwExitCode;
# } EXIT_PROCESS_DEBUG_INFO;
class EXIT_PROCESS_DEBUG_INFO(Structure):
    _fields_ = [
        ('dwExitCode',          DWORD),
    ]

# typedef struct _LOAD_DLL_DEBUG_INFO {
#   HANDLE hFile;
#   LPVOID lpBaseOfDll;
#   DWORD dwDebugInfoFileOffset;
#   DWORD nDebugInfoSize;
#   LPVOID lpImageName;
#   WORD fUnicode;
# } LOAD_DLL_DEBUG_INFO;
class LOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('hFile',                   HANDLE),
        ('lpBaseOfDll',             LPVOID),
        ('dwDebugInfoFileOffset',   DWORD),
        ('nDebugInfoSize',          DWORD),
        ('lpImageName',             LPVOID),
        ('fUnicode',                WORD),
    ]

# typedef struct _UNLOAD_DLL_DEBUG_INFO {
#   LPVOID lpBaseOfDll;
# } UNLOAD_DLL_DEBUG_INFO;
class UNLOAD_DLL_DEBUG_INFO(Structure):
    _fields_ = [
        ('lpBaseOfDll',         LPVOID),
    ]

# typedef struct _OUTPUT_DEBUG_STRING_INFO {
#   LPSTR lpDebugStringData;
#   WORD fUnicode;
#   WORD nDebugStringLength;
# } OUTPUT_DEBUG_STRING_INFO;
class OUTPUT_DEBUG_STRING_INFO(Structure):
    _fields_ = [
        ('lpDebugStringData',   LPVOID),    # don't use LPSTR
        ('fUnicode',            WORD),
        ('nDebugStringLength',  WORD),
    ]

# typedef struct _RIP_INFO {
#     DWORD dwError;
#     DWORD dwType;
# } RIP_INFO, *LPRIP_INFO;
class RIP_INFO(Structure):
    _fields_ = [
        ('dwError',             DWORD),
        ('dwType',              DWORD),
    ]

# typedef struct _DEBUG_EVENT {
#   DWORD dwDebugEventCode;
#   DWORD dwProcessId;
#   DWORD dwThreadId;
#   union {
#     EXCEPTION_DEBUG_INFO Exception;
#     CREATE_THREAD_DEBUG_INFO CreateThread;
#     CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
#     EXIT_THREAD_DEBUG_INFO ExitThread;
#     EXIT_PROCESS_DEBUG_INFO ExitProcess;
#     LOAD_DLL_DEBUG_INFO LoadDll;
#     UNLOAD_DLL_DEBUG_INFO UnloadDll;
#     OUTPUT_DEBUG_STRING_INFO DebugString;
#     RIP_INFO RipInfo;
#   } u;
# } DEBUG_EVENT;.
class _DEBUG_EVENT_UNION_(Union):
    _fields_ = [
        ('Exception',           EXCEPTION_DEBUG_INFO),
        ('CreateThread',        CREATE_THREAD_DEBUG_INFO),
        ('CreateProcessInfo',   CREATE_PROCESS_DEBUG_INFO),
        ('ExitThread',          EXIT_THREAD_DEBUG_INFO),
        ('ExitProcess',         EXIT_PROCESS_DEBUG_INFO),
        ('LoadDll',             LOAD_DLL_DEBUG_INFO),
        ('UnloadDll',           UNLOAD_DLL_DEBUG_INFO),
        ('DebugString',         OUTPUT_DEBUG_STRING_INFO),
        ('RipInfo',             RIP_INFO),
    ]
class DEBUG_EVENT(Structure):
    _fields_ = [
        ('dwDebugEventCode',    DWORD),
        ('dwProcessId',         DWORD),
        ('dwThreadId',          DWORD),
        ('u',                   _DEBUG_EVENT_UNION_),
    ]
LPDEBUG_EVENT = POINTER(DEBUG_EVENT)

#--- Console API defines and structures ---------------------------------------

FOREGROUND_MASK = 0x000F
BACKGROUND_MASK = 0x00F0
COMMON_LVB_MASK = 0xFF00

FOREGROUND_BLACK     = 0x0000
FOREGROUND_BLUE      = 0x0001
FOREGROUND_GREEN     = 0x0002
FOREGROUND_CYAN      = 0x0003
FOREGROUND_RED       = 0x0004
FOREGROUND_MAGENTA   = 0x0005
FOREGROUND_YELLOW    = 0x0006
FOREGROUND_GREY      = 0x0007
FOREGROUND_INTENSITY = 0x0008

BACKGROUND_BLACK     = 0x0000
BACKGROUND_BLUE      = 0x0010
BACKGROUND_GREEN     = 0x0020
BACKGROUND_CYAN      = 0x0030
BACKGROUND_RED       = 0x0040
BACKGROUND_MAGENTA   = 0x0050
BACKGROUND_YELLOW    = 0x0060
BACKGROUND_GREY      = 0x0070
BACKGROUND_INTENSITY = 0x0080

COMMON_LVB_LEADING_BYTE    = 0x0100
COMMON_LVB_TRAILING_BYTE   = 0x0200
COMMON_LVB_GRID_HORIZONTAL = 0x0400
COMMON_LVB_GRID_LVERTICAL  = 0x0800
COMMON_LVB_GRID_RVERTICAL  = 0x1000
COMMON_LVB_REVERSE_VIDEO   = 0x4000
COMMON_LVB_UNDERSCORE      = 0x8000

# typedef struct _CHAR_INFO {
#   union {
#     WCHAR UnicodeChar;
#     CHAR  AsciiChar;
#   } Char;
#   WORD  Attributes;
# } CHAR_INFO, *PCHAR_INFO;
class _CHAR_INFO_CHAR(Union):
    _fields_ = [
        ('UnicodeChar', WCHAR),
        ('AsciiChar',   CHAR),
    ]
class CHAR_INFO(Structure):
    _fields_ = [
        ('Char',       _CHAR_INFO_CHAR),
        ('Attributes', WORD),
   ]
PCHAR_INFO = POINTER(CHAR_INFO)

# typedef struct _COORD {
#   SHORT X;
#   SHORT Y;
# } COORD, *PCOORD;
class COORD(Structure):
    _fields_ = [
        ('X', SHORT),
        ('Y', SHORT),
    ]
PCOORD = POINTER(COORD)

# typedef struct _SMALL_RECT {
#   SHORT Left;
#   SHORT Top;
#   SHORT Right;
#   SHORT Bottom;
# } SMALL_RECT;
class SMALL_RECT(Structure):
    _fields_ = [
        ('Left',   SHORT),
        ('Top',    SHORT),
        ('Right',  SHORT),
        ('Bottom', SHORT),
    ]
PSMALL_RECT = POINTER(SMALL_RECT)

# typedef struct _CONSOLE_SCREEN_BUFFER_INFO {
#   COORD      dwSize;
#   COORD      dwCursorPosition;
#   WORD       wAttributes;
#   SMALL_RECT srWindow;
#   COORD      dwMaximumWindowSize;
# } CONSOLE_SCREEN_BUFFER_INFO;
class CONSOLE_SCREEN_BUFFER_INFO(Structure):
    _fields_ = [
        ('dwSize',              COORD),
        ('dwCursorPosition',    COORD),
        ('wAttributes',         WORD),
        ('srWindow',            SMALL_RECT),
        ('dwMaximumWindowSize', COORD),
    ]
PCONSOLE_SCREEN_BUFFER_INFO = POINTER(CONSOLE_SCREEN_BUFFER_INFO)

#--- Toolhelp library defines and structures ----------------------------------

TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

# typedef struct tagTHREADENTRY32 {
#   DWORD dwSize;
#   DWORD cntUsage;
#   DWORD th32ThreadID;
#   DWORD th32OwnerProcessID;
#   LONG tpBasePri;
#   LONG tpDeltaPri;
#   DWORD dwFlags;
# } THREADENTRY32,  *PTHREADENTRY32;
class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          LONG),
        ('tpDeltaPri',         LONG),
        ('dwFlags',            DWORD),
    ]
LPTHREADENTRY32 = POINTER(THREADENTRY32)

# typedef struct tagPROCESSENTRY32 {
#    DWORD dwSize;
#    DWORD cntUsage;
#    DWORD th32ProcessID;
#    ULONG_PTR th32DefaultHeapID;
#    DWORD th32ModuleID;
#    DWORD cntThreads;
#    DWORD th32ParentProcessID;
#    LONG pcPriClassBase;
#    DWORD dwFlags;
#    TCHAR szExeFile[MAX_PATH];
# } PROCESSENTRY32,  *PPROCESSENTRY32;
class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   ULONG_PTR),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           TCHAR * 260),
    ]
LPPROCESSENTRY32 = POINTER(PROCESSENTRY32)

# typedef struct tagMODULEENTRY32 {
#   DWORD dwSize;
#   DWORD th32ModuleID;
#   DWORD th32ProcessID;
#   DWORD GlblcntUsage;
#   DWORD ProccntUsage;
#   BYTE* modBaseAddr;
#   DWORD modBaseSize;
#   HMODULE hModule;
#   TCHAR szModule[MAX_MODULE_NAME32 + 1];
#   TCHAR szExePath[MAX_PATH];
# } MODULEENTRY32,  *PMODULEENTRY32;
class MODULEENTRY32(Structure):
    _fields_ = [
        ("dwSize",        DWORD),
        ("th32ModuleID",  DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage",  DWORD),
        ("ProccntUsage",  DWORD),
        ("modBaseAddr",   LPVOID),  # BYTE*
        ("modBaseSize",   DWORD),
        ("hModule",       HMODULE),
        ("szModule",      TCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath",     TCHAR * MAX_PATH),
    ]
LPMODULEENTRY32 = POINTER(MODULEENTRY32)

# typedef struct tagHEAPENTRY32 {
#   SIZE_T    dwSize;
#   HANDLE    hHandle;
#   ULONG_PTR dwAddress;
#   SIZE_T    dwBlockSize;
#   DWORD     dwFlags;
#   DWORD     dwLockCount;
#   DWORD     dwResvd;
#   DWORD     th32ProcessID;
#   ULONG_PTR th32HeapID;
# } HEAPENTRY32,
# *PHEAPENTRY32;
class HEAPENTRY32(Structure):
    _fields_ = [
        ("dwSize",          SIZE_T),
        ("hHandle",         HANDLE),
        ("dwAddress",       ULONG_PTR),
        ("dwBlockSize",     SIZE_T),
        ("dwFlags",         DWORD),
        ("dwLockCount",     DWORD),
        ("dwResvd",         DWORD),
        ("th32ProcessID",   DWORD),
        ("th32HeapID",      ULONG_PTR),
]
LPHEAPENTRY32 = POINTER(HEAPENTRY32)

# typedef struct tagHEAPLIST32 {
#   SIZE_T    dwSize;
#   DWORD     th32ProcessID;
#   ULONG_PTR th32HeapID;
#   DWORD     dwFlags;
# } HEAPLIST32,
#  *PHEAPLIST32;
class HEAPLIST32(Structure):
    _fields_ = [
        ("dwSize",          SIZE_T),
        ("th32ProcessID",   DWORD),
        ("th32HeapID",      ULONG_PTR),
        ("dwFlags",         DWORD),
]
LPHEAPLIST32 = POINTER(HEAPLIST32)


#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
#==============================================================================
