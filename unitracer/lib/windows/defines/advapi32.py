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
Wrapper for advapi32.dll in ctypes.
"""

__revision__ = "$Id: advapi32.py 1299 2013-12-20 09:30:55Z qvasimodo $"

from defines import *
from kernel32 import *

# XXX TODO
# + add transacted registry operations

#==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
#==============================================================================

#--- Constants ----------------------------------------------------------------

# Privilege constants
SE_ASSIGNPRIMARYTOKEN_NAME      = "SeAssignPrimaryTokenPrivilege"
SE_AUDIT_NAME                   = "SeAuditPrivilege"
SE_BACKUP_NAME                  = "SeBackupPrivilege"
SE_CHANGE_NOTIFY_NAME           = "SeChangeNotifyPrivilege"
SE_CREATE_GLOBAL_NAME           = "SeCreateGlobalPrivilege"
SE_CREATE_PAGEFILE_NAME         = "SeCreatePagefilePrivilege"
SE_CREATE_PERMANENT_NAME        = "SeCreatePermanentPrivilege"
SE_CREATE_SYMBOLIC_LINK_NAME    = "SeCreateSymbolicLinkPrivilege"
SE_CREATE_TOKEN_NAME            = "SeCreateTokenPrivilege"
SE_DEBUG_NAME                   = "SeDebugPrivilege"
SE_ENABLE_DELEGATION_NAME       = "SeEnableDelegationPrivilege"
SE_IMPERSONATE_NAME             = "SeImpersonatePrivilege"
SE_INC_BASE_PRIORITY_NAME       = "SeIncreaseBasePriorityPrivilege"
SE_INCREASE_QUOTA_NAME          = "SeIncreaseQuotaPrivilege"
SE_INC_WORKING_SET_NAME         = "SeIncreaseWorkingSetPrivilege"
SE_LOAD_DRIVER_NAME             = "SeLoadDriverPrivilege"
SE_LOCK_MEMORY_NAME             = "SeLockMemoryPrivilege"
SE_MACHINE_ACCOUNT_NAME         = "SeMachineAccountPrivilege"
SE_MANAGE_VOLUME_NAME           = "SeManageVolumePrivilege"
SE_PROF_SINGLE_PROCESS_NAME     = "SeProfileSingleProcessPrivilege"
SE_RELABEL_NAME                 = "SeRelabelPrivilege"
SE_REMOTE_SHUTDOWN_NAME         = "SeRemoteShutdownPrivilege"
SE_RESTORE_NAME                 = "SeRestorePrivilege"
SE_SECURITY_NAME                = "SeSecurityPrivilege"
SE_SHUTDOWN_NAME                = "SeShutdownPrivilege"
SE_SYNC_AGENT_NAME              = "SeSyncAgentPrivilege"
SE_SYSTEM_ENVIRONMENT_NAME      = "SeSystemEnvironmentPrivilege"
SE_SYSTEM_PROFILE_NAME          = "SeSystemProfilePrivilege"
SE_SYSTEMTIME_NAME              = "SeSystemtimePrivilege"
SE_TAKE_OWNERSHIP_NAME          = "SeTakeOwnershipPrivilege"
SE_TCB_NAME                     = "SeTcbPrivilege"
SE_TIME_ZONE_NAME               = "SeTimeZonePrivilege"
SE_TRUSTED_CREDMAN_ACCESS_NAME  = "SeTrustedCredManAccessPrivilege"
SE_UNDOCK_NAME                  = "SeUndockPrivilege"
SE_UNSOLICITED_INPUT_NAME       = "SeUnsolicitedInputPrivilege"

SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_ENABLED            = 0x00000002
SE_PRIVILEGE_REMOVED            = 0x00000004
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

TOKEN_ADJUST_PRIVILEGES         = 0x00000020

LOGON_WITH_PROFILE              = 0x00000001
LOGON_NETCREDENTIALS_ONLY       = 0x00000002

# Token access rights
TOKEN_ASSIGN_PRIMARY    = 0x0001
TOKEN_DUPLICATE         = 0x0002
TOKEN_IMPERSONATE       = 0x0004
TOKEN_QUERY             = 0x0008
TOKEN_QUERY_SOURCE      = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS     = 0x0040
TOKEN_ADJUST_DEFAULT    = 0x0080
TOKEN_ADJUST_SESSIONID  = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID)

# Predefined HKEY values
HKEY_CLASSES_ROOT       = 0x80000000
HKEY_CURRENT_USER       = 0x80000001
HKEY_LOCAL_MACHINE      = 0x80000002
HKEY_USERS              = 0x80000003
HKEY_PERFORMANCE_DATA   = 0x80000004
HKEY_CURRENT_CONFIG     = 0x80000005

# Registry access rights
KEY_ALL_ACCESS          = 0xF003F
KEY_CREATE_LINK         = 0x0020
KEY_CREATE_SUB_KEY      = 0x0004
KEY_ENUMERATE_SUB_KEYS  = 0x0008
KEY_EXECUTE             = 0x20019
KEY_NOTIFY              = 0x0010
KEY_QUERY_VALUE         = 0x0001
KEY_READ                = 0x20019
KEY_SET_VALUE           = 0x0002
KEY_WOW64_32KEY         = 0x0200
KEY_WOW64_64KEY         = 0x0100
KEY_WRITE               = 0x20006

# Registry value types
REG_NONE                        = 0
REG_SZ                          = 1
REG_EXPAND_SZ                   = 2
REG_BINARY                      = 3
REG_DWORD                       = 4
REG_DWORD_LITTLE_ENDIAN         = REG_DWORD
REG_DWORD_BIG_ENDIAN            = 5
REG_LINK                        = 6
REG_MULTI_SZ                    = 7
REG_RESOURCE_LIST               = 8
REG_FULL_RESOURCE_DESCRIPTOR    = 9
REG_RESOURCE_REQUIREMENTS_LIST  = 10
REG_QWORD                       = 11
REG_QWORD_LITTLE_ENDIAN         = REG_QWORD

#--- TOKEN_PRIVILEGE structure ------------------------------------------------

# typedef struct _LUID {
#   DWORD LowPart;
#   LONG HighPart;
# } LUID,
#  *PLUID;
class LUID(Structure):
    _fields_ = [
        ("LowPart",     DWORD),
        ("HighPart",    LONG),
    ]

PLUID = POINTER(LUID)

# typedef struct _LUID_AND_ATTRIBUTES {
#   LUID Luid;
#   DWORD Attributes;
# } LUID_AND_ATTRIBUTES,
#  *PLUID_AND_ATTRIBUTES;
class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid",        LUID),
        ("Attributes",  DWORD),
    ]

# typedef struct _TOKEN_PRIVILEGES {
#   DWORD PrivilegeCount;
#   LUID_AND_ATTRIBUTES Privileges[ANYSIZE_ARRAY];
# } TOKEN_PRIVILEGES,
#  *PTOKEN_PRIVILEGES;
class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount",  DWORD),
##        ("Privileges",      LUID_AND_ATTRIBUTES * ANYSIZE_ARRAY),
        ("Privileges",      LUID_AND_ATTRIBUTES),
    ]
    # See comments on AdjustTokenPrivileges about this structure

PTOKEN_PRIVILEGES = POINTER(TOKEN_PRIVILEGES)

#--- GetTokenInformation enums and structures ---------------------------------

# typedef enum _TOKEN_INFORMATION_CLASS {
#   TokenUser                              = 1,
#   TokenGroups,
#   TokenPrivileges,
#   TokenOwner,
#   TokenPrimaryGroup,
#   TokenDefaultDacl,
#   TokenSource,
#   TokenType,
#   TokenImpersonationLevel,
#   TokenStatistics,
#   TokenRestrictedSids,
#   TokenSessionId,
#   TokenGroupsAndPrivileges,
#   TokenSessionReference,
#   TokenSandBoxInert,
#   TokenAuditPolicy,
#   TokenOrigin,
#   TokenElevationType,
#   TokenLinkedToken,
#   TokenElevation,
#   TokenHasRestrictions,
#   TokenAccessInformation,
#   TokenVirtualizationAllowed,
#   TokenVirtualizationEnabled,
#   TokenIntegrityLevel,
#   TokenUIAccess,
#   TokenMandatoryPolicy,
#   TokenLogonSid,
#   TokenIsAppContainer,
#   TokenCapabilities,
#   TokenAppContainerSid,
#   TokenAppContainerNumber,
#   TokenUserClaimAttributes,
#   TokenDeviceClaimAttributes,
#   TokenRestrictedUserClaimAttributes,
#   TokenRestrictedDeviceClaimAttributes,
#   TokenDeviceGroups,
#   TokenRestrictedDeviceGroups,
#   TokenSecurityAttributes,
#   TokenIsRestricted,
#   MaxTokenInfoClass
# } TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

TOKEN_INFORMATION_CLASS = ctypes.c_int

TokenUser                               = 1
TokenGroups                             = 2
TokenPrivileges                         = 3
TokenOwner                              = 4
TokenPrimaryGroup                       = 5
TokenDefaultDacl                        = 6
TokenSource                             = 7
TokenType                               = 8
TokenImpersonationLevel                 = 9
TokenStatistics                         = 10
TokenRestrictedSids                     = 11
TokenSessionId                          = 12
TokenGroupsAndPrivileges                = 13
TokenSessionReference                   = 14
TokenSandBoxInert                       = 15
TokenAuditPolicy                        = 16
TokenOrigin                             = 17
TokenElevationType                      = 18
TokenLinkedToken                        = 19
TokenElevation                          = 20
TokenHasRestrictions                    = 21
TokenAccessInformation                  = 22
TokenVirtualizationAllowed              = 23
TokenVirtualizationEnabled              = 24
TokenIntegrityLevel                     = 25
TokenUIAccess                           = 26
TokenMandatoryPolicy                    = 27
TokenLogonSid                           = 28
TokenIsAppContainer                     = 29
TokenCapabilities                       = 30
TokenAppContainerSid                    = 31
TokenAppContainerNumber                 = 32
TokenUserClaimAttributes                = 33
TokenDeviceClaimAttributes              = 34
TokenRestrictedUserClaimAttributes      = 35
TokenRestrictedDeviceClaimAttributes    = 36
TokenDeviceGroups                       = 37
TokenRestrictedDeviceGroups             = 38
TokenSecurityAttributes                 = 39
TokenIsRestricted                       = 40
MaxTokenInfoClass                       = 41

# typedef enum tagTOKEN_TYPE {
#   TokenPrimary         = 1,
#   TokenImpersonation
# } TOKEN_TYPE, *PTOKEN_TYPE;

TOKEN_TYPE = ctypes.c_int
PTOKEN_TYPE = POINTER(TOKEN_TYPE)

TokenPrimary        = 1
TokenImpersonation  = 2

# typedef enum  {
#   TokenElevationTypeDefault   = 1,
#   TokenElevationTypeFull,
#   TokenElevationTypeLimited
# } TOKEN_ELEVATION_TYPE , *PTOKEN_ELEVATION_TYPE;

TokenElevationTypeDefault   = 1
TokenElevationTypeFull      = 2
TokenElevationTypeLimited   = 3

TOKEN_ELEVATION_TYPE = ctypes.c_int
PTOKEN_ELEVATION_TYPE = POINTER(TOKEN_ELEVATION_TYPE)

# typedef enum _SECURITY_IMPERSONATION_LEVEL {
#   SecurityAnonymous,
#   SecurityIdentification,
#   SecurityImpersonation,
#   SecurityDelegation
# } SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

SecurityAnonymous       = 0
SecurityIdentification  = 1
SecurityImpersonation   = 2
SecurityDelegation      = 3

SECURITY_IMPERSONATION_LEVEL = ctypes.c_int
PSECURITY_IMPERSONATION_LEVEL = POINTER(SECURITY_IMPERSONATION_LEVEL)

# typedef struct _SID_AND_ATTRIBUTES {
#   PSID  Sid;
#   DWORD Attributes;
# } SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES;
class SID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Sid",         PSID),
        ("Attributes",  DWORD),
    ]
PSID_AND_ATTRIBUTES = POINTER(SID_AND_ATTRIBUTES)

# typedef struct _TOKEN_USER {
#   SID_AND_ATTRIBUTES User;
# } TOKEN_USER, *PTOKEN_USER;
class TOKEN_USER(Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]
PTOKEN_USER = POINTER(TOKEN_USER)

# typedef struct _TOKEN_MANDATORY_LABEL {
#   SID_AND_ATTRIBUTES Label;
# } TOKEN_MANDATORY_LABEL, *PTOKEN_MANDATORY_LABEL;
class TOKEN_MANDATORY_LABEL(Structure):
    _fields_ = [
        ("Label", SID_AND_ATTRIBUTES),
    ]
PTOKEN_MANDATORY_LABEL = POINTER(TOKEN_MANDATORY_LABEL)

# typedef struct _TOKEN_OWNER {
#   PSID Owner;
# } TOKEN_OWNER, *PTOKEN_OWNER;
class TOKEN_OWNER(Structure):
    _fields_ = [
        ("Owner", PSID),
    ]
PTOKEN_OWNER = POINTER(TOKEN_OWNER)

# typedef struct _TOKEN_PRIMARY_GROUP {
#   PSID PrimaryGroup;
# } TOKEN_PRIMARY_GROUP, *PTOKEN_PRIMARY_GROUP;
class TOKEN_PRIMARY_GROUP(Structure):
    _fields_ = [
        ("PrimaryGroup", PSID),
    ]
PTOKEN_PRIMARY_GROUP = POINTER(TOKEN_PRIMARY_GROUP)

# typedef struct _TOKEN_APPCONTAINER_INFORMATION {
#   	PSID TokenAppContainer;
# } TOKEN_APPCONTAINER_INFORMATION, *PTOKEN_APPCONTAINER_INFORMATION;
class TOKEN_APPCONTAINER_INFORMATION(Structure):
    _fields_ = [
        ("TokenAppContainer", PSID),
    ]
PTOKEN_APPCONTAINER_INFORMATION = POINTER(TOKEN_APPCONTAINER_INFORMATION)

# typedef struct _TOKEN_ORIGIN {
#   LUID OriginatingLogonSession;
# } TOKEN_ORIGIN, *PTOKEN_ORIGIN;
class TOKEN_ORIGIN(Structure):
    _fields_ = [
        ("OriginatingLogonSession", LUID),
    ]
PTOKEN_ORIGIN = POINTER(TOKEN_ORIGIN)

# typedef struct _TOKEN_LINKED_TOKEN {
#   HANDLE LinkedToken;
# } TOKEN_LINKED_TOKEN, *PTOKEN_LINKED_TOKEN;
class TOKEN_LINKED_TOKEN(Structure):
    _fields_ = [
        ("LinkedToken", HANDLE),
    ]
PTOKEN_LINKED_TOKEN = POINTER(TOKEN_LINKED_TOKEN)

# typedef struct _TOKEN_STATISTICS {
#   LUID                         TokenId;
#   LUID                         AuthenticationId;
#   LARGE_INTEGER                ExpirationTime;
#   TOKEN_TYPE                   TokenType;
#   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
#   DWORD                        DynamicCharged;
#   DWORD                        DynamicAvailable;
#   DWORD                        GroupCount;
#   DWORD                        PrivilegeCount;
#   LUID                         ModifiedId;
# } TOKEN_STATISTICS, *PTOKEN_STATISTICS;
class TOKEN_STATISTICS(Structure):
    _fields_ = [
        ("TokenId",             LUID),
        ("AuthenticationId",    LUID),
        ("ExpirationTime",      LONGLONG),  # LARGE_INTEGER
        ("TokenType",           TOKEN_TYPE),
        ("ImpersonationLevel",  SECURITY_IMPERSONATION_LEVEL),
        ("DynamicCharged",      DWORD),
        ("DynamicAvailable",    DWORD),
        ("GroupCount",          DWORD),
        ("PrivilegeCount",      DWORD),
        ("ModifiedId",          LUID),
    ]
PTOKEN_STATISTICS = POINTER(TOKEN_STATISTICS)

#--- SID_NAME_USE enum --------------------------------------------------------

# typedef enum _SID_NAME_USE {
#   SidTypeUser             = 1,
#   SidTypeGroup,
#   SidTypeDomain,
#   SidTypeAlias,
#   SidTypeWellKnownGroup,
#   SidTypeDeletedAccount,
#   SidTypeInvalid,
#   SidTypeUnknown,
#   SidTypeComputer,
#   SidTypeLabel
# } SID_NAME_USE, *PSID_NAME_USE;

SidTypeUser             = 1
SidTypeGroup            = 2
SidTypeDomain           = 3
SidTypeAlias            = 4
SidTypeWellKnownGroup   = 5
SidTypeDeletedAccount   = 6
SidTypeInvalid          = 7
SidTypeUnknown          = 8
SidTypeComputer         = 9
SidTypeLabel            = 10

#--- WAITCHAIN_NODE_INFO structure and types ----------------------------------

WCT_MAX_NODE_COUNT       = 16
WCT_OBJNAME_LENGTH       = 128
WCT_ASYNC_OPEN_FLAG      = 1
WCTP_OPEN_ALL_FLAGS      = WCT_ASYNC_OPEN_FLAG
WCT_OUT_OF_PROC_FLAG     = 1
WCT_OUT_OF_PROC_COM_FLAG = 2
WCT_OUT_OF_PROC_CS_FLAG  = 4
WCTP_GETINFO_ALL_FLAGS   = WCT_OUT_OF_PROC_FLAG | WCT_OUT_OF_PROC_COM_FLAG | WCT_OUT_OF_PROC_CS_FLAG

HWCT = LPVOID

# typedef enum _WCT_OBJECT_TYPE
# {
#     WctCriticalSectionType = 1,
#     WctSendMessageType,
#     WctMutexType,
#     WctAlpcType,
#     WctComType,
#     WctThreadWaitType,
#     WctProcessWaitType,
#     WctThreadType,
#     WctComActivationType,
#     WctUnknownType,
#     WctMaxType
# } WCT_OBJECT_TYPE;

WCT_OBJECT_TYPE         = DWORD

WctCriticalSectionType  = 1
WctSendMessageType      = 2
WctMutexType            = 3
WctAlpcType             = 4
WctComType              = 5
WctThreadWaitType       = 6
WctProcessWaitType      = 7
WctThreadType           = 8
WctComActivationType    = 9
WctUnknownType          = 10
WctMaxType              = 11

# typedef enum _WCT_OBJECT_STATUS
# {
#     WctStatusNoAccess = 1,            // ACCESS_DENIED for this object
#     WctStatusRunning,                 // Thread status
#     WctStatusBlocked,                 // Thread status
#     WctStatusPidOnly,                 // Thread status
#     WctStatusPidOnlyRpcss,            // Thread status
#     WctStatusOwned,                   // Dispatcher object status
#     WctStatusNotOwned,                // Dispatcher object status
#     WctStatusAbandoned,               // Dispatcher object status
#     WctStatusUnknown,                 // All objects
#     WctStatusError,                   // All objects
#     WctStatusMax
# } WCT_OBJECT_STATUS;

WCT_OBJECT_STATUS       = DWORD

WctStatusNoAccess       = 1             # ACCESS_DENIED for this object
WctStatusRunning        = 2             # Thread status
WctStatusBlocked        = 3             # Thread status
WctStatusPidOnly        = 4             # Thread status
WctStatusPidOnlyRpcss   = 5             # Thread status
WctStatusOwned          = 6             # Dispatcher object status
WctStatusNotOwned       = 7             # Dispatcher object status
WctStatusAbandoned      = 8             # Dispatcher object status
WctStatusUnknown        = 9             # All objects
WctStatusError          = 10            # All objects
WctStatusMax            = 11

# typedef struct _WAITCHAIN_NODE_INFO {
#   WCT_OBJECT_TYPE   ObjectType;
#   WCT_OBJECT_STATUS ObjectStatus;
#   union {
#     struct {
#       WCHAR ObjectName[WCT_OBJNAME_LENGTH];
#       LARGE_INTEGER Timeout;
#       BOOL Alertable;
#     } LockObject;
#     struct {
#       DWORD ProcessId;
#       DWORD ThreadId;
#       DWORD WaitTime;
#       DWORD ContextSwitches;
#     } ThreadObject;
#   } ;
# }WAITCHAIN_NODE_INFO, *PWAITCHAIN_NODE_INFO;

class _WAITCHAIN_NODE_INFO_STRUCT_1(Structure):
    _fields_ = [
        ("ObjectName",      WCHAR * WCT_OBJNAME_LENGTH),
        ("Timeout",         LONGLONG), # LARGE_INTEGER
        ("Alertable",       BOOL),
    ]

class _WAITCHAIN_NODE_INFO_STRUCT_2(Structure):
    _fields_ = [
        ("ProcessId",       DWORD),
        ("ThreadId",        DWORD),
        ("WaitTime",        DWORD),
        ("ContextSwitches", DWORD),
    ]

class _WAITCHAIN_NODE_INFO_UNION(Union):
    _fields_ = [
        ("LockObject",      _WAITCHAIN_NODE_INFO_STRUCT_1),
        ("ThreadObject",    _WAITCHAIN_NODE_INFO_STRUCT_2),
    ]

class WAITCHAIN_NODE_INFO(Structure):
    _fields_ = [
        ("ObjectType",      WCT_OBJECT_TYPE),
        ("ObjectStatus",    WCT_OBJECT_STATUS),
        ("u",               _WAITCHAIN_NODE_INFO_UNION),
    ]

PWAITCHAIN_NODE_INFO = POINTER(WAITCHAIN_NODE_INFO)

class WaitChainNodeInfo (object):
    """
    Represents a node in the wait chain.

    It's a wrapper on the L{WAITCHAIN_NODE_INFO} structure.

    The following members are defined only
    if the node is of L{WctThreadType} type:
     - C{ProcessId}
     - C{ThreadId}
     - C{WaitTime}
     - C{ContextSwitches}

    @see: L{GetThreadWaitChain}

    @type ObjectName: unicode
    @ivar ObjectName: Object name. May be an empty string.

    @type ObjectType: int
    @ivar ObjectType: Object type.
        Should be one of the following values:
         - L{WctCriticalSectionType}
         - L{WctSendMessageType}
         - L{WctMutexType}
         - L{WctAlpcType}
         - L{WctComType}
         - L{WctThreadWaitType}
         - L{WctProcessWaitType}
         - L{WctThreadType}
         - L{WctComActivationType}
         - L{WctUnknownType}

    @type ObjectStatus: int
    @ivar ObjectStatus: Wait status.
        Should be one of the following values:
         - L{WctStatusNoAccess} I{(ACCESS_DENIED for this object)}
         - L{WctStatusRunning} I{(Thread status)}
         - L{WctStatusBlocked} I{(Thread status)}
         - L{WctStatusPidOnly} I{(Thread status)}
         - L{WctStatusPidOnlyRpcss} I{(Thread status)}
         - L{WctStatusOwned} I{(Dispatcher object status)}
         - L{WctStatusNotOwned} I{(Dispatcher object status)}
         - L{WctStatusAbandoned} I{(Dispatcher object status)}
         - L{WctStatusUnknown} I{(All objects)}
         - L{WctStatusError} I{(All objects)}

    @type ProcessId: int
    @ivar ProcessId: Process global ID.

    @type ThreadId: int
    @ivar ThreadId: Thread global ID.

    @type WaitTime: int
    @ivar WaitTime: Wait time.

    @type ContextSwitches: int
    @ivar ContextSwitches: Number of context switches.
    """

    #@type Timeout: int
    #@ivar Timeout: Currently not documented in MSDN.
    #
    #@type Alertable: bool
    #@ivar Alertable: Currently not documented in MSDN.

    # TODO: __repr__

    def __init__(self, aStructure):
        self.ObjectType = aStructure.ObjectType
        self.ObjectStatus = aStructure.ObjectStatus
        if self.ObjectType == WctThreadType:
            self.ProcessId = aStructure.u.ThreadObject.ProcessId
            self.ThreadId = aStructure.u.ThreadObject.ThreadId
            self.WaitTime = aStructure.u.ThreadObject.WaitTime
            self.ContextSwitches = aStructure.u.ThreadObject.ContextSwitches
            self.ObjectName = u''
        else:
            self.ObjectName = aStructure.u.LockObject.ObjectName.value
            #self.Timeout = aStructure.u.LockObject.Timeout
            #self.Alertable = bool(aStructure.u.LockObject.Alertable)

class ThreadWaitChainSessionHandle (Handle):
    """
    Thread wait chain session handle.

    Returned by L{OpenThreadWaitChainSession}.

    @see: L{Handle}
    """

    def __init__(self, aHandle = None):
        """
        @type  aHandle: int
        @param aHandle: Win32 handle value.
        """
        super(ThreadWaitChainSessionHandle, self).__init__(aHandle,
                                                           bOwnership = True)

    def _close(self):
        if self.value is None:
            raise ValueError("Handle was already closed!")
        CloseThreadWaitChainSession(self.value)

    def dup(self):
        raise NotImplementedError()

    def wait(self, dwMilliseconds = None):
        raise NotImplementedError()

    @property
    def inherit(self):
        return False

    @property
    def protectFromClose(self):
        return False

#--- Privilege dropping -------------------------------------------------------

SAFER_LEVEL_HANDLE = HANDLE

SAFER_SCOPEID_MACHINE = 1
SAFER_SCOPEID_USER    = 2

SAFER_LEVEL_OPEN = 1

SAFER_LEVELID_DISALLOWED   = 0x00000
SAFER_LEVELID_UNTRUSTED    = 0x01000
SAFER_LEVELID_CONSTRAINED  = 0x10000
SAFER_LEVELID_NORMALUSER   = 0x20000
SAFER_LEVELID_FULLYTRUSTED = 0x40000

SAFER_POLICY_INFO_CLASS = DWORD
SaferPolicyLevelList = 1
SaferPolicyEnableTransparentEnforcement = 2
SaferPolicyDefaultLevel = 3
SaferPolicyEvaluateUserScope = 4
SaferPolicyScopeFlags = 5

SAFER_TOKEN_NULL_IF_EQUAL = 1
SAFER_TOKEN_COMPARE_ONLY  = 2
SAFER_TOKEN_MAKE_INERT    = 4
SAFER_TOKEN_WANT_FLAGS    = 8
SAFER_TOKEN_MASK          = 15

#--- Service Control Manager types, constants and structures ------------------

SC_HANDLE = HANDLE

SERVICES_ACTIVE_DATABASEW = u"ServicesActive"
SERVICES_FAILED_DATABASEW = u"ServicesFailed"

SERVICES_ACTIVE_DATABASEA = "ServicesActive"
SERVICES_FAILED_DATABASEA = "ServicesFailed"

SC_GROUP_IDENTIFIERW = u'+'
SC_GROUP_IDENTIFIERA = '+'

SERVICE_NO_CHANGE = 0xffffffff

# enum SC_STATUS_TYPE
SC_STATUS_TYPE         = ctypes.c_int
SC_STATUS_PROCESS_INFO = 0

# enum SC_ENUM_TYPE
SC_ENUM_TYPE         = ctypes.c_int
SC_ENUM_PROCESS_INFO = 0

# Access rights
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx

SERVICE_ALL_ACCESS           = 0xF01FF
SERVICE_QUERY_CONFIG         = 0x0001
SERVICE_CHANGE_CONFIG        = 0x0002
SERVICE_QUERY_STATUS         = 0x0004
SERVICE_ENUMERATE_DEPENDENTS = 0x0008
SERVICE_START                = 0x0010
SERVICE_STOP                 = 0x0020
SERVICE_PAUSE_CONTINUE       = 0x0040
SERVICE_INTERROGATE          = 0x0080
SERVICE_USER_DEFINED_CONTROL = 0x0100

SC_MANAGER_ALL_ACCESS           = 0xF003F
SC_MANAGER_CONNECT              = 0x0001
SC_MANAGER_CREATE_SERVICE       = 0x0002
SC_MANAGER_ENUMERATE_SERVICE    = 0x0004
SC_MANAGER_LOCK                 = 0x0008
SC_MANAGER_QUERY_LOCK_STATUS    = 0x0010
SC_MANAGER_MODIFY_BOOT_CONFIG   = 0x0020

# CreateService() service start type
SERVICE_BOOT_START   = 0x00000000
SERVICE_SYSTEM_START = 0x00000001
SERVICE_AUTO_START   = 0x00000002
SERVICE_DEMAND_START = 0x00000003
SERVICE_DISABLED     = 0x00000004

# CreateService() error control flags
SERVICE_ERROR_IGNORE    = 0x00000000
SERVICE_ERROR_NORMAL    = 0x00000001
SERVICE_ERROR_SEVERE    = 0x00000002
SERVICE_ERROR_CRITICAL  = 0x00000003

# EnumServicesStatusEx() service state filters
SERVICE_ACTIVE    = 1
SERVICE_INACTIVE  = 2
SERVICE_STATE_ALL = 3

# SERVICE_STATUS_PROCESS.dwServiceType
SERVICE_KERNEL_DRIVER       = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
SERVICE_ADAPTER             = 0x00000004
SERVICE_RECOGNIZER_DRIVER   = 0x00000008
SERVICE_WIN32_OWN_PROCESS   = 0x00000010
SERVICE_WIN32_SHARE_PROCESS = 0x00000020
SERVICE_INTERACTIVE_PROCESS = 0x00000100

# EnumServicesStatusEx() service type filters (in addition to actual types)
SERVICE_DRIVER = 0x0000000B # SERVICE_KERNEL_DRIVER and SERVICE_FILE_SYSTEM_DRIVER
SERVICE_WIN32  = 0x00000030 # SERVICE_WIN32_OWN_PROCESS and SERVICE_WIN32_SHARE_PROCESS

# SERVICE_STATUS_PROCESS.dwCurrentState
SERVICE_STOPPED             = 0x00000001
SERVICE_START_PENDING       = 0x00000002
SERVICE_STOP_PENDING        = 0x00000003
SERVICE_RUNNING             = 0x00000004
SERVICE_CONTINUE_PENDING    = 0x00000005
SERVICE_PAUSE_PENDING       = 0x00000006
SERVICE_PAUSED              = 0x00000007

# SERVICE_STATUS_PROCESS.dwControlsAccepted
SERVICE_ACCEPT_STOP                  = 0x00000001
SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
SERVICE_ACCEPT_NETBINDCHANGE         = 0x00000010
SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
SERVICE_ACCEPT_POWEREVENT            = 0x00000040
SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100

# SERVICE_STATUS_PROCESS.dwServiceFlags
SERVICE_RUNS_IN_SYSTEM_PROCESS = 0x00000001

# Service control flags
SERVICE_CONTROL_STOP                  = 0x00000001
SERVICE_CONTROL_PAUSE                 = 0x00000002
SERVICE_CONTROL_CONTINUE              = 0x00000003
SERVICE_CONTROL_INTERROGATE           = 0x00000004
SERVICE_CONTROL_SHUTDOWN              = 0x00000005
SERVICE_CONTROL_PARAMCHANGE           = 0x00000006
SERVICE_CONTROL_NETBINDADD            = 0x00000007
SERVICE_CONTROL_NETBINDREMOVE         = 0x00000008
SERVICE_CONTROL_NETBINDENABLE         = 0x00000009
SERVICE_CONTROL_NETBINDDISABLE        = 0x0000000A
SERVICE_CONTROL_DEVICEEVENT           = 0x0000000B
SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C
SERVICE_CONTROL_POWEREVENT            = 0x0000000D
SERVICE_CONTROL_SESSIONCHANGE         = 0x0000000E

# Service control accepted bitmasks
SERVICE_ACCEPT_STOP                  = 0x00000001
SERVICE_ACCEPT_PAUSE_CONTINUE        = 0x00000002
SERVICE_ACCEPT_SHUTDOWN              = 0x00000004
SERVICE_ACCEPT_PARAMCHANGE           = 0x00000008
SERVICE_ACCEPT_NETBINDCHANGE         = 0x00000010
SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
SERVICE_ACCEPT_POWEREVENT            = 0x00000040
SERVICE_ACCEPT_SESSIONCHANGE         = 0x00000080
SERVICE_ACCEPT_PRESHUTDOWN           = 0x00000100
SERVICE_ACCEPT_TIMECHANGE            = 0x00000200
SERVICE_ACCEPT_TRIGGEREVENT          = 0x00000400
SERVICE_ACCEPT_USERMODEREBOOT        = 0x00000800

# enum SC_ACTION_TYPE
SC_ACTION_NONE        = 0
SC_ACTION_RESTART     = 1
SC_ACTION_REBOOT      = 2
SC_ACTION_RUN_COMMAND = 3

# QueryServiceConfig2
SERVICE_CONFIG_DESCRIPTION     = 1
SERVICE_CONFIG_FAILURE_ACTIONS = 2

# typedef struct _SERVICE_STATUS {
#   DWORD dwServiceType;
#   DWORD dwCurrentState;
#   DWORD dwControlsAccepted;
#   DWORD dwWin32ExitCode;
#   DWORD dwServiceSpecificExitCode;
#   DWORD dwCheckPoint;
#   DWORD dwWaitHint;
# } SERVICE_STATUS, *LPSERVICE_STATUS;
class SERVICE_STATUS(Structure):
    _fields_ = [
        ("dwServiceType",               DWORD),
        ("dwCurrentState",              DWORD),
        ("dwControlsAccepted",          DWORD),
        ("dwWin32ExitCode",             DWORD),
        ("dwServiceSpecificExitCode",   DWORD),
        ("dwCheckPoint",                DWORD),
        ("dwWaitHint",                  DWORD),
    ]
LPSERVICE_STATUS = POINTER(SERVICE_STATUS)

# typedef struct _SERVICE_STATUS_PROCESS {
#   DWORD dwServiceType;
#   DWORD dwCurrentState;
#   DWORD dwControlsAccepted;
#   DWORD dwWin32ExitCode;
#   DWORD dwServiceSpecificExitCode;
#   DWORD dwCheckPoint;
#   DWORD dwWaitHint;
#   DWORD dwProcessId;
#   DWORD dwServiceFlags;
# } SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;
class SERVICE_STATUS_PROCESS(Structure):
    _fields_ = SERVICE_STATUS._fields_ + [
        ("dwProcessId",                 DWORD),
        ("dwServiceFlags",              DWORD),
    ]
LPSERVICE_STATUS_PROCESS = POINTER(SERVICE_STATUS_PROCESS)

# typedef struct _ENUM_SERVICE_STATUS {
#   LPTSTR         lpServiceName;
#   LPTSTR         lpDisplayName;
#   SERVICE_STATUS ServiceStatus;
# } ENUM_SERVICE_STATUS, *LPENUM_SERVICE_STATUS;
class ENUM_SERVICE_STATUSA(Structure):
    _fields_ = [
        ("lpServiceName", LPSTR),
        ("lpDisplayName", LPSTR),
        ("ServiceStatus", SERVICE_STATUS),
    ]
class ENUM_SERVICE_STATUSW(Structure):
    _fields_ = [
        ("lpServiceName", LPWSTR),
        ("lpDisplayName", LPWSTR),
        ("ServiceStatus", SERVICE_STATUS),
    ]
LPENUM_SERVICE_STATUSA = POINTER(ENUM_SERVICE_STATUSA)
LPENUM_SERVICE_STATUSW = POINTER(ENUM_SERVICE_STATUSW)

# typedef struct _ENUM_SERVICE_STATUS_PROCESS {
#   LPTSTR                 lpServiceName;
#   LPTSTR                 lpDisplayName;
#   SERVICE_STATUS_PROCESS ServiceStatusProcess;
# } ENUM_SERVICE_STATUS_PROCESS, *LPENUM_SERVICE_STATUS_PROCESS;
class ENUM_SERVICE_STATUS_PROCESSA(Structure):
    _fields_ = [
        ("lpServiceName",        LPSTR),
        ("lpDisplayName",        LPSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
class ENUM_SERVICE_STATUS_PROCESSW(Structure):
    _fields_ = [
        ("lpServiceName",        LPWSTR),
        ("lpDisplayName",        LPWSTR),
        ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
    ]
LPENUM_SERVICE_STATUS_PROCESSA = POINTER(ENUM_SERVICE_STATUS_PROCESSA)
LPENUM_SERVICE_STATUS_PROCESSW = POINTER(ENUM_SERVICE_STATUS_PROCESSW)

class ServiceStatus(object):
    """
    Wrapper for the L{SERVICE_STATUS} structure.
    """

    def __init__(self, raw):
        """
        @type  raw: L{SERVICE_STATUS}
        @param raw: Raw structure for this service status data.
        """
        self.ServiceType             = raw.dwServiceType
        self.CurrentState            = raw.dwCurrentState
        self.ControlsAccepted        = raw.dwControlsAccepted
        self.Win32ExitCode           = raw.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.dwServiceSpecificExitCode
        self.CheckPoint              = raw.dwCheckPoint
        self.WaitHint                = raw.dwWaitHint

class ServiceStatusProcess(object):
    """
    Wrapper for the L{SERVICE_STATUS_PROCESS} structure.
    """

    def __init__(self, raw):
        """
        @type  raw: L{SERVICE_STATUS_PROCESS}
        @param raw: Raw structure for this service status data.
        """
        self.ServiceType             = raw.dwServiceType
        self.CurrentState            = raw.dwCurrentState
        self.ControlsAccepted        = raw.dwControlsAccepted
        self.Win32ExitCode           = raw.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.dwServiceSpecificExitCode
        self.CheckPoint              = raw.dwCheckPoint
        self.WaitHint                = raw.dwWaitHint
        self.ProcessId               = raw.dwProcessId
        self.ServiceFlags            = raw.dwServiceFlags

class ServiceStatusEntry(object):
    """
    Service status entry returned by L{EnumServicesStatus}.
    """

    def __init__(self, raw):
        """
        @type  raw: L{ENUM_SERVICE_STATUSA} or L{ENUM_SERVICE_STATUSW}
        @param raw: Raw structure for this service status entry.
        """
        self.ServiceName             = raw.lpServiceName
        self.DisplayName             = raw.lpDisplayName
        self.ServiceType             = raw.ServiceStatus.dwServiceType
        self.CurrentState            = raw.ServiceStatus.dwCurrentState
        self.ControlsAccepted        = raw.ServiceStatus.dwControlsAccepted
        self.Win32ExitCode           = raw.ServiceStatus.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.ServiceStatus.dwServiceSpecificExitCode
        self.CheckPoint              = raw.ServiceStatus.dwCheckPoint
        self.WaitHint                = raw.ServiceStatus.dwWaitHint

    def __str__(self):
        output = []
        if self.ServiceType & SERVICE_INTERACTIVE_PROCESS:
            output.append("Interactive service")
        else:
            output.append("Service")
        if self.DisplayName:
            output.append("\"%s\" (%s)" % (self.DisplayName, self.ServiceName))
        else:
            output.append("\"%s\"" % self.ServiceName)
        if   self.CurrentState == SERVICE_CONTINUE_PENDING:
            output.append("is about to continue.")
        elif self.CurrentState == SERVICE_PAUSE_PENDING:
            output.append("is pausing.")
        elif self.CurrentState == SERVICE_PAUSED:
            output.append("is paused.")
        elif self.CurrentState == SERVICE_RUNNING:
            output.append("is running.")
        elif self.CurrentState == SERVICE_START_PENDING:
            output.append("is starting.")
        elif self.CurrentState == SERVICE_STOP_PENDING:
            output.append("is stopping.")
        elif self.CurrentState == SERVICE_STOPPED:
            output.append("is stopped.")
        return " ".join(output)

class ServiceStatusProcessEntry(object):
    """
    Service status entry returned by L{EnumServicesStatusEx}.
    """

    def __init__(self, raw):
        """
        @type  raw: L{ENUM_SERVICE_STATUS_PROCESSA} or L{ENUM_SERVICE_STATUS_PROCESSW}
        @param raw: Raw structure for this service status entry.
        """
        self.ServiceName             = raw.lpServiceName
        self.DisplayName             = raw.lpDisplayName
        self.ServiceType             = raw.ServiceStatusProcess.dwServiceType
        self.CurrentState            = raw.ServiceStatusProcess.dwCurrentState
        self.ControlsAccepted        = raw.ServiceStatusProcess.dwControlsAccepted
        self.Win32ExitCode           = raw.ServiceStatusProcess.dwWin32ExitCode
        self.ServiceSpecificExitCode = raw.ServiceStatusProcess.dwServiceSpecificExitCode
        self.CheckPoint              = raw.ServiceStatusProcess.dwCheckPoint
        self.WaitHint                = raw.ServiceStatusProcess.dwWaitHint
        self.ProcessId               = raw.ServiceStatusProcess.dwProcessId
        self.ServiceFlags            = raw.ServiceStatusProcess.dwServiceFlags

    def __str__(self):
        output = []
        if self.ServiceType & SERVICE_INTERACTIVE_PROCESS:
            output.append("Interactive service ")
        else:
            output.append("Service ")
        if self.DisplayName:
            output.append("\"%s\" (%s)" % (self.DisplayName, self.ServiceName))
        else:
            output.append("\"%s\"" % self.ServiceName)
        if   self.CurrentState == SERVICE_CONTINUE_PENDING:
            output.append(" is about to continue")
        elif self.CurrentState == SERVICE_PAUSE_PENDING:
            output.append(" is pausing")
        elif self.CurrentState == SERVICE_PAUSED:
            output.append(" is paused")
        elif self.CurrentState == SERVICE_RUNNING:
            output.append(" is running")
        elif self.CurrentState == SERVICE_START_PENDING:
            output.append(" is starting")
        elif self.CurrentState == SERVICE_STOP_PENDING:
            output.append(" is stopping")
        elif self.CurrentState == SERVICE_STOPPED:
            output.append(" is stopped")
        if self.ProcessId:
            output.append(" at process %d" % self.ProcessId)
        output.append(".")
        return "".join(output)

#--- Handle wrappers ----------------------------------------------------------

# XXX maybe add functions related to the tokens here?
class TokenHandle (Handle):
    """
    Access token handle.

    @see: L{Handle}
    """
    pass

class RegistryKeyHandle (UserModeHandle):
    """
    Registry key handle.
    """

    _TYPE = HKEY

    def _close(self):
        RegCloseKey(self.value)

class SaferLevelHandle (UserModeHandle):
    """
    Safer level handle.

    @see: U{http://msdn.microsoft.com/en-us/library/ms722425(VS.85).aspx}
    """

    _TYPE = SAFER_LEVEL_HANDLE

    def _close(self):
        SaferCloseLevel(self.value)

class ServiceHandle (UserModeHandle):
    """
    Service handle.

    @see: U{http://msdn.microsoft.com/en-us/library/windows/desktop/ms684330(v=vs.85).aspx}
    """

    _TYPE = SC_HANDLE

    def _close(self):
        CloseServiceHandle(self.value)

class ServiceControlManagerHandle (UserModeHandle):
    """
    Service Control Manager (SCM) handle.

    @see: U{http://msdn.microsoft.com/en-us/library/windows/desktop/ms684323(v=vs.85).aspx}
    """

    _TYPE = SC_HANDLE

    def _close(self):
        CloseServiceHandle(self.value)

#==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith('_')]
__all__.sort()
#==============================================================================
