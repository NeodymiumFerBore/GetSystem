#ifndef DEF_ELEVATE_H
#define DEF_ELEVATE_H

// Interesting functions to look after
// GetUserNameEx()
// ConvertSidToStringSid()
// LookupAccountSid()
// CreateRestrictedToken()
// ConvertStringSidToSid() // for getTI

#include "utils.h"
#include "tokenmgt.h"
#include "service.h"
#include "namedpipe.h"
#include "filedropper.h"

#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>

BOOL WINAPI getsystem(TokenCollection * tc);
BOOL WINAPI getTrustedInstaller(TokenCollection * tc);

//static BOOL WINAPI checkProcName(DWORD procID, LPCWSTR name);

static BOOL WINAPI checkProcessExecution(LPCWSTR name, DWORD * pid);

//void PrintProcessNameAndID(DWORD processID);
//int test_enum_processes(void);
void PrintProcesses();

#endif // DEF_ELEVATE_H

/*
THOSE ARE ALL WINDOWS PRIVILEGES DEFINES

SE_ASSIGNPRIMARYTOKEN_NAME
TEXT("SeAssignPrimaryTokenPrivilege")

SE_AUDIT_NAME
TEXT("SeAuditPrivilege")

SE_BACKUP_NAME
TEXT("SeBackupPrivilege")

SE_CHANGE_NOTIFY_NAME
TEXT("SeChangeNotifyPrivilege")

SE_CREATE_GLOBAL_NAME
TEXT("SeCreateGlobalPrivilege")

SE_CREATE_PAGEFILE_NAME
TEXT("SeCreatePagefilePrivilege")

SE_CREATE_PERMANENT_NAME
TEXT("SeCreatePermanentPrivilege")

SE_CREATE_SYMBOLIC_LINK_NAME
TEXT("SeCreateSymbolicLinkPrivilege")

SE_CREATE_TOKEN_NAME
TEXT("SeCreateTokenPrivilege")

SE_DEBUG_NAME
TEXT("SeDebugPrivilege")

SE_ENABLE_DELEGATION_NAME
TEXT("SeEnableDelegationPrivilege")

SE_IMPERSONATE_NAME
TEXT("SeImpersonatePrivilege")

SE_INC_BASE_PRIORITY_NAME
TEXT("SeIncreaseBasePriorityPrivilege")

SE_INCREASE_QUOTA_NAME
TEXT("SeIncreaseQuotaPrivilege")

SE_INC_WORKING_SET_NAME
TEXT("SeIncreaseWorkingSetPrivilege")

SE_LOAD_DRIVER_NAME
TEXT("SeLoadDriverPrivilege")

SE_LOCK_MEMORY_NAME
TEXT("SeLockMemoryPrivilege")

SE_MACHINE_ACCOUNT_NAME
TEXT("SeMachineAccountPrivilege")

SE_MANAGE_VOLUME_NAME
TEXT("SeManageVolumePrivilege")

SE_PROF_SINGLE_PROCESS_NAME
TEXT("SeProfileSingleProcessPrivilege")

SE_RELABEL_NAME
TEXT("SeRelabelPrivilege")

SE_REMOTE_SHUTDOWN_NAME
TEXT("SeRemoteShutdownPrivilege")

SE_RESTORE_NAME
TEXT("SeRestorePrivilege")

SE_SECURITY_NAME
TEXT("SeSecurityPrivilege")

SE_SHUTDOWN_NAME
TEXT("SeShutdownPrivilege")

SE_SYNC_AGENT_NAME
TEXT("SeSyncAgentPrivilege")

SE_SYSTEM_ENVIRONMENT_NAME
TEXT("SeSystemEnvironmentPrivilege")

SE_SYSTEM_PROFILE_NAME
TEXT("SeSystemProfilePrivilege")

SE_SYSTEMTIME_NAME
TEXT("SeSystemtimePrivilege")

SE_TAKE_OWNERSHIP_NAME
TEXT("SeTakeOwnershipPrivilege")

SE_TCB_NAME
TEXT("SeTcbPrivilege")

SE_TIME_ZONE_NAME
TEXT("SeTimeZonePrivilege")

SE_TRUSTED_CREDMAN_ACCESS_NAME
TEXT("SeTrustedCredManAccessPrivilege")

SE_UNDOCK_NAME
TEXT("SeUndockPrivilege")

SE_UNSOLICITED_INPUT_NAME
TEXT("SeUnsolicitedInputPrivilege")


SE_ASSIGNPRIMARYTOKEN_NAME
SE_AUDIT_NAME
SE_BACKUP_NAME
SE_CHANGE_NOTIFY_NAME
SE_CREATE_GLOBAL_NAME
SE_CREATE_PAGEFILE_NAME
SE_CREATE_PERMANENT_NAME
SE_CREATE_SYMBOLIC_LINK_NAME
SE_CREATE_TOKEN_NAME
SE_DEBUG_NAME
SE_ENABLE_DELEGATION_NAME
SE_IMPERSONATE_NAME
SE_INC_BASE_PRIORITY_NAME
SE_INCREASE_QUOTA_NAME
SE_INC_WORKING_SET_NAME
SE_LOAD_DRIVER_NAME
SE_LOCK_MEMORY_NAME
SE_MACHINE_ACCOUNT_NAME
SE_MANAGE_VOLUME_NAME
SE_PROF_SINGLE_PROCESS_NAME
SE_RELABEL_NAME
SE_REMOTE_SHUTDOWN_NAME
SE_RESTORE_NAME
SE_SECURITY_NAME
SE_SHUTDOWN_NAME
SE_SYNC_AGENT_NAME
SE_SYSTEM_ENVIRONMENT_NAME
SE_SYSTEM_PROFILE_NAME
SE_SYSTEMTIME_NAME
SE_TAKE_OWNERSHIP_NAME
SE_TCB_NAME
SE_TIME_ZONE_NAME
SE_TRUSTED_CREDMAN_ACCESS_NAME
SE_UNDOCK_NAME
SE_UNSOLICITED_INPUT_NAME
*/
/* EXAMPLE OF AdjustTokenPrivilege
void f()
{
HANDLE hToken;
LUID luid;
TOKEN_PRIVILEGES tkp;

OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

tkp.PrivilegeCount = 1;
tkp.Privileges[0].Luid = luid;
tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

CloseHandle(hToken);
}
*/