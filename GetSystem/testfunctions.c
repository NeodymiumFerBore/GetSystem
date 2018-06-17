#include "stdafx.h"
#include "testFunctions.h"

void runWhoAmI()
{
	ShellExecute(GetCurrentProcess(), L"open", L"cmd.exe", L"/C whoami & pause", 0, SW_SHOW);
	WPRINTD_SUCCESS(L"runWhoAmI() done\n");
}

void triggerUAC()
{
	wchar_t inputBuffer[MAX_PROGNAME_LENGTH] = { 0 };

	WPRINTD_INFO(L"Enter the program to run\n");
	wprintf(L"> ");
	wScanStr(inputBuffer, MAX_PROGNAME_LENGTH);

	if ((int)ShellExecuteW(0, L"runAs", inputBuffer, NULL, NULL, SW_SHOW) < 33)
		WPRINTD_ERROR(L"[testfunctions.c] triggerUAC. ShellExecuteW - FAIL\n", GetLastError());
	else
		WPRINTD_SUCCESS(L"[testfunctions.c] triggerUAC. ShellExecuteW - SUCCESS\n");

	//ShellExecute(0, L"runAs", L"cmd", NULL, NULL, SW_SHOW);			// Triggers UAC
	//ShellExecute(0, L"runAs", L"taskmgr.exe", NULL, NULL, SW_SHOW);	// Does NOT trigger UAC
	//ShellExecuteA(0, "runAs", "C:\\Windows\\sysnative\\sysprep\\sysprep.exe", NULL, NULL, SW_SHOW);
	/*
	// This works, the actual path to sysprep is in an inexisting folder lol
	CreateProcess(TEXT("C:\\Windows\\sysnative\\sysprep\\sysprep.exe"), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	wprintf(L"Last Error: %d\n", GetLastError());
	*/
	//WPRINTD_SUCCESS(L"triggerUAC() done\n");
}

void startTaskmgr()
{
	SHELLEXECUTEINFOA sei = { 0 };

	sei.cbSize = sizeof(sei);
	sei.fMask = 0;
	sei.hwnd = 0;
	sei.lpVerb = "open";
	sei.lpFile = "c:\\windows\\system32\\taskmgr.exe";
	sei.lpDirectory = 0;
	sei.nShow = SW_SHOW;
	sei.hInstApp = 0;
	ShellExecuteExA(&sei);
}
