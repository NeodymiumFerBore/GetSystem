#include "stdafx.h"
#include "utils.h"

static HANDLE hMutex;

void WINAPI initConsole()
{
	hMutex = CreateMutex(NULL, FALSE, NULL);
}

void WINAPI cleanupConsole()
{
	if (hMutex)
		CloseHandle(hMutex);
}

void wPrintDebugMessage(wchar_t msg[], dbgMessageType messageType, DWORD lastError)
{
#ifdef PRINT_DEBUG_MESSAGES
	WaitForSingleObject(hMutex, INFINITE);

	HANDLE						hConsole = NULL;
	WORD						originalConsoleAttr = 0;
	CONSOLE_SCREEN_BUFFER_INFO	csbi = { 0 };

	BOOL changeColor = FALSE;

	// Retrieve and save current attributes
	// If we fail, don't change attributes and write anything with default colors
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (GetConsoleScreenBufferInfo(hConsole, &csbi))
	{
		originalConsoleAttr = csbi.wAttributes;
		changeColor = TRUE;
	}

	// Change color attributes according to the message type

	switch (messageType)
	{
	case _ERROR_: // Red
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		wprintf(L"[-]\t");
		break;
	case _WARNING_: // Yellow
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
		wprintf(L"[!]\t");
		break;
	case _SUCCESS_: // Green
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		wprintf(L"[+]\t");
		break;
	case _INFO_: // Default
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		wprintf(L"[*]\t");
		break;
	default:
		break;
	}
	wprintf(msg);

	// If the message is an error and lastError != 0, print it
	if (messageType == _ERROR_ && lastError != 0)
		wprintf(L"[-]\tGetLastError: %d - %#010x\n", lastError, lastError);

	// If text color has been changed, revert it to original
	if (changeColor)
		SetConsoleTextAttribute(hConsole, originalConsoleAttr);

	ReleaseMutex(hMutex);
#endif
}

void aPrintDebugMessage(char msg[], dbgMessageType messageType, DWORD lastError)
{
#ifdef PRINT_DEBUG_MESSAGES
	WaitForSingleObject(hMutex, INFINITE);

	HANDLE						hConsole;
	WORD						originalConsoleAttr;
	CONSOLE_SCREEN_BUFFER_INFO	csbi;

	BOOL changeColor = FALSE;

	// Retrieve and save current attributes
	// If we fail, don't change attributes and write anything with default colors
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	if (GetConsoleScreenBufferInfo(hConsole, &csbi))
	{
		originalConsoleAttr = csbi.wAttributes;
		changeColor = TRUE;
	}

	// Change color attributes according to the message type

	switch (messageType)
	{
	case _ERROR_: // Red
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		printf("[-]\t");
		break;
	case _WARNING_: // Yellow
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
		printf("[!]\t");
		break;
	case _SUCCESS_: // Green
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		printf("[+]\t");
		break;
	case _INFO_: // Blue
		if (changeColor)
			SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
		printf("[*]\t");
		break;
	default:
		break;
	}
	printf(msg);

	// If the message is an error and lastError != 0, print it
	if (messageType == _ERROR_ && lastError != 0)
		printf("[-]\tGetLastError: %d - %#010x\n", lastError, lastError);

	// If text color has been changed, revert it to original
	if (changeColor)
		SetConsoleTextAttribute(hConsole, originalConsoleAttr);

	ReleaseMutex(hMutex);
#endif
}

int scanStr(char * str, int len)
{
	char *posEnter = NULL;

	if (fgets(str, len, stdin) != NULL)
	{
		posEnter = strchr(str, '\n');
		if (posEnter != NULL)
			*posEnter = '\0';

		return 1;
	}
	else
		return 0;
}
///////////
int wScanStr(wchar_t * str, int len)
{
	wchar_t *posEnter = NULL;

	if (fgetws(str, len, stdin) != NULL)
	{
		posEnter = wcschr(str, '\x0A');
		if (posEnter != NULL)
			*posEnter = '\x00';

		return 1;
	}
	else
		return 0;
}
///////////
long scanLong()
{
	char chaine[100] = { 0 };

	if (scanStr(chaine, 100))
		return strtol(chaine, NULL, 10);
	else
		return 0;
}
///////////
double scanDouble()
{
	char chaine[100] = { 0 };
	char* virgule = NULL;

	if (scanStr(chaine, 100))
	{
		virgule = strchr(chaine, ',');
		if (virgule != NULL)
			*virgule = '.';
		return strtod(chaine, NULL);
	}
	else
		return 0;
}
///////////
void cleanBuff()
{
	int c = 0;
	while (c != '\n' && c != EOF)
		c = getchar();
}
