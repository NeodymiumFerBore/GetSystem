#ifndef DEF_SCANSECLIB_H
#define DEF_SCANSECLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Windows.h>

int scanStr(char * str, int len);
int wScanStr(wchar_t * str, int len);
long scanLong();
double scanDouble();
void cleanBuff();

void WINAPI initConsole();
void WINAPI cleanupConsole();

#define PRINT_DEBUG_MESSAGES
typedef enum { _ERROR_, _WARNING_, _SUCCESS_, _INFO_ } dbgMessageType;

#define WPRINTD_ERROR(wSTR, err)	wPrintDebugMessage(wSTR, _ERROR_, err)
#define WPRINTD_WARNING(wSTR)		wPrintDebugMessage(wSTR, _WARNING_, 0)
#define WPRINTD_SUCCESS(wSTR)		wPrintDebugMessage(wSTR, _SUCCESS_, 0)
#define WPRINTD_INFO(wSTR)			wPrintDebugMessage(wSTR, _INFO_, 0)

#define APRINTD_ERROR(aSTR, err)	aPrintDebugMessage(aSTR, _ERROR_, err)
#define APRINTD_WARNING(aSTR)		aPrintDebugMessage(aSTR, _WARNING_, 0)
#define APRINTD_SUCCESS(aSTR)		aPrintDebugMessage(aSTR, _SUCCESS_, 0)
#define APRINTD_INFO(aSTR)			aPrintDebugMessage(aSTR, _INFO_, 0)

void wPrintDebugMessage(wchar_t msg[], dbgMessageType messageType, DWORD lastError);
void aPrintDebugMessage(char msg[], dbgMessageType messageType, DWORD lastError);

#endif // SCANSECLIB_H_INCLUDED
