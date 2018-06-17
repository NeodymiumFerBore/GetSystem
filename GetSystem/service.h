#ifndef DEF_SERVICE_H
#define DEF_SERVICE_H

#include "utils.h"
#include <Windows.h>

DWORD serviceStart(wchar_t * cpName);
DWORD serviceStop(wchar_t * cpName);

DWORD serviceCreate(wchar_t * cpName, wchar_t * cpPath);
DWORD serviceDelete(wchar_t * cpName);

#endif
