#ifndef DEF_FILEDROPPER_H
#define DEF_FILEDROPPER_H

#include "base64.h"
#include <string.h>
#include <Windows.h>

BOOL WINAPI dropFileFromB64(const char * b64Str, const wchar_t * filePath);
BOOL WINAPI dropFileFromBinary(const unsigned char * blob, const wchar_t * filePath);

#endif // !DEF_FILEDROPPER_H
