#include "stdafx.h"
#include "filedropper.h"

BOOL WINAPI dropFileFromB64(const char * b64Str, const wchar_t * filePath)
{
	// filePath must include file name
	unsigned char * decodedPayload = NULL;
	size_t decodedPayloadLen = 0;
	BOOL bResult = FALSE;

	decodedPayload = base64_decode(b64Str, strlen(b64Str), &decodedPayloadLen);

	if (decodedPayload != NULL)
	{
		bResult = dropFileFromBinary(decodedPayload, filePath);
		free(decodedPayload);
	}

	return bResult;
}

BOOL WINAPI dropFileFromBinary(const unsigned char * blob, const wchar_t * filePath)
{
	// filePath must include file name
	FILE* file = NULL;
	unsigned int i = 0;
	size_t blobLen = 0;
	BOOL bResult = FALSE;

	if (NULL == blob)
		return FALSE;

	blobLen = strlen(blob);

	_wfopen_s(&file, filePath, L"wb+");
	if (file != NULL)
	{
		for (i = 0; i < blobLen; i++)
			fputc(blob[i], file);
		fclose(file);

		bResult = TRUE;
	}

	return bResult;
}
