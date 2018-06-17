#ifndef DEF_NAMEDPIPE_H
#define DEF_NAMEDPIPE_H

#include "utils.h"
#include "tokenmgt.h"
#include <Windows.h>
#include <AccCtrl.h>
#include <AclAPI.h>

typedef struct ElevationSharedData ElevationSharedData;
struct ElevationSharedData
{
	HANDLE hSemaphore;
	TokenCollection * tokens;
};

DWORD WINAPI elevatorNamedPipeThread(ElevationSharedData * sharedData);//TokenCollection * tc);

#endif
