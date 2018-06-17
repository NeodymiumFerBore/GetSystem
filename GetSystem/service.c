#include "stdafx.h"
#include "service.h"

DWORD serviceStart(wchar_t * cpName)
{
	DWORD dwResult = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	WPRINTD_INFO(L"Starting service\n");

	do
	{
		if (!cpName)
		{
			dwResult = ERROR_BAD_ARGUMENTS;
			SetLastError(ERROR_BAD_ARGUMENTS);
			WPRINTD_ERROR(L"serviceStart. Bad argument\n", ERROR_BAD_ARGUMENTS);
			break;
		}

		hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (!hManager)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceStart. Open SC manager - FAIL\n", dwResult);
			break;
		}

		hService = OpenServiceW(hManager, cpName, SERVICE_START);
		if (!hService)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceStart. Open service - FAIL\n", dwResult);
			break;
		}
		if (!StartServiceW(hService, 0, NULL))
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceStart. Start service - FAIL\n", dwResult);
			break;
		}

		WPRINTD_SUCCESS(L"Service started - SUCCESS\n");
	} while (0);

	if (hService)
		CloseServiceHandle(hService);

	if (hManager)
		CloseServiceHandle(hManager);

	SetLastError(dwResult);

	return dwResult;
}

DWORD serviceStop(wchar_t * cpName)
{
	DWORD dwResult = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;
	SERVICE_STATUS_PROCESS status = { 0 };
	DWORD dwBytes = 0;
	DWORD dwStartTime = 0;
	DWORD dwTimeout = 30000; //30 seconds

	WPRINTD_INFO(L"Stopping service\n");

	do
	{
		if (!cpName)
		{
			dwResult = ERROR_BAD_ARGUMENTS;
			SetLastError(ERROR_BAD_ARGUMENTS);
			WPRINTD_ERROR(L"serviceStop. Bad argument\n", ERROR_BAD_ARGUMENTS);
			break;
		}

		hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (!hManager)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceStop. Open SC manager - FAIL\n", dwResult);
			break;
		}

		hService = OpenServiceW(hManager, cpName, SERVICE_START);
		if (!hService)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceStop. Open service - FAIL\n", dwResult);
			break;
		}

		if (!ControlService(hService, SERVICE_CONTROL_STOP, (SERVICE_STATUS *)&status))
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceStop. Stop service - FAIL\n", dwResult);
			break;
		}

		dwStartTime = GetTickCount();

		while (TRUE)
		{
			if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status,
				sizeof(SERVICE_STATUS_PROCESS), &dwBytes))
			{
				dwResult = GetLastError();
				WPRINTD_ERROR(L"serviceStop. Query service status - FAIL\n", dwResult);
				break;
			}

			if (status.dwCurrentState == SERVICE_STOPPED)
				break;

			if ((GetTickCount() - dwStartTime) > dwTimeout)
			{
				dwResult = ERROR_TIMEOUT;
				SetLastError(ERROR_TIMEOUT);
				WPRINTD_ERROR(L"serviceStop. Stop service timeout reached - FAIL\n", dwResult);
				break;
			}

			Sleep(status.dwWaitHint);
		}

	} while (0);

	if (hService)
		CloseServiceHandle(hService);

	if (hManager)
		CloseServiceHandle(hManager);

	SetLastError(dwResult);

	return dwResult;
}

DWORD serviceCreate(wchar_t * cpName, wchar_t * cpPath)
{
	DWORD dwResult = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	WPRINTD_INFO(L"Creating service\n");

	do
	{
		if (!cpName || !cpPath)
		{
			dwResult = ERROR_BAD_ARGUMENTS;
			SetLastError(ERROR_BAD_ARGUMENTS);
			WPRINTD_ERROR(L"serviceCreate. Bad argument\n", ERROR_BAD_ARGUMENTS);
			break;
		}

		hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (!hManager)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceCreate. Open SC manager - FAIL\n", dwResult);
			break;
		}

		hService = CreateServiceW(hManager, cpName, NULL, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
			SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, cpPath, NULL, NULL, NULL, NULL, NULL);
		if (!hService)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceCreate. Create service - FAIL\n", dwResult);
			break;
		}

		WPRINTD_SUCCESS(L"Service created - SUCCESS\n");
	} while (0);

	if (hService)
		CloseServiceHandle(hService);

	if (hManager)
		CloseServiceHandle(hManager);

	SetLastError(dwResult);

	return dwResult;
}

DWORD serviceDelete(wchar_t * cpName)
{
	DWORD dwResult = ERROR_SUCCESS;
	HANDLE hManager = NULL;
	HANDLE hService = NULL;

	WPRINTD_INFO(L"Deleting service\n");

	do
	{
		if (!cpName)
		{
			dwResult = ERROR_BAD_ARGUMENTS;
			SetLastError(ERROR_BAD_ARGUMENTS);
			WPRINTD_ERROR(L"serviceDelete. Bad argument\n", ERROR_BAD_ARGUMENTS);
			break;
		}

		hManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (!hManager)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceDelete. Open SC manager - FAIL\n", dwResult);
			break;
		}

		hService = OpenServiceW(hManager, cpName, DELETE);
		if (!hService)
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceDelete. Open service - FAIL\n", dwResult);
			break;
		}

		if (!DeleteService(hService))
		{
			dwResult = GetLastError();
			WPRINTD_ERROR(L"serviceDelete. Delete service - FAIL\n", dwResult);
			break;
		}

		WPRINTD_SUCCESS(L"Service deleted - SUCCESS\n");
	} while (0);

	if (hService)
		CloseServiceHandle(hService);

	if (hManager)
		CloseServiceHandle(hManager);

	SetLastError(dwResult);

	return dwResult;
}
