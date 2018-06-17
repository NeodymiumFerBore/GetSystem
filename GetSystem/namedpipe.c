#include "stdafx.h"
#include "namedpipe.h"

DWORD WINAPI elevatorNamedPipeThread(ElevationSharedData * sharedData)//TokenCollection * tc)
{
	HANDLE pipe = NULL;
	BYTE bMessage[128] = { 0 };
	DWORD dwBytes = 0;
	DWORD dwResult = ERROR_ACCESS_DENIED;

	// Create a new Token
	Token newToken = { 0 };

	// Check if argument is valid
	if (NULL == sharedData)
	{
		SetLastError(ERROR_BAD_ARGUMENTS);
		return ERROR_BAD_ARGUMENTS;
	}
	if (NULL == sharedData->tokens) // The semaphore is not mandatory
	{
		SetLastError(ERROR_BAD_ARGUMENTS);
		return ERROR_BAD_ARGUMENTS;
	}

	//////// Create a security descriptor holding attributes to authorize anyone to write to our pipe ////////

	PSID everyoneSID = NULL;
	SID_IDENTIFIER_AUTHORITY sidAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	SECURITY_ATTRIBUTES sa = { 0 };
	EXPLICIT_ACCESSW ace = { 0 };
	PACL acl = NULL;
	PSECURITY_DESCRIPTOR sd = { 0 };

	if (!AllocateAndInitializeSid(&sidAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &everyoneSID))
	{
		WPRINTD_ERROR(L"Allocate and initialize SID - FAIL\n", GetLastError());
		return EXIT_FAILURE;
	}

	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;

	// Set up ACE
	ace.grfAccessMode = SET_ACCESS;
	ace.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE;
	ace.grfInheritance = NO_INHERITANCE;
	ace.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ace.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ace.Trustee.ptstrName = (LPTSTR)everyoneSID;

	if (ERROR_SUCCESS != SetEntriesInAclW(1, &ace, NULL, &acl))
	{
		WPRINTD_ERROR(L"Set entries in ACL - FAIL\n", GetLastError());
		return EXIT_FAILURE;
	}

	// Create Security descriptor
	sd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION))
	{
		WPRINTD_ERROR(L"Initialize security descriptor - FAIL\n", GetLastError());
		return EXIT_FAILURE;
	}
	if (!SetSecurityDescriptorDacl(sd, TRUE, acl, FALSE))
	{
		WPRINTD_ERROR(L"Set security descriptor DACL - FAIL\n", GetLastError());
		return EXIT_FAILURE;
	}

	// Set security descriptor in security attributes
	sa.lpSecurityDescriptor = sd;

	//////// Security attributes ready to use ////////

	WPRINTD_INFO(L"Creating named pipe...\n");

	// Create pipe
	pipe = CreateNamedPipeW
	(
		L"\\\\.\\pipe\\my_pipe",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		2, 128, 128, 0, &sa//NULL
	);

	if (pipe == NULL || pipe == INVALID_HANDLE_VALUE)
	{
		WPRINTD_ERROR(L"Create named pipe - FAIL\n", GetLastError());
		LocalFree(acl);
		LocalFree(sd);
		return EXIT_FAILURE;
	}

	WPRINTD_SUCCESS(L"Named pipe now running\n");

	while (TRUE)
	{
		WPRINTD_INFO(L"Waiting for a client...\n");
		if (!ConnectNamedPipe(pipe, NULL))
		{
			if (GetLastError() != ERROR_PIPE_CONNECTED)
				continue;
		}
		WPRINTD_SUCCESS(L"Client connected!\n");

		// Release the semaphore in sharedData if it is not null
		if (sharedData->hSemaphore)
		{
			if (!ReleaseSemaphore(sharedData->hSemaphore, 1, NULL)) {
				WPRINTD_ERROR(L"Release semaphore - FAIL\n", GetLastError());
				break;
			}
		}

		// Read data to be able to impersonate the client (blocks until something is written to the pipe)
		if (!ReadFile(pipe, &bMessage, 1, &dwBytes, NULL)) {
			WPRINTD_ERROR(L"Read data from named pipe - FAIL\n", GetLastError());
			continue;
		}

		// Now impersonate the client!
		if (!ImpersonateNamedPipeClient(pipe)) {
			WPRINTD_ERROR(L"Impersonate named pipe client - FAIL\n", GetLastError());
			continue;
		}

		// Get the handle on this thread's token, and store it in our newToken's impersonation token handle
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &newToken.hImpersonationToken)) {
			WPRINTD_ERROR(L"Open thread token - FAIL\n", GetLastError());
			continue;
		}
		else
			WPRINTD_SUCCESS(L"Open thread token - SUCCESS\n");

		// Duplicate our impersonated token to a primary token
		if (!DuplicateTokenEx(newToken.hImpersonationToken, TOKEN_ALL_ACCESS, NULL,
			SecurityDelegation, TokenPrimary, &newToken.hPrimaryToken))
			WPRINTD_ERROR(L"Duplicate token - FAIL\n", GetLastError());
		else
			WPRINTD_SUCCESS(L"Duplicate token - SUCCESS\n");

		// Feed the newToken with all relative informations
		feedTokenInformations(&newToken);

		// Add the newToken to the collection
		//addToken(tc, newToken);
		addToken(sharedData->tokens, newToken);

		WPRINTD_INFO(L"Reached end of createNamedPipe( HANDLE ) main loop...\n");

		dwResult = ERROR_SUCCESS;

		break; // Comment this to make the loop never stop
	}

	if (pipe) {
		DisconnectNamedPipe(pipe);
		CloseHandle(pipe);
	}

	LocalFree(acl);
	LocalFree(sd);

	return dwResult;
}
