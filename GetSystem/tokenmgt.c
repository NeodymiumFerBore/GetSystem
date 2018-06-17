#include "stdafx.h"
#include "tokenmgt.h"

void WINAPI printTokenInformations(Token * token)
{
	wprintf(L"ID\t\t%d\n", token->uniqueID);
	wprintf(L"Username\t%ls\\%ls\n", token->domainName, token->username);
	wprintf(L"Computer\t%ls\n", token->systemName);
	wprintf(L"SID\t\t%ls\n", token->sidStr);
	wprintf(L"Logon SID\t%ls\n", token->logonSid);
}

void WINAPI freeToken(Token * t)
{
	// Close handles
	if (NULL != t->hImpersonationToken)
		CloseHandle(t->hImpersonationToken);

	if (NULL != t->hPrimaryToken)
		CloseHandle(t->hPrimaryToken);

	// Free any allocated buffer
	////////////////////////////////////// the 2 next conditions are to watch closely for segfaults
	if (NULL != t->logonSid) {
		free(t->logonSid);
		t->logonSid = NULL; // Failsafe
	}

	if (NULL != t->sidStr) {
		free(t->sidStr);
		t->sidStr = NULL; // Failsafe
	}
	/////////////////////////////////////
	if (NULL != t->username) {
		free(t->username);
		t->username = NULL; // Failsafe
	}
	if (NULL != t->domainName) {
		free(t->domainName);
		t->domainName = NULL; // Failsafe
	}
	if (NULL != t->systemName) {
		free(t->systemName);
		t->systemName = NULL; // Failsafe
	}

	t->usernameLen = 0;
	t->domainNameLen = 0;
	t->systemNameLen = 0;
}

void WINAPI freeTokenCollection(TokenCollection * tc)
{
	DWORD i = 0;

	if (NULL == tc)
		return;

	// Free all tokens
	for (i = 0; i < tc->dwNbTokens; i++)
		freeToken(&tc->tokens[i]);

	tc->dwNbTokens = 0;
	tc->dwCurrToken = 0;

	free(tc->tokens);
}

Token * WINAPI getCurrentToken(TokenCollection * tc)
{
	return getTokenById(tc, tc->dwCurrToken);
}

Token * WINAPI getTokenById(TokenCollection * tc, DWORD id)
{
	DWORD i = 0;
	for (i = 0; i < tc->dwNbTokens; i++)
	{
		if (tc->tokens[i].uniqueID == id)
			return &tc->tokens[i];
	}
	return NULL; // If no token is found, return null
}

BOOL WINAPI feedTokenInformations(Token * token)
{
	//PTOKEN_OWNER to = NULL; // OWNER
	PTOKEN_USER to = NULL; // USER
	DWORD dummyLen = 0;
	SID_NAME_USE snu;

	// If token is NULL, we stop
	if (NULL == token) {
		WPRINTD_ERROR(L"feedTokenInformations - NULL pointer is forbidden - FAIL\n", 0);
		return FALSE;
	}
	// If both token's HANDLE are NULL, we leave
	if (NULL == token->hPrimaryToken && NULL == token->hImpersonationToken) {
		WPRINTD_ERROR(L"feedTokenInformations - No valid HANDLE - FAIL\n", 0);
		return FALSE;
	}

	// If the token only has a primary HANDLE, duplicate it to an impersonation token
	if (NULL == token->hImpersonationToken)
	{
		WPRINTD_INFO(L"Provided token is a primary token. Creating an impersonation token from it\n");
		if (!DuplicateTokenEx(token->hPrimaryToken, TOKEN_ALL_ACCESS, NULL,
			SecurityDelegation, TokenImpersonation, &token->hImpersonationToken))
			WPRINTD_ERROR(L"Duplicate token - FAIL\n", GetLastError());
		else
			WPRINTD_SUCCESS(L"Duplicate token - SUCCESS\n");
	}

	// If the token only has an impersonation HANDLE, duplicate it to a primary token
	if (NULL == token->hPrimaryToken)
	{
		WPRINTD_INFO(L"Provided token is an impersonation token. Creating a primary token from it\n");
		if (!DuplicateTokenEx(token->hImpersonationToken, TOKEN_ALL_ACCESS, NULL,
			SecurityDelegation, TokenPrimary, &token->hPrimaryToken))
		{
			WPRINTD_ERROR(L"Duplicate token - FAIL\n", GetLastError());

			// We CANNOT continue without a primary token
			return FALSE;
		}
		else
			WPRINTD_SUCCESS(L"Duplicate token - SUCCESS\n");
	}

	// Get the logon SID
	if (!getTokenLogonSid(token->hPrimaryToken, &token->logonSid)) {
		WPRINTD_WARNING(L"Get token logon SID - FAIL\n");
		// Do not return FALSE, as a SYSTEM token does NOT have a logon SID!!!
		//return FALSE;
	}
	else
		WPRINTD_SUCCESS(L"Get token logon SID - SUCCESS\n");

	///////// Get the owner SID ///////////
	//if (!GetTokenInformation(token->hPrimaryToken, TokenOwner, NULL, 0, &dummyLen)) // OWNER
	if (!GetTokenInformation(token->hPrimaryToken, TokenUser, NULL, 0, &dummyLen)) // USER
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			WPRINTD_ERROR(L"GetTokenInformation - FAIL", GetLastError());
			return FALSE;
		}
	}
	//to = (PTOKEN_OWNER) LocalAlloc(LPTR, dummyLen); // Our SID // OWNER
	to = (PTOKEN_USER)LocalAlloc(LPTR, dummyLen); // USER
	if (!to)
	{
		WPRINTD_ERROR(L"LocalAlloc - FAIL", GetLastError());
		return FALSE;
	}

	//if (!GetTokenInformation(token->hPrimaryToken, TokenOwner, to, dummyLen, &dummyLen)) // OWNER
	if (!GetTokenInformation(token->hPrimaryToken, TokenUser, to, dummyLen, &dummyLen)) // USER
	{
		WPRINTD_ERROR(L"GetTokenInformation - FAIL", GetLastError());

		LocalFree(to);
		return FALSE;
	}

	// Get username and domain name from the SID "to"

	// First call will fail, but will also give us the necessary buffer sizes
	if (!LookupAccountSidW
	(
		//NULL, to->Owner, // OWNER
		NULL, to->User.Sid, // USER
		token->username, &token->usernameLen,
		token->domainName, &token->domainNameLen,
		&snu
	))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			WPRINTD_ERROR(L"LookupAccountSidW - FAIL", GetLastError());

			LocalFree(to);
			return FALSE;
		}
	}
	// Allocate token->{username,domainName} with the corresponding length returned by previous call
	token->username = /*(wchar_t *)*/malloc(sizeof(wchar_t) * token->usernameLen);
	token->domainName = /*(wchar_t *)*/malloc(sizeof(wchar_t) * token->domainNameLen);

	if (!LookupAccountSidW
	(
		//NULL, to->Owner, // OWNER
		NULL, to->User.Sid,
		token->username, &token->usernameLen,
		token->domainName, &token->domainNameLen,
		&snu
	))
	{
		WPRINTD_ERROR(L"LookupAccountSidW - FAIL", GetLastError());

		free(token->username);
		free(token->domainName);
		LocalFree(to);
		return FALSE;
	}

	//if (!ConvertSidToStringSidW(to->Owner, &token->sidStr)) // OWNER
	if (!ConvertSidToStringSidW(to->User.Sid, &token->sidStr)) // USER
		WPRINTD_ERROR(L"Convert SID to string - FAIL\n", GetLastError());
	else
		WPRINTD_SUCCESS(L"Convert SID to string - SUCCESS\n");

	LocalFree(to);

	// get the computer name @TODO

	return TRUE;
}

//static BOOL WINAPI getTokenLogonSid(HANDLE hToken, PSID* ppSid)
static BOOL WINAPI getTokenLogonSid(HANDLE hToken, LPTSTR * logonSid)
{
	DWORD dwLength = 0;
	PTOKEN_GROUPS pGroups = NULL;
	PSID pSid = NULL;
	PSID * ppSid = &pSid;

	if (NULL == hToken || NULL == logonSid)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		WPRINTD_ERROR(L"getTokenLogonSid - invalid argument - FAIL\n", GetLastError());
		return FALSE;
	}
	GetTokenInformation(hToken, TokenLogonSid, NULL, 0, &dwLength);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		WPRINTD_ERROR(L"getTokenLogonSid()::GetTokenInformation()1 - FAIL\n", GetLastError());
		return FALSE;
	}
	pGroups = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!pGroups)
	{
		WPRINTD_ERROR(L"getTokenLogonSid()::HeapAlloc() - FAIL\n", GetLastError());
		return FALSE;
	}
	if (!GetTokenInformation(hToken, TokenLogonSid, pGroups, dwLength, &dwLength))
	{
		HeapFree(GetProcessHeap(), 0, pGroups);
		WPRINTD_ERROR(L"getTokenLogonSid()::GetTokenInformation()2 - FAIL\n", GetLastError());
		return FALSE;
	}
	RtlMoveMemory(pGroups, pGroups->Groups[0].Sid, GetLengthSid(pGroups->Groups[0].Sid));
	*ppSid = pGroups;

	if (!ConvertSidToStringSidW(pSid, logonSid)) {
		WPRINTD_ERROR(L"Convert Logon SID to string - FAIL\n", GetLastError());
		*logonSid = L"";
	}
	else
		WPRINTD_SUCCESS(L"Convert logon SID to string - SUCCESS\n");

	if (pSid != NULL)
		FreeSid(pSid);

	return TRUE;
}

BOOL WINAPI addToken(TokenCollection * tc, Token newToken)
{
	DWORD newSize = 0; // new number of tokens in the array
	DWORD newID = 0;
	DWORD i = 0;

	// If tc->tokens is NULL, then it is the first token added. Malloc instead of realloc
	if (NULL == tc->tokens)
		tc->tokens = malloc(sizeof(Token));

	else // Try reallocate memory
	{
		newSize = tc->dwNbTokens + 1;
		Token * tmp = realloc(tc->tokens, sizeof(Token) * newSize);
		if (NULL == tmp) // Reallocation failed
		{
			WPRINTD_ERROR(L"addToken - memory reallocation - FAIL\n", 0);
			return FALSE;
		}
		else // Reallocation succeeded
			tc->tokens = tmp;
	}
	tc->dwNbTokens++; // Add 1 to the token counter

					  // Now add newToken to tc->token[dwNbToken-1]
	tc->tokens[tc->dwNbTokens - 1] = newToken;

	// Find the greatest unique ID, and set the new one to this value +1
	for (i = 0; i < tc->dwNbTokens; i++)
	{
		if (tc->tokens[i].uniqueID > newID)
			newID = tc->tokens[i].uniqueID;
	}
	tc->tokens[tc->dwNbTokens - 1].uniqueID = newID + 1;

	// If there is only one token in the collection, set its ID as the current token
	if (tc->dwNbTokens == 1)
		tc->dwCurrToken = tc->tokens[tc->dwNbTokens - 1].uniqueID;

	return TRUE;
}

BOOL WINAPI initTokenCollection(TokenCollection * tc)
{
	BOOL bResult = FALSE;
	Token newToken = { 0 };

	tc->tokens = NULL;
	tc->dwNbTokens = 0;
	tc->dwCurrToken = 0;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &newToken.hPrimaryToken))
	{
		WPRINTD_ERROR(L"addCurrentPrimToken()::OpenProcessToken() - FAIL\n"
			L"\tCould not open current primary token\n", GetLastError());
	}
	else
	{
		if (!DuplicateTokenEx(newToken.hPrimaryToken, TOKEN_ALL_ACCESS, NULL,
			SecurityDelegation, TokenPrimary, &newToken.hPrimaryToken))
			WPRINTD_ERROR(L"Duplicate token - FAIL\n", GetLastError());
		else
			WPRINTD_SUCCESS(L"Duplicate token - SUCCESS\n");

		if (!feedTokenInformations(&newToken))
			WPRINTD_WARNING(L"addCurrentPrimToken()::feedTokenInformations() - FAIL\n");
		else
			WPRINTD_SUCCESS(L"Retrieving informations from token - SUCCESS\n");

		bResult = addToken(tc, newToken);
	}
	return bResult;
}
