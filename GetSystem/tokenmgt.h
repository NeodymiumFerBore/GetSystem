#ifndef DEF_GETTOKEN_H
#define DEF_GETTOKEN_H

// Process to elevate:
//                      create a named pipe, start listen
//                      create a service and launch it ( it gets a SYSTEM token )
//                      make the service connect to the named pipe
//                      impersonate the service token
//						duplicate the token 
//                      kill and destroy the service
//                      close the pipe
//                      use the token :)

/*
* getSystemToken():
*		[1] create a listening named pipe
*		[2] create a new thread which creates and launches a service that connects to the pipe
*		[3] impersonate the received token
*		[4] duplicate the token
*		[5] close and destroy all which has been created
*		[6] return the token
*/

#include "service.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <sddl.h>

typedef struct Token Token;
struct Token
{
	DWORD uniqueID;

	HANDLE hImpersonationToken;
	HANDLE hPrimaryToken;

	wchar_t * logonSid;
	wchar_t * sidStr;

	wchar_t * username;
	DWORD usernameLen;

	wchar_t * domainName;
	DWORD domainNameLen;

	wchar_t * systemName;
	DWORD systemNameLen;
};

// Prints all info about a token
void WINAPI printTokenInformations(Token * token);
// Set all the Token members according to the "primary" HANDLE
BOOL WINAPI feedTokenInformations(Token * token);
// Get a LPTSTR of the SID from a token handler
static BOOL WINAPI getTokenLogonSid(HANDLE hToken, LPTSTR * logonSid);
// Free memory allocated to the Token members
void WINAPI freeToken(Token * t);

typedef struct TokenCollection TokenCollection;
struct TokenCollection
{
	Token * tokens;		// Table containing all our tokens
	DWORD dwNbTokens;	// = tokens.length();
	DWORD dwCurrToken;	// The ID of the current token being used
};

BOOL WINAPI initTokenCollection(TokenCollection * tc);

BOOL WINAPI addToken(TokenCollection * tc, Token t);
Token * WINAPI getTokenById(TokenCollection * tc, DWORD id);
Token * WINAPI getCurrentToken(TokenCollection * tc);

// Free any memory allocated in TokenCollection and its tokens
void WINAPI freeTokenCollection(TokenCollection * tc);

#endif
