#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "Syscalls.h"

#define EXTPS_ARG1 0x01
#define EXTPS_ARG2 0x02

BOOL UserFromProc( syscall_t *syscall, HANDLE hProc, char *szUserOut, char *szDomOut )
{
	BOOL bRet = FALSE;
	void *tokenUser[384] =  { 0 };
	char szUser[64] = { 0 }, szDom[256] = { 0 };
	DWORD dwUserLen = 64, dwDomLen = 256, dwTokeLen = 384, dwSidType = 0;
	HANDLE hProcToken = NULL;
	NTSTATUS ntStatus;

	if(!hProc)
		return bRet;
	
	ntStatus = syscall->NtOpenProcessToken(hProc, TOKEN_QUERY, &hProcToken);

	if(!hProcToken)
		return bRet;

	ntStatus = syscall->NtQueryInformationToken(hProcToken, TokenUser, (LPVOID)tokenUser, dwTokeLen, &dwTokeLen);
	if(ntStatus < 0)
	{

		syscall->NtClose(hProcToken);
		return bRet;
	}

	if(!ADVAPI32$LookupAccountSidA(NULL, ((TOKEN_USER *)&tokenUser)->User.Sid, szUser, &dwUserLen, szDom, &dwDomLen, (PSID_NAME_USE)&dwSidType))
	{
		syscall->NtClose(hProcToken);
		return bRet;
	}

	bRet = TRUE;
	syscall->NtClose(hProcToken);

	if(szUserOut)
		_strcpy(szUserOut, szUser);

	if(szDomOut)
		_strcpy(szDomOut, szDom);

	return bRet;
}

void UserFromPID( syscall_t *syscall, ULONGLONG dwProcID, char *szUserOut, char *szDomOut, char *szArchOut )
{
	HANDLE hProc = NULL;
	CLIENT_ID hClientPid = { 0 };
	OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };
	NTSTATUS ntStatus = 0;
	
	InitializeObjectAttributes(&zoa, NULL, NULL, NULL, NULL);

	hClientPid.UniqueProcess = (HANDLE)dwProcID;

	ntStatus = syscall->NtOpenProcess(&hProc, PROCESS_QUERY_LIMITED_INFORMATION, &zoa, &hClientPid);
	if(ntStatus < 0 || !hProc) 
		return;

	UserFromProc(syscall, hProc, szUserOut, szDomOut);

	BOOL bProcArch = FALSE;
	KERNEL32$IsWow64Process(hProc, &bProcArch);

	if(!bProcArch)
		_strcpy(szArchOut, "x64");
	else
		_strcpy(szArchOut, "x86");
	
	syscall->NtClose(hProc);
}

void go( char *args, int len ) 
{
	syscall_t sc; 
    datap parser;
	char *arg_1, *arg_2;
	DWORD dwFlags = 0x00;

	BeaconDataParse(&parser, args, len);
	arg_1 = BeaconDataExtract(&parser, NULL);
	arg_2 = BeaconDataExtract(&parser, NULL);
	for(char *p = arg_1;*p;++p) *p=*p>='A'&&*p<='Z'?*p|0x60:*p;
	for(char *p = arg_2;*p;++p) *p=*p>='A'&&*p<='Z'?*p|0x60:*p;

	if(_strlen(arg_1) > 0)
		dwFlags |= EXTPS_ARG1;

	if(_strlen(arg_2) > 0)
		dwFlags |= EXTPS_ARG2;

	if(dwFlags & EXTPS_ARG2)
		BeaconPrintf(CALLBACK_OUTPUT, "- Searching for %s under user %s", arg_1, arg_2);
	else if(dwFlags & EXTPS_ARG1)
		BeaconPrintf(CALLBACK_OUTPUT, "- Searching for proc/user %s", arg_1);
	else
		BeaconPrintf(CALLBACK_OUTPUT, "- No arguments provided, listing all processes");

    sc.NtOpenProcess				= (NtOpenProcess_t)GetSyscallStub("NtOpenProcess");
	sc.NtOpenProcessToken			= (NtOpenProcessToken_t)GetSyscallStub("NtOpenProcessToken");
	sc.NtQueryInformationToken		= (NtQueryInformationToken_t)GetSyscallStub("NtQueryInformationToken");
	sc.NtClose						= (NtClose_t)GetSyscallStub("NtClose");
	sc.NtQuerySystemInformation		= (NtQuerySystemInformation_t)GetSyscallStub("NtQuerySystemInformation");

	SYSTEM_PROCESSES *pSysProcInf = NULL, *pSysProcHead = NULL;
	DWORD dwSysProcLen = (sizeof(SYSTEM_PROCESSES) * 128);
	LONG ntRet = 0x00;
	BOOL bMore = TRUE;
	char szProcUser[64] = { 0 };
	char szDom[256] = { 0 };
	char szArch[4] 	= { 0 };

	pSysProcInf = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwSysProcLen);
	if(!pSysProcInf)
		return;

	ntRet = sc.NtQuerySystemInformation(5, pSysProcInf, dwSysProcLen, &dwSysProcLen);

	while(ntRet == STATUS_INFO_LENGTH_MISMATCH)
	{
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pSysProcInf);
		pSysProcInf = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwSysProcLen);
		ntRet = sc.NtQuerySystemInformation(5, pSysProcInf, dwSysProcLen, &dwSysProcLen);
	}

	pSysProcHead = pSysProcInf;

	int nCurrSize = 192;
	char *buf = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, nCurrSize);

	if(ntRet == STATUS_SUCCESS)
	{
		_strcat(buf, "PID    PPID   Name                           Arch  Session  User\n");
		_strcat(buf, "----   ----   ----                           ----  -------  ----\n");
		while(bMore)
		{
			if(!pSysProcInf->NextEntryDelta)
				bMore = !bMore;

			_memset(&szProcUser, 0, 64);
			_memset(&szDom, 0, 256);
			_memset(&szArch, 0, 4);

			UserFromPID(&sc, (ULONGLONG)pSysProcInf->ProcessId, szProcUser, szDom, szArch);

			DWORD dwSess = 0;
			KERNEL32$ProcessIdToSessionId(pSysProcInf->ProcessId, &dwSess);

			char buff[512] = { 0 };

			if(_strlen(szProcUser) < 1 || _strlen(szDom) < 1)
				MSVCRT$_snprintf(buff, 512, "%-6d %-6d %-30ws %-5s %-8d\n", (ULONGLONG)pSysProcInf->ProcessId, pSysProcInf->InheritedFromProcessId, (pSysProcInf->ProcessName.Length ? pSysProcInf->ProcessName.Buffer : L"[System Process]"), szArch, dwSess);
			else
				MSVCRT$_snprintf(buff, 512, "%-6d %-6d %-30ws %-5s %-8d %s\\%s\n", (ULONGLONG)pSysProcInf->ProcessId, pSysProcInf->InheritedFromProcessId, (pSysProcInf->ProcessName.Length ? pSysProcInf->ProcessName.Buffer : L"[System Process]"), szArch, dwSess, szDom, szProcUser);

			nCurrSize += _strlen(buff) + 1;
			char *tmp = KERNEL32$HeapReAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buf, nCurrSize);
			buf = tmp;

			char procLower[192] = { 0 };
			MSVCRT$_snprintf(procLower, 192, "%ws", (pSysProcInf->ProcessName.Length ? pSysProcInf->ProcessName.Buffer : L"[System Process]"));

			for(char *p = szProcUser;*p;++p) *p=*p>='A'&&*p<='Z'?*p|0x60:*p;
			for(char *p = procLower;*p;++p) *p=*p>='A'&&*p<='Z'?*p|0x60:*p;

			if(dwFlags & EXTPS_ARG2)
			{
				if(_strstr(procLower, arg_1) && _strstr(szProcUser, arg_2))
					_strcat(buf, buff);
			} else if(dwFlags & EXTPS_ARG1) {
				if(_strstr(szProcUser, arg_1) || _strstr(procLower, arg_1))
					_strcat(buf, buff);
			} else {
				_strcat(buf, buff);
			}

			pSysProcInf = (SYSTEM_PROCESSES *)((ULONGLONG)pSysProcInf + (ULONGLONG)pSysProcInf->NextEntryDelta);
		}
	} 

	BeaconPrintf(CALLBACK_OUTPUT, buf);

	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buf);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pSysProcHead);

}

