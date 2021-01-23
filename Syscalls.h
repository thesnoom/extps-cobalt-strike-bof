#pragma once

#include <windows.h>

// credit: @odzhan 

#define NTDLL_PATH "%SystemRoot%\\system32\\NTDLL.dll"
#define MAX_PATH_LENGTH 1000
#define STATUS_INFO_LENGTH_MISMATCH ((LONG)0xC0000004L)
#define STATUS_SUCCESS 0x00000000
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
  PVOID UniqueProcess;
  PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation,
  SystemProcessorInformation,
  SystemPerformanceInformation,
  SystemTimeOfDayInformation,
  SystemPathInformation,
  SystemProcessInformation,
  SystemCallCountInformation,
  SystemDeviceInformation,
  SystemProcessorPerformanceInformation,
  SystemFlagsInformation,
  SystemCallTimeInformation,
  SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESSES {
  ULONG NextEntryDelta;
  ULONG ThreadCount;
  ULONG Reserved1[6];
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ProcessName;
  LONG BasePriority;
  HANDLE ProcessId;
  HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

// BEACON IMPORT DEFINITIONS
WINBASEAPI DWORD WINAPI KERNEL32$ExpandEnvironmentStringsA (LPCSTR, LPSTR, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingA (HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT WINBASEAPI PVOID WINAPI KERNEL32$MapViewOfFile (HANDLE, DWORD, DWORD, DWORD, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$UnmapViewOfFile (LPCVOID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle (HANDLE);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char *__stream, size_t count, const char *__format, ...);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD dwProcessId, DWORD *pSessionId);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$IsWow64Process(HANDLE hProc, BOOL *bOut);


// DYNAMIC DEFINITIONS
typedef NTSTATUS (NTAPI *NtOpenProcess_t)(
  PHANDLE ProcessHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID ClientId
);
  
typedef NTSTATUS (NTAPI *NtOpenProcessToken_t)(
  HANDLE ProcessHandle,
  ACCESS_MASK DesiredAccess,
  PHANDLE TokenHandle
);

typedef NTSTATUS (NTAPI *NtQueryInformationToken_t)(
  HANDLE TokenHandle,
  TOKEN_INFORMATION_CLASS TokenInformationClass,
  PVOID TokenInformation,
  ULONG TokenInformationLength,
  PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *NtClose_t)(
  HANDLE ObjectHandle
);

typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(
  SYSTEM_INFORMATION_CLASS SystemInformationClass,
  PVOID SystemInformation,
  ULONG SystemInformationLength,
  PULONG ReturnLength
);

typedef struct _syscall_t {
    NtOpenProcess_t           	NtOpenProcess;
	  NtOpenProcessToken_t		    NtOpenProcessToken;
    NtQueryInformationToken_t   NtQueryInformationToken;
    NtClose_t                 	NtClose;
	  NtQuerySystemInformation_t 	NtQuerySystemInformation;
} syscall_t;

char *_strcpy(char* d, const char* s)
{
    if (d == NULL)
        return NULL;

    char *ptr = s;

    while (*s != '\0')
    {
        *d = *s;
        d++;
        s++;
    }

    *d = '\0';

    return ptr;
}

int _strlen(const char *str)
{
	const char *s;

	for (s = str; *s; ++s);

	return (s - str);
}


char *_strcat(char* d, const char* s)
{
    _strcpy(d + _strlen(d), s);
    return d;
}

int _strcmp(const char* s1, const char* s2)
{
    while(*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }
	
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

char *_strstr(char *input, const char *find)
{
    do
    {
        const char *p, *q;
        for (p = input, q = find; *q != '\0' && *p == *q; p++, q++) {}
        if (*q == '\0')
        {
            return input;
        }
    } while (*(input++) != '\0');
    return NULL;
}

void* _memcpy (void *dest, const void *src, size_t len)
{
	char *d = dest;
	const char *s = src;

	while (len--)
		*d++ = *s++;

	return dest;
}

void* _memset(void *b, int c, int len)
{
	int i;
	unsigned char *p = b;
	i = 0;

	while(len > 0)
	{
		*p = c;
		p++;
		len--;
	}

	return(b);
}

ULONG64 rva2ofs(PIMAGE_NT_HEADERS nt, DWORD rva) {
    PIMAGE_SECTION_HEADER sh;
    int                   i;
    
    if(rva == 0) return -1;
    
    sh = (PIMAGE_SECTION_HEADER)((LPBYTE)&nt->OptionalHeader + 
           nt->FileHeader.SizeOfOptionalHeader);
    
    for(i = nt->FileHeader.NumberOfSections - 1; i >= 0; i--) {
      if(sh[i].VirtualAddress <= rva &&
        rva <= (DWORD)sh[i].VirtualAddress + sh[i].SizeOfRawData)
      {
        return sh[i].PointerToRawData + rva - sh[i].VirtualAddress;
      }
    }
    return -1;
}

LPVOID GetProcAddress2(LPBYTE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS       nt;
    PIMAGE_SECTION_HEADER   sh;
    PIMAGE_DATA_DIRECTORY   dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD                   rva, ofs, cnt, nos;
    PCHAR                   str;
    PDWORD                  adr, sym;
    PWORD                   ord;
    
    if(hModule == NULL || lpProcName == NULL) return NULL;
    
    dos = (PIMAGE_DOS_HEADER)hModule;
    nt  = (PIMAGE_NT_HEADERS)(hModule + dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    
    // no exports? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(rva == 0) return NULL;
    
    ofs = rva2ofs(nt, rva);
    if(ofs == -1) return NULL;
    
    // no exported symbols? exit
    exp = (PIMAGE_EXPORT_DIRECTORY)(ofs + hModule);
    cnt = exp->NumberOfNames;
    if(cnt == 0) return NULL;
    
    // read the array containing address of api names
    ofs = rva2ofs(nt, exp->AddressOfNames);        
    if(ofs == -1) return NULL;
    sym = (PDWORD)(ofs + hModule);

    // read the array containing address of api
    ofs = rva2ofs(nt, exp->AddressOfFunctions);        
    if(ofs == -1) return NULL;
    adr = (PDWORD)(ofs + hModule);
    
    // read the array containing list of ordinals
    ofs = rva2ofs(nt, exp->AddressOfNameOrdinals);
    if(ofs == -1) return NULL;
    ord = (PWORD)(ofs + hModule);
    
    // scan symbol array for api string
    do {
      str = (PCHAR)(rva2ofs(nt, sym[cnt - 1]) + hModule);
      // found it?
      if(_strcmp(str, lpProcName) == 0) {
        // return the address
		return (LPVOID)(rva2ofs(nt, adr[ord[cnt - 1]]) + hModule);
		}
    } while (--cnt);
    return NULL;
}

LPVOID GetSyscallStub(LPCSTR lpSyscallName) {
    HANDLE                        file = NULL, map = NULL;
    LPBYTE                        mem = NULL;
    LPVOID                        cs = NULL;
    PIMAGE_DOS_HEADER             dos;
    PIMAGE_NT_HEADERS             nt;
    PIMAGE_DATA_DIRECTORY         dir;
    PIMAGE_RUNTIME_FUNCTION_ENTRY rf;
    ULONG64                       ofs, start=0, end=0, addr;
    SIZE_T                        len;
    DWORD                         i, rva;
    CHAR                          path[MAX_PATH];
    
    KERNEL32$ExpandEnvironmentStringsA(NTDLL_PATH, path, MAX_PATH);
    
    // open file
    file = KERNEL32$CreateFileA((LPCWSTR)path, 
      GENERIC_READ, FILE_SHARE_READ, NULL, 
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(file == INVALID_HANDLE_VALUE) { goto cleanup; }
    
    // create mapping
    map = KERNEL32$CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if(map == NULL) { goto cleanup; }
    
    // create view
    mem = (LPBYTE)KERNEL32$MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if(mem == NULL) { goto cleanup; }
    
    // try resolve address of system call
    addr = (ULONG64)GetProcAddress2(mem, lpSyscallName);
    if(addr == 0) { goto cleanup; }
    
    dos = (PIMAGE_DOS_HEADER)mem;
    nt  = (PIMAGE_NT_HEADERS)((PBYTE)mem + dos->e_lfanew);
    dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;
    
    // no exception directory? exit
    rva = dir[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    if(rva == 0) { goto cleanup; }
    
    ofs = rva2ofs(nt, rva);
    if(ofs == -1) { goto cleanup; }
    
    rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(ofs + mem);

    // for each runtime function (there might be a better way??)
    for(i=0; rf[i].BeginAddress != 0; i++) {
      // is it our system call?
      start = rva2ofs(nt, rf[i].BeginAddress) + (ULONG64)mem;
      if(start == addr) {
        // save the end and calculate length
        end = rva2ofs(nt, rf[i].EndAddress) + (ULONG64)mem;
        len = (SIZE_T) (end - start);

        // allocate RWX memory
        cs = KERNEL32$VirtualAlloc(NULL, len, 
          MEM_COMMIT | MEM_RESERVE,
          PAGE_EXECUTE_READWRITE);
          
        if(cs != NULL) {
          // copy system call code stub to memory
          _memcpy(cs, (const void*)start, len);
        }
        break;
      }
    }
    
cleanup:
    if(mem != NULL) KERNEL32$UnmapViewOfFile(mem);
    if(map != NULL) KERNEL32$CloseHandle(map);
    if(file != NULL) KERNEL32$CloseHandle(file);
    
    // return pointer to code stub or NULL
    return cs;
}