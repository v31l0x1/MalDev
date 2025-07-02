---
description: completely remove imports from PE
---

# No Imports

### implant.cpp

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helpers.h"

#pragma comment(linker, "/entry:WinMain")


typedef BOOL (WINAPI * CreateProcessA_t)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI * WaitForSingleObject_t)(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);

typedef BOOL (WINAPI * CloseHandle_t)(
  HANDLE hObject
);

//int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

	CreateProcessA_t pCreateProcessA = (CreateProcessA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateProcessA");
	WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "WaitForSingleObject");
	CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");

	if (!pCreateProcessA( NULL,   // No module name
					"c:\\Windows\\System32\\notepad.exe",
					NULL,           // Process handle not inheritable
					NULL,           // Thread handle not inheritable
					FALSE,          // Set handle inheritance to FALSE
					0,              // No creation flags
					NULL,           // Use parent's environment block
					NULL,           // Use parent's starting directory 
					&si,            // Pointer to STARTUPINFO structure
					&pi )           // Pointer to PROCESS_INFORMATION structure
		    ) {
        //printf( "CreateProcess failed (%d).\n", GetLastError() );
        return -1;
	}
	pWaitForSingleObject( pi.hProcess, INFINITE );
    
	// Close process and thread handles. 
    pCloseHandle( pi.hProcess );
    pCloseHandle( pi.hThread );

	return 0;
}
```

### helpers.cpp

```c
#include "PEstructs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helpers.h"

int hlpStrcmp(const char* str1, const char* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(unsigned char*)str1 - *(unsigned char*)str2;
}

int hlpWcscmp(const wchar_t* str1, const wchar_t* str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
	PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (sModuleName == NULL) 
		return (HMODULE) (ProcEnvBlk->ImageBaseAddress);

	PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY * ModuleList = NULL;
	
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *  pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
					   pListEntry != ModuleList;	    	// walk all list entries
					   pListEntry  = pListEntry->Flink)	{
		
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (hlpStrcmp((const char *) pEntry->BaseDllName.Buffer, (const char *) sModuleName) == 0)
			return (HMODULE) pEntry->DllBase;
	}

	// otherwise:
	return NULL;

}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

	char * pBaseAddr = (char *) hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void *pProcAddr = NULL;

	// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD) sProcName & 0xFFFF;	// convert to WORD
		DWORD Base = pExportDirAddr->Base;			// first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
	}
	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
	
			if (hlpStrcmp(sProcName, sTmpFuncName) == 0)	{
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}

	return (FARPROC) pProcAddr;
}
```

### helpers.h

```c
#pragma once

#include <windows.h>
#include <malloc.h>

int hlpStrcmp(const char* str1, const char* str2);
int hlpWcscmp(const wchar_t* str1, const wchar_t* str2);

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName);
FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName);
```

### PEstructs.h

```c
#pragma once

#include <windows.h>

//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
};
//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	//...
};

struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
};
	
//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//...
};
```

### compile.bat

```batch
@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:implant.exe
del *.obj
```
