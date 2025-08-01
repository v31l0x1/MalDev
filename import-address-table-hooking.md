# Import Address Table Hooking

### compile.bat

```batch
@ECHO OFF

cl.exe /nologo /W0 hookem.cpp /MT /link /DLL /OUT:hookem.dll

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp hookme.cpp /link /OUT:hookme.exe /SUBSYSTEM:CONSOLE
del *.obj *.lib *.exp
```

### hookme.cpp

```c
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>
#pragma comment(lib, "user32.lib")

int main(void) {

	printf("hookme.exe: Starting.\n");

	MessageBoxA(NULL, "First message", "HOOKS", MB_OK);
	MessageBoxA(NULL, "Second message", "HOOKS", MB_OK);
	MessageBoxA(NULL, "Third message", "HOOKS", MB_OK);

	printf("hookme.exe: Reger and out!\n");

	return 0;
}
```

### hookem.cpp

```c
#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "user32.lib")
#pragma comment (lib, "dbghelp.lib")

// pointer to original MessageBox
int (WINAPI * pOrigMessageBox)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBox;


// Hooking function
int HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	
	printf("HookedMessageBox() called. No popup on screen!\n");

	pOrigMessageBox(hWnd, "You loose!", "TROLOLOLO", uType);
	return IDOK;
}


// Set hook on origFunc()
BOOL Hookem(char * dll, char * origFunc, PROC hookingFunc) {

    ULONG size;
	DWORD i;
	BOOL found = FALSE;

	// get a HANDLE to a main module == BaseImage
	HANDLE baseAddress = GetModuleHandle(NULL);			
	
	// get Import Table of main module
	PIMAGE_IMPORT_DESCRIPTOR importTbl = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToDataEx(
												baseAddress,
												TRUE,
												IMAGE_DIRECTORY_ENTRY_IMPORT,
												&size,
												NULL);

	// find imports for target dll 
	for (i = 0; i < size ; i++){
		char * importName = (char *)((PBYTE) baseAddress + importTbl[i].Name);
		if (_stricmp(importName, dll) == 0) {
				found = TRUE;
				break;
		}
	}
	if (!found)
		return FALSE;

	// Optimization: get original address of function to hook 
	// and use it as a reference when searching through IAT directly
	PROC origFuncAddr = (PROC) GetProcAddress(GetModuleHandle(dll), origFunc);

	// Search IAT
	PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA) ((PBYTE) baseAddress + importTbl[i].FirstThunk);
	while (thunk->u1.Function) {
		PROC * currentFuncAddr = (PROC *) &thunk->u1.Function;
		
		// found
		if (*currentFuncAddr == origFuncAddr) {

			// make sure memory is writable
			DWORD oldProtect = 0;
			VirtualProtect((LPVOID) currentFuncAddr, 4096, PAGE_READWRITE, &oldProtect);

			// set the hook
			*currentFuncAddr = (PROC)hookingFunc;

			// revert protection setting back
			VirtualProtect((LPVOID) currentFuncAddr, 4096, oldProtect, &oldProtect);

			printf("IAT function %s() hooked!\n", origFunc);
			return TRUE;
		}
	thunk++;
	}
	
	return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem("user32.dll", "MessageBoxA", (PROC) HookedMessageBox);
			break;
			
		case DLL_THREAD_ATTACH:
			break;
			
		case DLL_THREAD_DETACH:
			break;
			
		case DLL_PROCESS_DETACH:
			break;
	}
	
    return TRUE;
}


```
