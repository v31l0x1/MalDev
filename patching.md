# Patching

### compile.bat

```batch
@ECHO OFF

cl.exe /nologo /W0 hookem.cpp /MT /link /DLL /OUT:hookem.dll

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp hookme.cpp /link /OUT:hookme.exe /SUBSYSTEM:CONSOLE
del *.obj *.lib *.exp
```

### hookme.cpp

```c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "user32.lib")

int main(void){
    printf("hookme: Starting.\n");

	MessageBoxA(NULL, "First message", "HOOKS", MB_OK);
	MessageBoxA(NULL, "Second message", "HOOKS", MB_OK);
	MessageBoxA(NULL, "Third message", "HOOKS", MB_OK);

    printf("hookme.exe: Roger and out!\n");

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

#define ORIG_BYTES_SIZE 14

BOOL Hookem(FARPROC hookingFunc);
// pointer to original MessageBox
typedef int (WINAPI * OrigMessageBox_t)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
OrigMessageBox_t pOrigMessageBox = NULL;

// storage for original bytes from MessageBox
char OriginalBytes[ORIG_BYTES_SIZE] = { 0 };


// Hooking function
int HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
	SIZE_T bytesOut = 0;
	
	printf("HookedMessageBox() called. No popup on screen!\n");

	//WriteProcessMemory(GetCurrentProcess(), (LPVOID)pOrigMessageBox, OriginalBytes, ORIG_BYTES_SIZE, &bytesOut);
	//pOrigMessageBox(hWnd, lpText, lpCaption, uType);
	//Hookem((FARPROC) HookedMessageBox);
	
	return IDOK;
}


// Set a hook by patching code
BOOL Hookem(FARPROC hookingFunc) {

	SIZE_T bytesIn = 0;
	SIZE_T bytesOut = 0;
	
	// save original address of MessageBoxA
	pOrigMessageBox = (OrigMessageBox_t) GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");

	// copy ORIG_BYTES_SIZE btes of original code from MessageBoxA
	ReadProcessMemory(GetCurrentProcess(), pOrigMessageBox, OriginalBytes, ORIG_BYTES_SIZE, &bytesIn);
	
	// src: https://www.ragestorm.net/blogs/?p=107
	// create a patch <14 bytes> with JMP [RIP+0]; <ADDR64>
	// \xFF\x25\x00\x00\x00\x00
	// \x00\x11\x22\x33\x44\0x55\x66\x77
	char patch[14] = { 0 };
	memcpy(patch, "\xFF\x25", 2);
	memcpy(patch + 6, &hookingFunc, 8);
	
	// patch the MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID) pOrigMessageBox, patch, sizeof(patch), &bytesOut);
	
	printf("IAT MessageBoxA() hooked!\n");
	printf("HookedMessageBox @ %p ; OriginalBytes @ %p\n", HookedMessageBox, OriginalBytes);
	
	return FALSE;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {

    switch (dwReason)  {
		case DLL_PROCESS_ATTACH:
			Hookem((FARPROC) HookedMessageBox);
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
