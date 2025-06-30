# PE vs Dll

### PE

```c
#include<stdio.h>
#include<stdlib.h>
#include<windows.h>
#include<string.h>

int main(void) {
	printf("RT Operator, here I come!\n");
	getchar();
	return 0;
}
// ./simplePE.exe
```

### DLL

```c
#include "pch.h"

#include <Windows.h>
#pragma comment(lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		// Code to run when a thread is created in the process
		break;
	case DLL_THREAD_DETACH:
		// Code to run when a thread exits cleanly
		break;
	case DLL_PROCESS_DETACH:
		// Code to run when the DLL is unloaded from a process
		break;
	}
	return TRUE;
}

extern "C"
__declspec(dllexport) BOOL WINAPI RunME(void) {
	MessageBox(
		NULL,
		L"RT Operator, here I come!",
		L"RTO",
		MB_OK
		);
	return TRUE;
}
// rundll32 simpleDLL.dll,RunME
```
