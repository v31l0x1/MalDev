# Local Payload Execution

* DLL file containing a function to execute a simple MessageBox.

```c
#include "pch.h"


VOID MsgBoxPayload() {
	MessageBoxA(NULL, "Hello from the DLL!", "DLL Message", MB_OK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
		MsgBoxPayload();
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

* C code to execute the DLL.

```c
#include <stdio.h>
#include <Windows.h>

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("[] Missing Argument; DLL Payload To Run \n");
		return -1;
	}

	printf("[i] Injecting \"%s\" to the local process of Pid: %d \n", argv[1], GetCurrentProcessId());

	printf("[+] Loading DLL...");
	if (LoadLibraryA(argv[1]) == NULL) {
		printf("[!] LoadLibrary failed with error: %d \n", GetLastError());
		return -1;
	}
	printf("[+] Done !\n");
	
	printf("[#] Press <Enter> to Quit...\n");
	getchar();

	return 0;
}
```
