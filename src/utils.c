/**
* MIT License
*
* Copyright (c) 2017 Viral Security Group
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
* @file		utils.c
* @section	Basic utility functions that have nothing to do with any Intel mechanisms
*/

#include "ntdatatypes.h"
#include "utils.h"

// HACK: Define intrinsic functions that visual studio might add implicitly
// to our code. These functions normally reside in standard libraries, 
// such as LIBC, but since we removed all standard libraries from our code, 
// these intrinsic functions, will cause: "LNK2001 unresolved external symbol"
// Unless we define them ourselves with "pragma function"...
#pragma function(memcpy)
void*
__cdecl
memcpy(
	void* pvDst,
	void const* pvSrc,
	size_t cbSize
)
{
	PUINT8 pcSrc = NULL;
	PUINT8 pcDst = NULL;
	PULONG_PTR pulSrc = (PULONG_PTR)pvSrc;
	PULONG_PTR pulDst = (PULONG_PTR)pvDst;
	UINTN i = 0;
	UINTN nIterCount = 0;

	if (	(NULL == pvDst)
		||	(NULL == pvSrc)
		||	(0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	// Copy bytes in ULONG_PTR increments to make things a bit faster
	nIterCount = (cbSize / sizeof(ULONG_PTR));
	for (i = 0; i < nIterCount; i++)
	{
		pulDst[i] = pulSrc[i];
	}

	// Copy the remaining bytes as regular chars
	pcSrc = (PUINT8)((ULONG_PTR)pvSrc + i * sizeof(ULONG_PTR));
	pcDst = (PUINT8)((ULONG_PTR)pvDst + i * sizeof(ULONG_PTR));
	nIterCount = (cbSize % sizeof(ULONG_PTR));
	for (i = 0; i < nIterCount; i++)
	{
		pcDst[i] = pcSrc[i];
	}

	return pvDst;
}

#pragma function(memset)
void *
__cdecl
memset(
	void* pvDst,
	int iValue,
	size_t cbSize
)
{
	UINT8 ucValue = (UINT8)iValue;
	PUINT8 pucDst = NULL;
	PULONG_PTR pqwDst = (PULONG_PTR)pvDst;
	ULONG_PTR qwValue = 0;
	PUINT8 pucValue = (PUINT8)&qwValue;
	ULONG_PTR i = 0;

	if (	(NULL == pvDst)
		||	(0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	// Build a ULONG_PTR with all bytes set to ucValue
	for (i = 0; i < sizeof(qwValue); i++)
	{
		pucValue[i] = ucValue;
	}

	// Set bytes in ULONG_PTR increments to make things a bit faster
	for (i = 0; i < (cbSize / sizeof(ULONG_PTR)); i++)
	{
		pqwDst[i] = qwValue;
	}

	// Set the remaining bytes as regular chars
	pucDst = (PUINT8)((ULONG_PTR)pvDst + i * sizeof(ULONG_PTR));
	for (i = 0; i < (cbSize % sizeof(ULONG_PTR)); i++)
	{
		pucDst[i] = ucValue;
	}

	return pvDst;
}

BOOLEAN
MemCopy(
	OUT PVOID pvDst,
	IN const PVOID pvSrc,
	IN const UINT64 cbSize
)
{
	return (pvDst == memcpy(pvDst, pvSrc, cbSize));
}

BOOLEAN
MemFill(
	OUT PVOID pvDst,
	IN const char cChar,
	IN const UINT64 cbSize
)
{
	return (pvDst == memset(pvDst, cChar, cbSize));
}

BOOLEAN
MemZero(
	OUT PVOID pvDst,
	IN const UINT64 cbSize
)
{
	return (pvDst == memset(pvDst, 0, cbSize));
}

BOOLEAN
MemEqual(
	IN const PVOID pvBuffer1,
	IN const PVOID pvBuffer2,
	IN const UINT64 cbSize
)
{
	BOOLEAN bSuccess = FALSE;
	PULONG_PTR pqwBuffer1 = (PULONG_PTR)pvBuffer1;
	PULONG_PTR pqwBuffer2 = (PULONG_PTR)pvBuffer2;
	PUINT8 pucBuffer1 = NULL;
	PUINT8 pucBuffer2 = NULL;
	ULONG_PTR i = 0;

	if (	(NULL == pvBuffer1)
		||	(NULL == pvBuffer2)
		||	(0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	for (i = 0; i < (cbSize / sizeof(ULONG_PTR)); i++)
	{
		if (pqwBuffer1[i] != pqwBuffer2[i])
		{
			goto lblCleanup;
		}
	}

	// Set the remaining bytes as regular chars
	pucBuffer1 = (PUINT8)((ULONG_PTR)pvBuffer1 + i * sizeof(ULONG_PTR));
	pucBuffer2 = (PUINT8)((ULONG_PTR)pvBuffer2 + i * sizeof(ULONG_PTR));
	for (i = 0; i < (cbSize % sizeof(ULONG_PTR)); i++)
	{
		if (pucBuffer1[i] != pucBuffer2[i])
		{
			goto lblCleanup;
		}
	}

	bSuccess = TRUE;
lblCleanup:
	return bSuccess;
}
