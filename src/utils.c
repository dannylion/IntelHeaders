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
	char * pcSrc = NULL;
	char * pcDst = NULL;
	PUINT64 pqwSrc = (PUINT64)pvSrc;
	PUINT64 pqwDst = (PUINT64)pvDst;
	UINT64 i;

	if (	(NULL == pvDst)
		||	(NULL == pvSrc)
		||	(0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	// Copy bytes in UINT64 increments to make things a bit faster
	for (i = cbSize / sizeof(UINT64); 0 < i; i--)
	{
		*pqwDst = *pqwSrc;
		pqwDst++;
		pqwSrc++;
	}

	// Copy the remaining bytes as regular chars
	pcSrc = (char *)pqwSrc;
	pcDst = (char *)pqwDst;
	for (i = cbSize % sizeof(UINT64); 0 < i; i--)
	{
		pcDst[i - 1] = pcSrc[i - 1];
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
	char cValue = (char)iValue;
	char * pcDst = NULL;
	PUINT64 pqwDst = (PUINT64)pvDst;
	UINT64 qwValue = 0;
	PUINT64 pqwValue = &qwValue;
	UINT64 i = cbSize / sizeof(UINT64);

	if (	(NULL == pvDst)
		||	(0 == cbSize))
	{
		// Invalid parameters
		return NULL;
	}

	// Build a UINT64 with all bytes set to cChar
	for (i = 0; i < sizeof(UINT64); i++)
	{
		*pqwValue = cValue;
	}

	// Set bytes in UINT64 increments to make things a bit faster
	for (i = cbSize / sizeof(UINT64); 0 < i; i--)
	{
		*pqwDst = qwValue;
		pqwDst++;
	}

	// Set the remaining bytes as regular chars
	pcDst = (char *)pqwDst;
	for (i = cbSize % sizeof(UINT64); 0 < i; i--)
	{
		pcDst[i - 1] = cValue;
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
