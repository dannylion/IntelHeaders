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

VOID
MemCopy(
	OUT PVOID pvDst,
	IN const PVOID pvSrc,
	IN const UINT64 cbSize
)
{
	char * pcSrc = NULL;
	char * pcDst = NULL;
	PUINT64 pqwSrc = (PUINT64)pvSrc;
	PUINT64 pqwDst = (PUINT64)pvDst;
	UINT64 i;

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
		pcDst[i-1] = pcSrc[i-1];
	}
}

VOID
MemFill(
	OUT PVOID pvDst,
	IN const char cChar,
	IN const UINT64 cbSize
)
{
	char * pcDst = NULL;
	PUINT64 pqwDst = (PUINT64)pvDst;
	UINT64 qwValue = 0;
	PUINT64 pqwValue = &qwValue;
	UINT64 i = cbSize / sizeof(UINT64);

	// Build a UINT64 with all bytes set to cChar
	for (i = 0; i < sizeof(UINT64); i++)
	{
		*pqwValue = cChar;
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
		pcDst[i-1] = cChar;
	}
}

VOID
MemZero(
	OUT PVOID pvDst,
	IN const UINT64 cbSize
)
{
	char * pcDst = NULL;
	PUINT64 pqwDst = (PUINT64)pvDst;
	UINT64 i = cbSize / sizeof(UINT64);

	// Zero bytes in UINT64 increments to make things a bit faster
	for (i = cbSize / sizeof(UINT64); 0 < i; i--)
	{
		*pqwDst = 0;
		pqwDst++;
	}

	// Zero the remaining bytes as regular chars
	pcDst = (char *)pqwDst;
	for (i = cbSize % sizeof(UINT64); 0 < i; i--)
	{
		pcDst[i-1] = 0;
	}
}
