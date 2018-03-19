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
* @file		utils.h
* @section	Basic utility functions that have nothing to do with any Intel mechanisms
*/

#ifndef __INTEL_UTILS_H__
#define __INTEL_UTILS_H__

#include "ntdatatypes.h"

// HACK: Define intrinsic functions that visual studio might add implicitly
// to our code. These functions normally reside in standard libraries, 
// such as LIBC, but since we removed all standard libraries from our code, 
// these intrinsic functions, will cause: "LNK2001 unresolved external symbol"
// Unless we define them ourselves with "pragma function"...
void*
__cdecl
memcpy(
	void* pvDst,
	void const* pvSrc,
	size_t cbSize
);

void *
__cdecl
memset(
	void*  pvDst,
	int    cValue,
	size_t cbSize
);

/**
* Copy an amount of bytes from the source buffer to the destination buffer
* @param pvDst - destination buffer
* @param pvSrc - source buffer
* @param cbSize - amount of bytes to copy
* @return TRUE on success, else FALSE
*/
BOOLEAN
MemCopy(
	OUT PVOID pvDst,
	IN const PVOID pvSrc,
	IN const UINT64 cbSize
);

/**
* Set an amount of bytes in the destination buffer to given character
* @param pvDst - destination buffer
* @param cChar - character to write
* @param cbSize - amount of bytes to set
* @return TRUE on success, else FALSE
*/
BOOLEAN
MemFill(
	OUT PVOID pvDst,
	IN const char cChar,
	IN const UINT64 cbSize
);

/**
* Zero an amount of bytes in the destination buffer
* @param pvDst - destination buffer
* @param cbSize - amount of bytes to set
* @return TRUE on success, else FALSE
*/
BOOLEAN
MemZero(
	OUT PVOID pvDst,
	IN const UINT64 cbSize
);

/**
* Check if the buffers are equal
* @param pvBuffer1 - first buffer
* @param pvBuffer2 - second buffer
* @param cbSize - amount of bytes
* @return TRUE the buffers are equal, else FALSE
*/
BOOLEAN
MemEqual(
	IN const PVOID pvBuffer1,
	IN const PVOID pvBuffer2,
	IN const UINT64 cbSize
);

#endif /* __INTEL_UTILS_H__ */
