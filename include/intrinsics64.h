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
* @file		intrinsics.h
* @section	Define functions that are written in assembly that perform specific opcodes
*/

#ifndef __INTRINSICS_H__
#define __INTRINSICS_H__

#include "ntdatatypes.h"

// __readmsr
extern
UINT64
__stdcall
ASM64_Rdmsr(
	IN const UINT32 dwMsrCode
);

// __writemsr
extern
VOID
__stdcall
ASM64_Wrmsr(
	IN const UINT32 dwMsrCode,
	IN const UINT64 qwValue
);

// __cpuidex
extern
VOID
__stdcall
ASM64_Cpuid(
	IN const UINT32 adwRegs[4],
	IN const UINT32 dwFunction,
	IN const UINT32 dwSubFunction
);

// __readcr0
extern
UINT64
__stdcall
ASM64_ReadCr0(
	VOID
);

// __readcr3
extern
UINT64
__stdcall
ASM64_ReadCr3(
	VOID
);

// __readcr4
extern
UINT64
__stdcall
ASM64_ReadCr4(
	VOID
);

// __readcr8
extern
UINT64
__stdcall
ASM64_ReadCr8(
	VOID
);

// __lgdt
extern
VOID
__stdcall
ASM64_Lgdt(
	IN const PUINT64 pqwValue
);

// __sgdt
extern
VOID
__stdcall
ASM64_Sgdt(
	IN const PUINT64 pqwValue
);

// __lidt
extern
VOID
__stdcall
ASM64_Lidt(
	IN const PUINT64 pqwValue
);

// __sidt
extern
VOID
__stdcall
ASM64_Sidt(
	IN const PUINT64 pqwValue
);

#endif /* __INTRINSICS_H__ */
