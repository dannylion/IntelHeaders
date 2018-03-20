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
* @file		cpuid.h
* @section	CPUID structures and functions (https://en.wikipedia.org/wiki/CPUID)
*/

#include "ntdatatypes.h"
#include "utils.h"
#include "intrinsics64.h"
#include "msr64.h"
#include "cpuid.h"

UINT8
CPUID_GetMaxPhyAddrBits(
	VOID
)
{
	CPUID_EX_MAXFUNC tCpuidExMaxFunc;
	CPUID_BASIC_FEATURES tCpuidBasicFeatures;
	CPUID_EX_MAXADDR tCpuidMaxAddrInfo;
	
	ASM64_Cpuid(
		(UINT32 *)&tCpuidExMaxFunc,
		(UINT32)CPUID_FUNCTION_EX_MAXFUNC,
		0);

	// Check if MAXPHYADDR from CPUID is not supported
	if (CPUID_FUNCTION_EX_MAXADDR > tCpuidExMaxFunc.dwMaxExFunc)
	{
		// 4.1.4 Enumeration of Paging Features by CPUID
		// Default MAXPHYADDR with PAE is 36, and without is 32
		ASM64_Cpuid(
			(UINT32 *)&tCpuidBasicFeatures,
			(UINT32)CPUID_FUNCTION_BASIC_FEATURES,
			0);
		return ((tCpuidBasicFeatures.Pae) ? 36 : 32);
	}

	ASM64_Cpuid(
		(UINT32 *)&tCpuidMaxAddrInfo,
		(UINT32)CPUID_FUNCTION_EX_MAXADDR,
		0);
	return (UINT8)tCpuidMaxAddrInfo.MaxPhysAddr;
}

UINT64
CPUID_GetMaxPhyAddr(
	VOID
)
{
	const UINT64 qwMaxPhyAddrBits = CPUID_GetMaxPhyAddrBits();
	UINT64 qwMaxPhyAddr = (1ULL << qwMaxPhyAddrBits) - 1ULL;
	return qwMaxPhyAddr;
}

BOOLEAN
CPUID_CheckOneGbPageSupport(
	VOID
)
{
	CPUID_EX_MAXFUNC tCpuidExMaxFunc;
	CPUID_EX_FEATURES tCpuidExFeatures;

	ASM64_Cpuid(
		(UINT32 *)&tCpuidExMaxFunc,
		(UINT32)CPUID_FUNCTION_EX_MAXFUNC,
		0);

	if (CPUID_FUNCTION_EX_FEATURES > tCpuidExMaxFunc.dwMaxExFunc)
	{
		return FALSE;
	}

	ASM64_Cpuid(
		(UINT32 *)&tCpuidExFeatures,
		(UINT32)CPUID_FUNCTION_EX_FEATURES,
		0);
	return (BOOLEAN)tCpuidExFeatures.OneGbPages;
}
