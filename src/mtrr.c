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
* @file		mtrr.c
* @section	11.11 MEMORY TYPE RANGE REGISTERS (MTRRS)
*/

#include "ntdatatypes.h"
#include "utils.h"
#include "intrinsics64.h"
#include "mtrr.h"
#include "cpuid.h"

//! Vol 3A, 11.11.1 MTRR Feature Identification
BOOLEAN
MTRR_IsMtrrSupported(
	VOID
)
{
	CPUID_BASIC_FEATURES tCpuidFeatures;
	ASM64_Cpuid(
		(UINT32 *)&tCpuidFeatures,
		(UINT32)CPUID_FUNCTION_BASIC_FEATURES,
		0);
	return (0 != tCpuidFeatures.Mtrr);
}

//! Vol 3C, 11.11.2.4 System-Management Range Register Interface
BOOLEAN
MTRR_GetSmmRange(
	OUT PUINT64 pqwSmmRangeStart,
	OUT PUINT64 pqwSmmRangeEnd,
	OUT PMTRR_MEMTYPE peSmmMemType
)
{
	BOOLEAN bSuccess = FALSE;
	IA32_MTRRCAP tMtrrCap;
	IA32_SMRR_PHYSBASE tSmrrPhysBase;
	IA32_SMRR_PHYSMASK tSmrrPhysMask;
	UINT64 qwSmrrBase = 0;
	UINT64 qwSmrrMask = 0;
	UINT64 qwRangeStart = 0;
	UINT64 qwRangeEnd = 0;
	const UINT64 qwMaxPhyAddr = MAXPHYADDR;

	tSmrrPhysBase.qwValue = 0;
	tSmrrPhysMask.qwValue = 0;

	if (	(NULL == pqwSmmRangeStart)
		||	(NULL == pqwSmmRangeEnd)
		||	(NULL == peSmmMemType))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	tMtrrCap.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_MTRRCAP);
	if (!tMtrrCap.Smrr)
	{
		// SMRR not supported
		goto lblCleanup;
	}

	tSmrrPhysBase.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_SMRR_PHYSBASE);
	tSmrrPhysMask.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_SMRR_PHYSMASK);

	qwSmrrBase = (((UINT64)tSmrrPhysBase.Base) << 12) & qwMaxPhyAddr;
	qwSmrrMask = (((UINT64)tSmrrPhysMask.Mask) << 12) & qwMaxPhyAddr;

	qwRangeStart = qwSmrrBase;
	qwRangeEnd = qwSmrrBase | qwSmrrMask;
	
	bSuccess = TRUE;

lblCleanup:
	if (bSuccess)
	{
		*pqwSmmRangeStart = qwRangeStart;
		*pqwSmmRangeEnd = qwRangeEnd;
		*peSmmMemType = tSmrrPhysBase.Type;
	}
	return bSuccess;
}

//! Vol 3A, 11.11.2.2 Fixed Range MTRRs
BOOLEAN
mtrr_GetMemTypeFromFixed(
	IN const UINT64 qwPhysicalAddress,
	OUT PMTRR_MEMTYPE peMemType
)
{
	UINT32 dwMtrrMsr = 0;
	UINT32 dwMtrrRangeIndex = 0;
	IA32_MTRR_FIX64K tFix64k;
	IA32_MTRR_FIX16K tFix16k;
	IA32_MTRR_FIX4K tFix4k;

	// Verify physical address is within range of fixed MTRR MSRs
	if (0xFFFFF < qwPhysicalAddress)
	{
		return FALSE;
	}

	if (0x7FFFF >= qwPhysicalAddress)
	{
		dwMtrrMsr = MSR_CODE_IA32_MTRR_FIX64K_00000;
		tFix64k.qwValue = ASM64_Rdmsr(dwMtrrMsr);
		dwMtrrRangeIndex = (UINT32)(qwPhysicalAddress / 0x10000);
		*peMemType = tFix64k.acRanges[dwMtrrRangeIndex];
		return TRUE;
	}

	if (	(0x80000 <= qwPhysicalAddress)
		&&	(0xBFFFF >= qwPhysicalAddress))
	{
		dwMtrrMsr = (
				MSR_CODE_IA32_MTRR_FIX16K_80000
			+	(UINT32)((qwPhysicalAddress - 0x80000) / 0x20000));
		tFix16k.qwValue = ASM64_Rdmsr(dwMtrrMsr);
		dwMtrrRangeIndex = (qwPhysicalAddress % 0x20000) / 0x4000;
		*peMemType = tFix16k.acRanges[dwMtrrRangeIndex];
		return TRUE;
	}
	
	if (	(0xC0000 <= qwPhysicalAddress)
		&&	(0xFFFFF >= qwPhysicalAddress))
	{
		dwMtrrMsr = (
				MSR_CODE_IA32_MTRR_FIX4K_C0000
			+	(UINT32)((qwPhysicalAddress - 0xC0000) / 0x8000));
		tFix4k.qwValue = ASM64_Rdmsr(dwMtrrMsr);
		dwMtrrRangeIndex = (qwPhysicalAddress % 0x8000) / 0x1000;
		*peMemType = tFix4k.acRanges[dwMtrrRangeIndex];
		return TRUE;
	}

	// Should never reach here
	return FALSE;
}

//! Vol 3A, 11.11.2.3 Variable Range MTRRs
BOOLEAN
mtrr_GetMemTypeFromVariable(
	IN const UINT64 qwPhysicalAddress,
	IN const PIA32_MTRRCAP ptMtrrCap,
	OUT PMTRR_MEMTYPE peMemType
)
{
	BOOLEAN bFound = FALSE;
	UINT32 dwCurrentIndex = 0;
	UINT64 qwMtrrBase = 0;
	UINT64 qwMtrrMask = 0;
	UINT64 qwRangeStart = 0;
	UINT64 qwRangeEnd = 0;
	MTRR_MEMTYPE eMemType = MTRR_MEMTYPE_INVALID;
	const UINT64 qwMaxPhysAddr = MAXPHYADDR;
	
	for (; dwCurrentIndex < ptMtrrCap->Vcnt; dwCurrentIndex++)
	{
		
		IA32_MTRR_PHYSBASE tMtrrPhysBase;
		IA32_MTRR_PHYSMASK tMtrrPhysMask;

		tMtrrPhysBase.qwValue = ASM64_Rdmsr(
			MSR_CODE_IA32_MTRR_PHYSBASE0 + (2 * dwCurrentIndex));
		tMtrrPhysMask.qwValue = ASM64_Rdmsr(
			MSR_CODE_IA32_MTRR_PHYSMASK0 + (2 * dwCurrentIndex));

		if (!tMtrrPhysMask.Valid)
		{
			// MTRR is not valid, skip it
			continue;
		}

		qwMtrrBase = (((UINT64)tMtrrPhysBase.Base) << 12) & qwMaxPhysAddr;
		qwMtrrMask = (((UINT64)tMtrrPhysMask.Mask) << 12) & qwMaxPhysAddr;

		qwRangeStart = qwMtrrBase;
		qwRangeEnd = qwMtrrBase | qwMtrrMask;
		if (	(qwRangeStart <= qwPhysicalAddress)
			&&	(qwRangeEnd >= qwPhysicalAddress))
		{
			bFound = TRUE;
			
			// MTRR contains the physical address given; get the memory type.
			// If more than one MTRR range contains the address, the one that
			// prevents caching has precedence
			if (tMtrrPhysBase.Type < eMemType)
			{
				eMemType = tMtrrPhysBase.Type;
			}
		}
	}

	if (bFound)
	{
		*peMemType = eMemType;
	}
	return bFound;
}

//! Vol 3A, 11.11.2.1 IA32_MTRR_DEF_TYPE MSR
BOOLEAN
MTRR_GetMemTypeForPhysicalAddress(
	IN const UINT64 qwPhysicalAddress,
	IN const BOOLEAN bInSmm,
	OUT PMTRR_MEMTYPE peMemType
)
{
	BOOLEAN bSuccess = FALSE;
	MTRR_MEMTYPE eMemType = MTRR_MEMTYPE_INVALID;
	IA32_MTRRCAP tMtrrCap;
	IA32_MTRR_DEF_TYPE tMtrrDefType;
	const UINT64 qwMaxPhyAddr = MAXPHYADDR;
	UINT64 qwSmrrStart = 0;
	UINT64 qwSmrrEnd = 0;
	MTRR_MEMTYPE eSmrrMemType = MTRR_MEMTYPE_INVALID;

	if (	(qwMaxPhyAddr <= qwPhysicalAddress)
		||	(NULL == peMemType))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	tMtrrCap.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_MTRRCAP);
	tMtrrDefType.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_MTRR_DEF_TYPE);

	// Check if physical address is in SMM range
	if (MTRR_GetSmmRange(
		&qwSmrrStart,
		&qwSmrrEnd,
		&eSmrrMemType))
	{
		if (	(qwSmrrStart <= qwPhysicalAddress)
			&&	(qwSmrrEnd >= qwPhysicalAddress))
		{
			// Physical address is in SMM range. If the logical processor is in
			// SMM eSmrrMemType is used, else MTRR_MEMTYPE_UC
			eMemType = bInSmm ? eSmrrMemType : MTRR_MEMTYPE_UC;
			bSuccess = TRUE;
			goto lblCleanup;
		}
	}

	if (!MTRR_IsMtrrSupported())
	{
		// MTRR not supported
		goto lblCleanup;
	}

	if (!tMtrrDefType.E)
	{
		// MTRRs are disabled. Apply the UC memory type for all physical memory
		eMemType = MTRR_MEMTYPE_UC;
		bSuccess = TRUE;
		goto lblCleanup;
	}

	// When the fixed-range MTRRs are enabled, they take priority over the
	// variable-range MTRRs when overlaps in ranges occur. Fixed MTRRs only
	// define the first 1MB of physical memory
	if (	(tMtrrDefType.Fe)
		&&	(0x100000 > qwPhysicalAddress))
	{
		if (mtrr_GetMemTypeFromFixed(
			qwPhysicalAddress,
			&eMemType))
		{
			bSuccess = TRUE;
			goto lblCleanup;
		}
	}

	// Fixed range MTRRs didn't contain the specified address, now we try
	// variable-range MTRRs
	if (mtrr_GetMemTypeFromVariable(
		qwPhysicalAddress,
		&tMtrrCap,
		&eMemType))
	{
		bSuccess = TRUE;
		goto lblCleanup;
	}

	// Physical address is not in any MTRR, use default type
	eMemType = tMtrrDefType.Type;
	bSuccess = TRUE;

lblCleanup:
	if (bSuccess)
	{
		*peMemType = eMemType;
	}
	return bSuccess;
}
