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
* @file		mtrr.h
* @section	11.11 MEMORY TYPE RANGE REGISTERS (MTRRS)
*/

#ifndef __INTEL_MTRR_H__
#define __INTEL_MTRR_H__

#include "ntdatatypes.h"
#include "msr64.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 3A, Table 11-8. Memory Types That Can Be Encoded in MTRRs
typedef enum _MTRR_MEMTYPE
{
	MTRR_MEMTYPE_UC = 0,
	MTRR_MEMTYPE_WC = 1,
	// 2-3 Reserved
	MTRR_MEMTYPE_WT = 4,
	MTRR_MEMTYPE_WP = 5,
	MTRR_MEMTYPE_WB = 6,
	// 7-0xFF Reserved
	MTRR_MEMTYPE_INVALID = 0xFF
} MTRR_MEMTYPE, *PMTRR_MEMTYPE;

/**
 * Verify MTRR feature is supported by the CPU
 * @return TRUE on success, else FALSE
 */
BOOLEAN
MTRR_IsMtrrSupported(
	VOID
);

/**
* Get SMM range and memory type from SMRR MSRs
* @param pqwSmmRangeStart - SMM Range start physical address
* @param pqwSmmRangeEnd - SMM Range end physical address
* @param peSmmMemType - the memory type of the SMM range
* @return TRUE on success, else FALSE
*/
BOOLEAN
MTRR_GetSmmRange(
	OUT PUINT64 pqwSmmRangeStart,
	OUT PUINT64 pqwSmmRangeEnd,
	OUT PMTRR_MEMTYPE peSmmMemType
);

/**
* Get memory type of the physical address given according to MTRR
* @param qwPhysicalAddress - physical address to query
* @param bInSmm - TRUE if we're currently in SMM
* @param peMemType - the memory type of the address
* @return TRUE on success, else FALSE
*/
BOOLEAN
MTRR_GetMemTypeForPhysicalAddress(
	IN const UINT64 qwPhysicalAddress,
	IN const BOOLEAN bInSmm,
	OUT PMTRR_MEMTYPE peMemType
);

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_MTRR_H__ */
