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
* @file		dr64.c
* @section	Intel Debug Registers
*/

#include "ntdatatypes.h"
#include "intrinsics64.h"
#include "cr64.h"
#include "dr64.h"

/**
 * Get the number of a breakpoint which isn't set in DR
 * @param tDr7 - DR7 value
 * @param pcBreakpointNumber - free breakpoint number
 * @return TRUE on success, else FALSE
 */
BOOLEAN
dr_GetFreeBreakpointNumber(
	IN const DR7_REG tDr7,
	OUT PUINT8 pcBreakpointNumber
)
{
	if ((!tDr7.L0) && (!tDr7.G0))
	{
		*pcBreakpointNumber = 0;
		return TRUE;
	}
	else if ((!tDr7.L1) && (!tDr7.G1))
	{
		*pcBreakpointNumber = 1;
		return TRUE;
	}
	else if ((!tDr7.L2) && (!tDr7.G2))
	{
		*pcBreakpointNumber = 2;
		return TRUE;
	}
	else if ((!tDr7.L3) && (!tDr7.G3))
	{
		*pcBreakpointNumber = 3;
		return TRUE;
	}
	return FALSE;
}

/**
* Set a breakpoint in DR
* @param tDr7 - DR7 value
* @param pvAddress - address of breakpoint
* @param eCondition - condition to trigger breakpoint fault
* @param eSize - size of the breakpoint area
* @param cBreakpointNumber - breakpoint number to set
* @return TRUE on success, else FALSE
*/
VOID
dr_SetBreakpoint(
	IN DR7_REG tDr7,
	IN const PVOID pvAddress,
	IN const DR_CONDITION eCondition,
	IN const DR_SIZE eSize,
	IN const UINT8 cBreakpointNumber
)
{
	// For backward compatibility, it's recommended to always set these to 1
	tDr7.Le = TRUE;
	tDr7.Ge = TRUE;

	switch (cBreakpointNumber)
	{
	case 0:
		tDr7.Rw0 = eCondition;
		tDr7.Len0 = eSize;
		tDr7.G0 = TRUE;
		ASM64_WriteDr0((UINT64)pvAddress);
		break;
	case 1:
		tDr7.Rw1 = eCondition;
		tDr7.Len1 = eSize;
		tDr7.G1 = TRUE;
		ASM64_WriteDr1((UINT64)pvAddress);
		break;
	case 2:
		tDr7.Rw2 = eCondition;
		tDr7.Len2 = eSize;
		tDr7.G2 = TRUE;
		ASM64_WriteDr2((UINT64)pvAddress);
		break;
	case 3:
		tDr7.Rw3 = eCondition;
		tDr7.Len3 = eSize;
		tDr7.G3 = TRUE;
		ASM64_WriteDr3((UINT64)pvAddress);
		break;
	}

	ASM64_WriteDr7((UINT64)tDr7.dwValue);
}

BOOLEAN
DR_AddBreakpoint(
	IN const PVOID pvAddress,
	IN const DR_CONDITION eCondition,
	IN const DR_SIZE eSize,
	OUT PUINT8 pcBreakpointNumber
)
{
	BOOLEAN bSuccess = FALSE;
	UINT8 cBreakpointNumber = 0xFF;
	DR7_REG tDr7;
	CR4_REG tCr4;

	if (	(NULL == pvAddress)
		||	(DR_CONDITION_COUNT <= eCondition)
		||	(DR_SIZE_COUNT <= eSize)
		||	(	(DR_CONDITION_EXECUTE == eCondition)
			&&	(DR_SIZE_1 != eSize)))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	if (DR_CONDITION_IO_ACCESS == eCondition)
	{
		tCr4.dwValue = (UINT32)ASM64_ReadCr4();
		if (!tCr4.De)
		{
			// DR_CONDITION_IO_ACCESS is undefined if CR4.DE is clear
			goto lblCleanup;
		}
	}

	tDr7.dwValue = (UINT32)ASM64_ReadDr7();

	if (!dr_GetFreeBreakpointNumber(tDr7, &cBreakpointNumber))
	{
		// All breakpoints are currently in use
		goto lblCleanup;
	}

	dr_SetBreakpoint(
		tDr7,
		pvAddress,
		eCondition,
		eSize,
		cBreakpointNumber);

	if (NULL != pcBreakpointNumber)
	{
		*pcBreakpointNumber = cBreakpointNumber;
	}
	bSuccess = TRUE;

lblCleanup:
	return bSuccess;
}

VOID
DR_RemoveBreakpoint(
	IN const UINT8 cBreakpointNumber
)
{
	DR7_REG tDr7;

	if (MAX_DR_BREAKPOINTS >= cBreakpointNumber)
	{
		// Invalid parameter
		return;
	}

	tDr7.dwValue = (UINT32)ASM64_ReadDr7();

	switch (cBreakpointNumber)
	{
	case 0:
		tDr7.L0 = FALSE;
		tDr7.G0 = FALSE;
		break;
	case 1:
		tDr7.L1 = FALSE;
		tDr7.G1 = FALSE;
		break;
	case 2:
		tDr7.L2 = FALSE;
		tDr7.G2 = FALSE;
		break;
	case 3:
		tDr7.L3 = FALSE;
		tDr7.G3 = FALSE;
		break;
	}

	ASM64_WriteDr7((UINT64)tDr7.dwValue);
}

VOID
DR_RemoveAllBreakpoints(
	VOID
)
{
	UINT8 i = 0;
	for (; i < MAX_DR_BREAKPOINTS; i++)
	{
		DR_RemoveBreakpoint(i);
	}
}
