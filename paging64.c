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
* @file		paging64.c
* @section	Intel x64 Page Tables structures and constants
*			See Intel's: Software Developers Manual Vol 3A, Section 4.5 IA-32E PAGING
*/

#include "paging64.h"

/**
* Convert a physical address to a virtual address
* @param qwPhysicalAddress - the physical address to query
* @return Virtual address used to map the physical address
*/
UINT64
paging64_PhysicalToVirtual(
	UINT64 qwPhysicalAddress
)
{
	// NOTE:	We assume the mapping is 1:1, like in EDK2 UEFI; 
	//			in any other environment, this isn't guaranteed...
	UINT64 qwVirtualAddress = qwPhysicalAddress;
	return qwVirtualAddress;
}

/**
* Verify 64bit paging is enabled
* @return TRUE on success, else FALSE
*/
BOOLEAN
paging64_IsPagingEnabled(
	VOID
)
{
	BOOLEAN bPaging64 = FALSE;
	CR0_REG tCr0 = { 0 };
	CR4_REG tCr4 = { 0 };
	IA32_EFER tEfer = { 0 };

	tCr0.dwValue = __readcr0();
	tCr4.dwValue = __readcr4();
	tEfer.qwValue = __readmsr(MSR_CODE_IA32_EFER);
	
	bPaging64 = (tCr0.Pg && tCr4.Pae && tEfer.Lme);
	return bPaging64;
}

BOOLEAN
paging64_VirtualToPhysical(
	IN const UINT64 qwVirtualAddress,
	OUT PUINT64 pqwPhysicalAddress
)
{
	VA_ADDRESS64 tVa;
	PML4E64 *atPml4e = NULL;
	PPML4E64 ptPml4e = NULL;
	PDPTE1G64 *atPdpte1gb = NULL;
	PPDPTE1G64 ptPdpte1gb = NULL;
	PDPTE64 *atPdpte = NULL;
	PPDPTE64 ptPdpte = NULL;
	PDE2MB64 *atPde2mb = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PDE64 *atPde = NULL;
	PPDE64 ptPde = NULL;
	PTE64 *atPte = NULL;
	PPTE64 ptPte = NULL;
	UINT64 qwPhysicalAddress = 0;
	BOOLEAN bFound = FALSE;
	CR3_REG tCr3 = { 0 };

	tVa.qwValue = qwVirtualAddress;
	tCr3.qwValue = __readcr3();

	atPml4e = paging64_PhysicalToVirtual(tCr3.Pcid.Pml4);
	ptPml4e = &atPml4e[tVa.OneGb.Pml4eIndex];
	if (!ptPml4e->Present)
	{
		// PML4E not present
		goto lblCleanup;
	}

	if (ptPml4e->PageSize)
	{
		// PML4E points to 1GB PDPTE
		atPdpte1gb = paging64_PhysicalToVirtual(ptPml4e->Addr);
		ptPdpte1gb = &atPdpte1gb[tVa.OneGb.PdpteIndex];
		if (!ptPdpte1gb->Present)
		{
			// PDPTE not present
			goto lblCleanup;
		}

		// Calculate physical address from 1GB PDPTE
		qwPhysicalAddress = (ptPdpte1gb->Addr << 30) | (tVa.OneGb.Offset & 0x3fffffff);
		bFound = TRUE;
		goto lblCleanup;
	}
	
	// PML4E points to normal PDPTE
	atPdpte = paging64_PhysicalToVirtual(ptPml4e->Addr);
	ptPdpte = &atPdpte[tVa.TwoMb.PdpteIndex];
	if (!ptPdpte->Present)
	{
		// PDPTE not present
		goto lblCleanup;
	}

	if (ptPdpte->PageSize)
	{
		// PDPTE points to 2MB PDE
		atPde2mb = paging64_PhysicalToVirtual(ptPdpte->Addr);
		ptPde2mb = &atPde2mb[tVa.TwoMb.PdeIndex];
		if (!ptPde2mb->Present)
		{
			// PDE not present
			goto lblCleanup;
		}

		// Calculate physical address from 2MB PDE
		qwPhysicalAddress = (ptPde2mb->Addr << 20) | (tVa.TwoMb.Offset & 0xFFFFF);
		bFound = TRUE;
		goto lblCleanup;
	}

	// PDPTE points to normal PDE
	atPde = paging64_PhysicalToVirtual(ptPdpte->Addr);
	ptPde = &atPde[tVa.FourKb.PdeIndex];
	if (!ptPde->Present)
	{
		// PDE not present
		goto lblCleanup;
	}
	
	// PDE points to 4KB PTE
	atPte = paging64_PhysicalToVirtual(ptPde->Addr);
	ptPte = &atPte[tVa.FourKb.PteIndex];
	if (!ptPte->Present)
	{
		// PTE not present
		goto lblCleanup;
	}

	// Calculate physical address from 4KB PTE
	qwPhysicalAddress = (ptPte->Addr << 12) | (tVa.FourKb.Offset & 0xFFF);
	bFound = TRUE;
	
lblCleanup:
	if (bFound)
	{
		*pqwPhysicalAddress = qwPhysicalAddress;
	}
	return bFound;
}

// TODO: Not tested!
BOOLEAN
PAGING64_VirtualToPhysical(
	IN const UINT64 qwVirtualAddress,
	OUT PUINT64 pqwPhysicalAddress
)
{
	if (	(NULL == pqwPhysicalAddress)
		||	(!paging64_IsPagingEnabled()))
	{
		return FALSE;
	}

	return paging64_VirtualToPhysical(
		qwVirtualAddress,
		pqwPhysicalAddress);
}

// TODO: Not tested!
BOOLEAN
PAGING64_IsMapped(
	IN const UINT64 qwVirtualAddress
)
{
	UINT64 qwPhysicalAddress = 0;
	return PAGING64_VirtualToPhysical(
		qwVirtualAddress,
		&qwPhysicalAddress);
}
