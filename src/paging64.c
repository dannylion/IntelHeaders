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

#include "ntdatatypes.h"
#include "utils.h"
#include "intrinsics64.h"
#include "cpuid.h"
#include "mtrr.h"
#include "paging64.h"
#include "paging64_internal.h"

BOOLEAN
PAGING64_IsIa32ePagingEnabled(
	VOID
)
{
	BOOLEAN bPaging64 = FALSE;
	CR0_REG tCr0;
	CR4_REG tCr4;
	IA32_EFER tEfer;

	tCr0.dwValue = (UINT32)ASM64_ReadCr0();
	tCr4.dwValue = (UINT32)ASM64_ReadCr4();
	tEfer.qwValue = ASM64_Rdmsr((UINT32)MSR_CODE_IA32_EFER);
	
	bPaging64 = (tCr0.Pg && tCr4.Pae && tEfer.Lme);
	return bPaging64;
}

BOOLEAN
paging64_IsPatSupported(
	VOID
)
{
	CPUID_BASIC_FEATURES tCpuidFeatures;
	ASM64_Cpuid(
		(UINT32 *)&tCpuidFeatures,
		(UINT32)CPUID_FUNCTION_BASIC_FEATURES,
		0);
	return (0 != tCpuidFeatures.Pat);
}

BOOLEAN
PAGING64_UefiPhysicalToVirtual(
	IN const UINT64 qwPhysicalAddress,
	OUT PUINT64 pqwVirtualAddress
)
{
	// In EDK2 UEFI the physical and virtual addresses are always equal
	*pqwVirtualAddress = qwPhysicalAddress;
	return TRUE;
}

BOOLEAN
PAGING64_OpenPageTableHandle(
	INOUT PPAGE_TABLE64_HANDLE phPtHandle,
	IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
	IN const UINT64 qwPml4PhysicalAddress
)
{
	BOOLEAN bSuccess = FALSE;
	UINT64 qwPml4VirtualAddress = 0;
	UINT64 qwPdptVirtualAddress = 0;
	UINT64 qwPdeVirtualAddress = 0;
	UINT64 qwPdptPhysicalAddress = 0;
	UINT64 qwPdePhysicalAddress = 0;
	IA32_EFER tEfer;
	IA32_PAT tPat;
	
	if (	(NULL == phPtHandle)
		||	(NULL == pfnPhysicalToVirtual))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	if (!PAGING64_IsIa32ePagingEnabled())
	{
		// 64bit paging is not enabled
		goto lblCleanup;
	}

	// Convert physical addresses of tables to virtual addresses
	if (!(*pfnPhysicalToVirtual)(qwPml4PhysicalAddress, &qwPml4VirtualAddress))
	{
		goto lblCleanup;
	}
	qwPdptPhysicalAddress = qwPml4PhysicalAddress + (sizeof(PML4E64) * PAGING64_PML4E_COUNT);
	qwPdePhysicalAddress = qwPdptPhysicalAddress + (sizeof(PPDPTE64) * PAGING64_PDPTE_COUNT);

	phPtHandle->qwPml4PhysicalAddress = qwPml4PhysicalAddress;
	phPtHandle->patPml4 = (PML4E64(*)[PAGING64_PML4E_COUNT])qwPml4VirtualAddress;
	phPtHandle->qwPdptPhysicalAddress = qwPdptPhysicalAddress;
	phPtHandle->patPdpt = (PDPTE64(*)[PAGING64_PDPTE_COUNT])qwPdptVirtualAddress;
	phPtHandle->qwPdePhysicalAddress = qwPdePhysicalAddress;
	phPtHandle->patPde = (PDE64(*)[PAGING64_PDE_COUNT][PAGING64_PTE_COUNT])qwPdeVirtualAddress;

	tEfer.qwValue = ASM64_Rdmsr((UINT32)MSR_CODE_IA32_EFER);
	phPtHandle->bNxBitSupported = (BOOLEAN)tEfer.Nxe;

	phPtHandle->bMtrrSupported = MTRR_IsMtrrSupported();

	phPtHandle->bPatSupported = paging64_IsPatSupported();
	if (phPtHandle->bPatSupported)
	{
		tPat.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_PAT);
		phPtHandle->acPatMemTypes[0] = (UINT8)tPat.Pa0;
		phPtHandle->acPatMemTypes[1] = (UINT8)tPat.Pa1;
		phPtHandle->acPatMemTypes[2] = (UINT8)tPat.Pa2;
		phPtHandle->acPatMemTypes[3] = (UINT8)tPat.Pa3;
		phPtHandle->acPatMemTypes[4] = (UINT8)tPat.Pa4;
		phPtHandle->acPatMemTypes[5] = (UINT8)tPat.Pa5;
		phPtHandle->acPatMemTypes[6] = (UINT8)tPat.Pa6;
		phPtHandle->acPatMemTypes[7] = (UINT8)tPat.Pa7;
	}
	
	bSuccess = TRUE;
lblCleanup:
	return bSuccess;
}

BOOLEAN
paging64_GetMappedEntryAtVirtualAddress(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	OUT PVOID *ppvEntry,
	OUT PPAGE_TYPE64 pePageType
)
{
	VA_ADDRESS64 tVa;
	PPML4E64 ptPml4e = NULL;
	PPDPTE1G64 ptPdpte1gb = NULL;
	PPDPTE64 ptPdpte = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PPDE64 ptPde = NULL;
	PPTE64 ptPte = NULL;
	BOOLEAN bFound = FALSE;

	tVa.qwValue = qwVirtualAddress;

	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.OneGb.Pml4eIndex];
	if (!ptPml4e->Present)
	{
		// PML4E not present
		goto lblCleanup;
	}

	if (ptPml4e->PageSize)
	{
		// PML4E points to 1GB PDPTE
		ptPdpte1gb = (PPDPTE1G64)&phPageTable->patPdpt[tVa.OneGb.PdpteIndex];
		if (!ptPdpte1gb->Present)
		{
			// PDPTE not present
			goto lblCleanup;
		}

		bFound = TRUE;
		*ppvEntry = (PVOID)ptPdpte1gb;
		*pePageType = PAGE_TYPE_1GB;
		goto lblCleanup;
	}

	// PML4E points to normal PDPTE
	ptPdpte = (PPDPTE64)&phPageTable->patPdpt[tVa.TwoMb.PdpteIndex];
	if (!ptPdpte->Present)
	{
		// PDPTE not present
		goto lblCleanup;
	}

	if (ptPdpte->PageSize)
	{
		// PDPTE points to 2MB PDE
		ptPde2mb = (PDE2MB64 *)&phPageTable->patPde[tVa.TwoMb.PdeIndex];
		if (!ptPde2mb->Present)
		{
			// PDE not present
			goto lblCleanup;
		}

		bFound = TRUE;
		*ppvEntry = (PVOID)ptPde2mb;
		*pePageType = PAGE_TYPE_2MB;
		goto lblCleanup;
	}

	// PDPTE points to normal PDE
	ptPde = (PPDE64)&phPageTable->patPde[tVa.FourKb.PdeIndex];
	if (!ptPde->Present)
	{
		// PDE not present
		goto lblCleanup;
	}

	// PDE points to 4KB PTE
	ptPte = (PPTE64)(&phPageTable->patPde[tVa.FourKb.PdeIndex][tVa.FourKb.PteIndex]);
	if (!ptPte->Present)
	{
		// PTE not present
		goto lblCleanup;
	}

	bFound = TRUE;
	*ppvEntry = (PVOID)ptPte;
	*pePageType = PAGE_TYPE_4KB;

lblCleanup:
	return bFound;
}

PAGE_PERMISSION
paging64_GetPagePermissions(
	IN const PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType
)
{
	PAGE_PERMISSION ePermissions = 0;
	PAGE_PERMISSION eSupervisor = 0;
	PAGE_PERMISSION eWrite = 0;
	PAGE_PERMISSION eExecute = 0;
	PPDPTE1G64 ptPdpte1gb = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PPTE64 ptPte = NULL;
	
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		ptPdpte1gb = (PPDPTE1G64)pvEntry;
		eSupervisor = (ptPdpte1gb->Us) ? PAGE_SUPERVISOR : 0;
		eWrite = (ptPdpte1gb->Rw) ? PAGE_WRITE : 0;
		eExecute = (!ptPdpte1gb->ExecuteDisable) ? PAGE_EXECUTE : 0;
		break;

	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		eSupervisor = (ptPde2mb->Us) ? PAGE_SUPERVISOR : 0;
		eWrite = (ptPde2mb->Rw) ? PAGE_WRITE : 0;
		eExecute = (!ptPde2mb->ExecuteDisable) ? PAGE_EXECUTE : 0;
		break;

	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		eSupervisor = (ptPte->Us) ? PAGE_SUPERVISOR : 0;
		eWrite = (ptPte->Rw) ? PAGE_WRITE : 0;
		eExecute = (!ptPte->ExecuteDisable) ? PAGE_EXECUTE : 0;
		break;
	}

	ePermissions = (eSupervisor | eWrite | eExecute);
	return ePermissions;
}

BOOLEAN
paging64_GetPageMemoryType(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwPhysicalAddress,
	IN const PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType,
	OUT PIA32_PAT_MEMTYPE peMemType
)
{
	BOOLEAN bSuccess = FALSE;
	IA32_PAT_MEMTYPE eEffectiveMemType = IA32_PAT_MEMTYPE_INVALID;
	IA32_PAT_MEMTYPE ePatMemType = IA32_PAT_MEMTYPE_INVALID;
	MTRR_MEMTYPE eMtrrMemType = MTRR_MEMTYPE_INVALID;
	BOOLEAN bPwt = FALSE;
	BOOLEAN bPcd = FALSE;
	BOOLEAN bPat = FALSE;
	UINT8 cPatIndex = 0;
	PPDPTE1G64 ptPdpte1gb = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PPTE64 ptPte = NULL;

	// Extract PAT flags from page-table entry
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		ptPdpte1gb = (PPDPTE1G64)pvEntry;
		bPwt = (BOOLEAN)ptPdpte1gb->Pwt;
		bPcd = (BOOLEAN)ptPdpte1gb->Pcd;
		bPcd = (BOOLEAN)ptPdpte1gb->Pat;
		break;

	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		bPwt = (BOOLEAN)ptPde2mb->Pwt;
		bPcd = (BOOLEAN)ptPde2mb->Pcd;
		bPcd = (BOOLEAN)ptPde2mb->Pat;
		break;

	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		bPwt = (BOOLEAN)ptPte->Pwt;
		bPcd = (BOOLEAN)ptPte->Pcd;
		bPcd = (BOOLEAN)ptPte->Pat;
		break;
	}
	
	// Calculate the PAT entry index from the flags
	cPatIndex = (
			bPwt
		|	(bPcd << 1)
		|	(bPat << 2));

	// Determine the PAT memory type according to the flags
	if (phPageTable->bPatSupported)
	{
		// Vol 3A, Table 11-11. Selection of PAT Entries with PAT, PCD, and PWT Flags
		ePatMemType = phPageTable->acPatMemTypes[cPatIndex];
	}
	else
	{
		if (bPat)
		{
			// If PAT is not supported. The PAT flag in page-table entry must be 0,
			// but in this case it's not... the entry is invalid
			goto lblCleanup;
		}

		// Vol 3A, 11.12.5 PAT Compatibility with Earlier IA-32 Processors
		// When PAT is not supported we use the default 4 entries
		switch (cPatIndex)
		{
		case 0:
			ePatMemType = IA32_PAT_MEMTYPE_WB;
			break;
		case 1:
			ePatMemType = IA32_PAT_MEMTYPE_WT;
			break;
		case 2:
			ePatMemType = IA32_PAT_MEMTYPE_UCM;
			break;
		case 3:
			ePatMemType = IA32_PAT_MEMTYPE_UC;
			break;
		}
	}

	// If MTRR is supported, get the memory type for the physical address from it
	if (phPageTable->bMtrrSupported)
	{
		if (!MTRR_GetMemTypeForPhysicalAddress(
			qwPhysicalAddress,
			FALSE,
			&eMtrrMemType))
		{
			goto lblCleanup;
		}
	}
	
	// Vol 3A, 11.5.2 Precedence of Cache Controls
	// If there is an overlap of page-level and MTRR caching controls, 
	// the mechanism that prevents caching has precedence
	eEffectiveMemType = (ePatMemType <= eMtrrMemType) ? ePatMemType : eMtrrMemType;
	bSuccess = TRUE;

lblCleanup:
	if (bSuccess)
	{
		*peMemType = eEffectiveMemType;
	}
	return bSuccess;
}

BOOLEAN
PAGING64_VirtualToPhysical(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	OUT PUINT64 pqwPhysicalAddress,
	OUT PPAGE_TYPE64 pePageType,
	OUT PPAGE_PERMISSION pePagePermissions,
	OUT PIA32_PAT_MEMTYPE peMemType
)
{
	BOOLEAN bSuccess = FALSE;
	VA_ADDRESS64 tVa;
	PPDPTE1G64 ptPdpte1gb = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PPTE64 ptPte = NULL;
	UINT64 qwPhysicalAddress = 0;
	PVOID pvEntry = NULL;
	PAGE_TYPE64 ePageType = 0;
	PAGE_PERMISSION ePermissions = 0;
	IA32_PAT_MEMTYPE eMemType = 0;

	if (	(NULL == phPageTable)
		||	(NULL == pqwPhysicalAddress))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	tVa.qwValue = qwVirtualAddress;

	if (!paging64_GetMappedEntryAtVirtualAddress(
		phPageTable,
		qwVirtualAddress,
		&pvEntry,
		&ePageType))
	{
		// Virtual address isn't mapped in page-table
		goto lblCleanup;
	}

	// Calculate physical address from entry
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		ptPdpte1gb = (PPDPTE1G64)pvEntry;
		qwPhysicalAddress = (
				(ptPdpte1gb->Addr << PAGE_SHIFT_1GB)
			|	(tVa.OneGb.Offset & PAGE_OFFSET_MASK_1GB));
		break;
	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		qwPhysicalAddress = (
				(ptPde2mb->Addr << PAGE_SHIFT_2MB)
			|	(tVa.TwoMb.Offset & PAGE_OFFSET_MASK_2MB));
		break;
	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		qwPhysicalAddress = (
				(ptPte->Addr << PAGE_SHIFT_4KB)
			|	(tVa.FourKb.Offset & PAGE_OFFSET_MASK_4KB));
		break;
	default:
		// Shouldn't happen
		goto lblCleanup;
	}

	if (!paging64_GetPageMemoryType(
		phPageTable,
		qwPhysicalAddress,
		pvEntry,
		ePageType,
		&eMemType))
	{
		goto lblCleanup;
	}

	ePermissions = paging64_GetPagePermissions(
		pvEntry,
		ePageType);

	bSuccess = TRUE;

lblCleanup:
	if (bSuccess)
	{
		*pqwPhysicalAddress = qwPhysicalAddress;
		*pePageType = ePageType;
		*pePagePermissions = ePermissions;
		*peMemType = eMemType;
	}
	return bSuccess;
}

UINT64
paging64_GetPageSize(
	IN const PAGE_TYPE64 ePageType
)
{
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		return  PAGE_SIZE_1GB;
	case PAGE_TYPE_2MB:
		return  PAGE_SIZE_2MB;
	case PAGE_TYPE_4KB:
		return PAGE_SIZE_4KB;
	default:
		return (UINT64)-1;
	}
}

BOOLEAN
PAGING64_IsVirtualMapped(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 cbSize
)
{
	UINT64 qwPageSize = 0;
	UINT64 qwCurrentVa = qwVirtualAddress;
	UINT64 cbCurrentSize = 0;
	UINT64 qwPhysicalAddress = 0;
	PAGE_TYPE64 ePageType = 0;
	PAGE_PERMISSION ePagePermissions = 0;
	IA32_PAT_MEMTYPE eMemType = 0;

	// Check all pages in the virtual address range are mapped
	while(cbCurrentSize < cbSize)
	{
		if (!PAGING64_VirtualToPhysical(
			phPageTable,
			qwCurrentVa,
			&qwPhysicalAddress,
			&ePageType,
			&ePagePermissions,
			&eMemType))
		{
			// Page isn't mapped
			return FALSE;
		}

		// Add current page size to current virtual address and size
		qwPageSize = paging64_GetPageSize(ePageType);
		cbCurrentSize += qwPageSize;
		qwCurrentVa += qwPageSize;
	}

	// All pages are mapped
	return TRUE;
}

VOID
paging64_UnmapPage(
	INOUT PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType
)
{
	PPDPTE1G64 ptPdtpe1gb = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PPTE64 ptPte = NULL;

	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		ptPdtpe1gb = (PPDPTE1G64)pvEntry;
		ptPdtpe1gb->Present = FALSE;
		break;
	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		ptPde2mb->Present = FALSE;
		break;
	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		ptPte->Present = FALSE;
		break;
	}
}

VOID
PAGING64_UnmapVirtual(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 cbSize
)
{	
	UINT64 qwPageSize = 0;
	UINT64 qwCurrentVa = qwVirtualAddress;
	UINT64 cbCurrentSize = 0;
	PAGE_TYPE64 ePageType = 0;
	PVOID pvEntry = NULL;
	BOOLEAN bEntryMapped = FALSE;

	// Mark all pages in requested range as not present
	while (cbCurrentSize < cbSize)
	{
		bEntryMapped = paging64_GetMappedEntryAtVirtualAddress(
			phPageTable,
			qwCurrentVa,
			&pvEntry,
			&ePageType);
		if (bEntryMapped)
		{
			// Page is mapped, unmap it
			paging64_UnmapPage(pvEntry, ePageType);
		}

		// Add current page size to current virtual address and size
		qwPageSize = paging64_GetPageSize(ePageType);
		cbCurrentSize += qwPageSize;
		qwCurrentVa += qwPageSize;
	}
}

BOOLEAN
paging64_GetPatFlagsForMemType(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const IA32_PAT_MEMTYPE eMemType,
	OUT PBOOLEAN pbPwtFlag,
	OUT PBOOLEAN pbPcdFlag,
	OUT PBOOLEAN pbPatFlag
)
{
	UINT8 i = 0;
	UINT8 cPatIndex = 0;

	if (phPageTable->bPatSupported)
	{
		//! Vol 3A, Table 11-11. Selection of PAT Entries with PAT, PCD, and PWT Flags
		// Iterate over all PAT entries from MSR and see which one contains
		// the given memory type
		for (; i < ARRAYSIZE(phPageTable->acPatMemTypes); i++)
		{
			cPatIndex = phPageTable->acPatMemTypes[i];
			if (cPatIndex == eMemType)
			{
				*pbPwtFlag = (0 != (cPatIndex & (1 << 0)));
				*pbPcdFlag = (0 != (cPatIndex & (1 << 1)));
				*pbPatFlag = (0 != (cPatIndex & (1 << 2)));
				return TRUE;
			}
		}
	}
	else
	{
		//! Vol 3A, 11.12.5 PAT Compatibility with Earlier IA-32 Processors
		// When PAT is not supported we use the default 4 entries.
		switch (eMemType)
		{
		case IA32_PAT_MEMTYPE_WB:
			// WB is by default at entry 0 (See PAT0_DEFAULT_MEMTYPE)
			*pbPwtFlag = 0;
			*pbPcdFlag = 0;
			*pbPatFlag = 0;
			return TRUE;
		case IA32_PAT_MEMTYPE_WT:
			// WT is by default at entry 1 (See PAT1_DEFAULT_MEMTYPE)
			*pbPwtFlag = 1;
			*pbPcdFlag = 0;
			*pbPatFlag = 0;
			return TRUE;
		case IA32_PAT_MEMTYPE_UCM:
			// UC- is by default at entry 2 (See PAT2_DEFAULT_MEMTYPE)
			*pbPwtFlag = 0;
			*pbPcdFlag = 1;
			*pbPatFlag = 0;
			return TRUE;
		case IA32_PAT_MEMTYPE_UC:
			// UC is by default at entry 3 (See PAT3_DEFAULT_MEMTYPE)
			*pbPwtFlag = 1;
			*pbPcdFlag = 1;
			*pbPatFlag = 0;
			return TRUE;
		}
	}

	// No PAT entry contains the given memory type
	return FALSE;
}

VOID
paging64_SetPdpte1gb(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_PERMISSION ePagePermission,
	IN const BOOLEAN bPwtFlag,
	IN const BOOLEAN bPcdFlag,
	IN const BOOLEAN bPatFlag
)
{
	PPML4E64 ptPml4e = NULL;
	PPDPTE1G64 ptPdpte1gb = NULL;
	UINT64 qwPdpteOffset = 0;
	BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
	BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
	VA_ADDRESS64 tVa;

	tVa.qwValue = qwVirtualAddress;

	// Get pointers to all relevant page-table entries for page
	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.OneGb.Pml4eIndex];
	ptPdpte1gb = (PPDPTE1G64)&phPageTable->patPdpt[tVa.OneGb.PdpteIndex];

	// Calculate entries offsets from array start
	qwPdpteOffset = ((UINT64)ptPdpte1gb) - ((UINT64)&phPageTable->patPdpt);

	// Initialize PML4E to point to PDPTE
	MemFill(ptPml4e, 0, sizeof(*ptPml4e));
	ptPml4e->Present = TRUE;
	ptPml4e->Addr = phPageTable->qwPdptPhysicalAddress + qwPdpteOffset;
	ptPml4e->Us = bSupervisor;
	ptPml4e->Rw = bWrite;
	ptPml4e->Pwt = bPwtFlag;
	ptPml4e->Pcd = bPcdFlag;

	// Initialize PDPTE to point to physical address
	MemFill(ptPdpte1gb, 0, sizeof(*ptPdpte1gb));
	ptPdpte1gb->Present = TRUE;
	ptPdpte1gb->PageSize = 1;
	ptPdpte1gb->Addr = qwPhysicalAddress >> PAGE_SHIFT_1GB;
	ptPdpte1gb->Us = bSupervisor;
	if (	phPageTable->bNxBitSupported
		&&	(0 == (ePagePermission & PAGE_EXECUTE)))
	{
		ptPdpte1gb->ExecuteDisable = TRUE;
	}
	ptPdpte1gb->Rw = bWrite;
	ptPdpte1gb->Pwt = bPwtFlag;
	ptPdpte1gb->Pcd = bPcdFlag;
	ptPdpte1gb->Pat = bPatFlag;
}

VOID
paging64_SetPde2mb(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_PERMISSION ePagePermission,
	IN const BOOLEAN bPwtFlag,
	IN const BOOLEAN bPcdFlag,
	IN const BOOLEAN bPatFlag
)
{
	PPML4E64 ptPml4e = NULL;
	PPDPTE64 ptPdpte = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	UINT64 qwPdpteOffset = 0;
	UINT64 qwPdeOffset = 0;
	BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
	BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
	VA_ADDRESS64 tVa;

	tVa.qwValue = qwVirtualAddress;

	// Get pointers to all relevant page-table entries for page
	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.TwoMb.Pml4eIndex];
	ptPdpte = (PPDPTE64)&phPageTable->patPdpt[tVa.TwoMb.PdpteIndex];
	ptPde2mb = (PPDE2MB64)&phPageTable->patPde[tVa.TwoMb.PdeIndex];

	// Calculate entries offsets from array start
	qwPdpteOffset = ((UINT64)ptPdpte) - ((UINT64)&phPageTable->patPdpt);
	qwPdeOffset = ((UINT64)ptPde2mb) - ((UINT64)&phPageTable->patPde);

	// Initialize PML4E to point to PDPTE
	MemFill(ptPml4e, 0, sizeof(*ptPml4e));
	ptPml4e->Present = TRUE;
	ptPml4e->Addr = phPageTable->qwPdptPhysicalAddress + qwPdpteOffset;
	ptPml4e->Us = bSupervisor;
	ptPml4e->Rw = bWrite;
	ptPml4e->Pwt = bPwtFlag;
	ptPml4e->Pcd = bPcdFlag;

	// Initialize PDPTE to point to PDE
	MemFill(ptPdpte, 0, sizeof(*ptPdpte));
	ptPdpte->Present = TRUE;
	ptPdpte->Addr = phPageTable->qwPdePhysicalAddress + qwPdeOffset;
	ptPdpte->Us = bSupervisor;
	ptPdpte->Rw = bWrite;
	ptPdpte->Pwt = bPwtFlag;
	ptPdpte->Pcd = bPcdFlag;

	// Initialize PDE to point to physical address
	MemFill(ptPde2mb, 0, sizeof(*ptPde2mb));
	ptPde2mb->Present = TRUE;
	ptPde2mb->PageSize = 1;
	ptPde2mb->Addr = qwPhysicalAddress >> PAGE_SHIFT_2MB;
	ptPde2mb->Us = bSupervisor;
	if (	phPageTable->bNxBitSupported
		&&	(0 == (ePagePermission & PAGE_EXECUTE)))
	{
		ptPde2mb->ExecuteDisable = TRUE;
	}
	ptPde2mb->Rw = bWrite;
	ptPde2mb->Pwt = bPwtFlag;
	ptPde2mb->Pcd = bPcdFlag;
	ptPde2mb->Pat = bPatFlag;
}

VOID
paging64_SetPte(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_PERMISSION ePagePermission,
	IN const BOOLEAN bPwtFlag,
	IN const BOOLEAN bPcdFlag,
	IN const BOOLEAN bPatFlag
)
{
	PPML4E64 ptPml4e = NULL;
	PPDPTE64 ptPdpte = NULL;
	PPDE64 ptPde = NULL;
	PPTE64 ptPte = NULL;
	UINT64 qwPdpteOffset = 0;
	UINT64 qwPdeOffset = 0;
	UINT64 qwPteOffset = 0;
	BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
	BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
	VA_ADDRESS64 tVa;

	tVa.qwValue = qwVirtualAddress;

	// Get pointers to all relevant page-table entries for page
	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.FourKb.Pml4eIndex];
	ptPdpte = (PPDPTE64)&phPageTable->patPdpt[tVa.FourKb.PdpteIndex];
	ptPde = (PPDE64)&phPageTable->patPde[tVa.FourKb.PdeIndex];
	ptPte = (PPTE64)&phPageTable->patPde[tVa.FourKb.PdeIndex][tVa.FourKb.PteIndex];

	// Calculate entries offsets from array start
	qwPdpteOffset = ((UINT64)ptPdpte) - ((UINT64)&phPageTable->patPdpt);
	qwPdeOffset = ((UINT64)ptPde) - ((UINT64)&phPageTable->patPde);
	qwPteOffset = ((UINT64)ptPte) - ((UINT64)&phPageTable->patPde);

	// Initialize PML4E to point to PDPTE
	MemFill(ptPml4e, 0, sizeof(*ptPml4e));
	ptPml4e->Present = TRUE;
	ptPml4e->Addr = phPageTable->qwPdptPhysicalAddress + qwPdpteOffset;
	ptPml4e->Us = bSupervisor;
	ptPml4e->Rw = bWrite;
	ptPml4e->Pwt = bPwtFlag;
	ptPml4e->Pcd = bPcdFlag;

	// Initialize PDPTE to point to PDE
	MemFill(ptPdpte, 0, sizeof(*ptPdpte));
	ptPdpte->Present = TRUE;
	ptPdpte->Addr = phPageTable->qwPdePhysicalAddress + qwPdeOffset;
	ptPdpte->Us = bSupervisor;
	ptPdpte->Rw = bWrite;
	ptPdpte->Pwt = bPwtFlag;
	ptPdpte->Pcd = bPcdFlag;

	// Initialize PDE to point to PTE
	MemFill(ptPde, 0, sizeof(*ptPde));
	ptPde->Present = TRUE;
	ptPde->Addr = phPageTable->qwPdePhysicalAddress + qwPteOffset;
	ptPde->Us = bSupervisor;
	ptPde->Rw = bWrite;
	ptPde->Pwt = bPwtFlag;
	ptPde->Pcd = bPcdFlag;

	// Initialize PTE to point to physical address
	MemFill(ptPte, 0, sizeof(*ptPte));
	ptPte->Present = TRUE;
	ptPte->Addr = qwPhysicalAddress >> PAGE_SHIFT_4KB;
	ptPte->Us = bSupervisor;
	ptPte->Rw = bWrite;
	if (	phPageTable->bNxBitSupported
		&&	(0 == (ePagePermission & PAGE_EXECUTE)))
	{
		ptPte->ExecuteDisable = TRUE;
	}
	ptPte->Pwt = bPwtFlag;
	ptPte->Pcd = bPcdFlag;
	ptPte->Pat = bPatFlag;
}

BOOLEAN
paging64_MapPage(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_TYPE64 ePageType,
	IN const PAGE_PERMISSION ePagePermission,
	IN const IA32_PAT_MEMTYPE eMemType
)
{
	BOOLEAN bSuccess = FALSE;
	BOOLEAN bPwtFlag = 0;
	BOOLEAN bPcdFlag = 0;
	BOOLEAN bPatFlag = 0;
	MTRR_MEMTYPE eMtrrMemType = MTRR_MEMTYPE_INVALID;

	// Get the memory type for the physical address from MTRR to see if we
	// can use the eMemType given, or not
	if (phPageTable->bMtrrSupported)
	{
		// TODO: What do we do here if page is more than 4KB? (TBD)
		if (!MTRR_GetMemTypeForPhysicalAddress(
			qwPhysicalAddress,
			FALSE,
			&eMtrrMemType))
		{
			goto lblCleanup;
		}

		// Vol 3A, 11.5.2 Precedence of Cache Controls
		// If there is an overlap of page-level and MTRR caching controls, 
		// the mechanism that prevents caching has precedence
		if (eMemType > eMtrrMemType)
		{
			// According to MTRR we can't use eMemType given
			goto lblCleanup;
		}
	}

	// Get the PAT flags that indicate the memory type given so we
	// can assign them in the page-table entries
	if (!paging64_GetPatFlagsForMemType(
		phPageTable,
		eMemType,
		&bPwtFlag,
		&bPcdFlag,
		&bPatFlag))
	{
		// No PAT entry contains the given memory type
		goto lblCleanup;
	}
	
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		paging64_SetPdpte1gb(
			phPageTable,
			qwVirtualAddress,
			qwPhysicalAddress,
			ePagePermission,
			bPwtFlag,
			bPcdFlag,
			bPatFlag);
		break;
	case PAGE_TYPE_2MB:
		paging64_SetPde2mb(
			phPageTable,
			qwVirtualAddress,
			qwPhysicalAddress,
			ePagePermission,
			bPwtFlag,
			bPcdFlag,
			bPatFlag);
		break;
	case PAGE_TYPE_4KB:
		paging64_SetPte(
			phPageTable,
			qwVirtualAddress,
			qwPhysicalAddress,
			ePagePermission,
			bPwtFlag,
			bPcdFlag,
			bPatFlag);
		break;
	}

	bSuccess = TRUE;

lblCleanup:
	return bSuccess;
}

BOOLEAN
PAGING64_MapPhysicalToVirtual(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwPhysicalAddress,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 cbSize,
	IN const PAGE_PERMISSION ePagePermission,
	IN const IA32_PAT_MEMTYPE eMemType
)
{
	BOOLEAN bSuccess = FALSE;
	PAGE_TYPE64 ePageType = 0;
	PVOID pvEntry = NULL;
	BOOLEAN bStartedMapping = FALSE;
	UINT64 nCurrentPage = 0;
	UINT64 nPagesToMap = BYTES_TO_PAGES_4KB(cbSize);
	UINT64 qwCurrentVa = (UINT64)PAGE_ALIGN_4KB(qwVirtualAddress);
	UINT64 qwCurrentPhysical = (UINT64)PAGE_ALIGN_4KB(qwPhysicalAddress);
	
	// Verify none of the pages in the virtual address range are already mapped
	for (nCurrentPage = 0; nCurrentPage < nPagesToMap; nCurrentPage++)
	{
		if (paging64_GetMappedEntryAtVirtualAddress(
			phPageTable,
			qwCurrentVa,
			&pvEntry,
			&ePageType))
		{
			// A page is already mapped at the given range
			goto lblCleanup;
		}

		qwCurrentVa += PAGE_SIZE_4KB;
	}

	// Map pages until all of the requested range is in the page-table
	qwCurrentVa = (UINT64)PAGE_ALIGN_4KB(qwVirtualAddress);
	bStartedMapping = TRUE;
	for (nCurrentPage = 0; nCurrentPage < nPagesToMap; nCurrentPage++)
	{
		if (!paging64_MapPage(
			phPageTable,
			qwCurrentVa,
			qwCurrentPhysical,
			PAGE_TYPE_4KB,
			ePagePermission,
			eMemType))
		{
			goto lblCleanup;
		}

		qwCurrentVa += PAGE_SIZE_4KB;
		qwCurrentPhysical += PAGE_SIZE_4KB;
	}

	bSuccess = TRUE;

lblCleanup:
	if (	(!bSuccess)
		&&	bStartedMapping)
	{
		PAGING64_UnmapVirtual(
			phPageTable,
			qwVirtualAddress,
			cbSize);
	}

	return bSuccess;
}

BOOLEAN
PAGING64_InitPageTable(
	INOUT PPAGE_TABLE64 ptPageTable,
	IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
	IN const UINT64 qwVirtualAddress,
	OUT PPAGE_TABLE64_HANDLE phOutPageTable
)
{
	BOOLEAN bSuccess = FALSE;
	PAGE_TABLE64_HANDLE hCurrentPageTable;
	PAGE_TABLE64_HANDLE hDstPageTable;
	UINT64 qwCurrentPml4PhysicalAddress = 0;
	UINT64 qwPml4PhysicalAddress = 0;
	CR3_REG tCr3;
	PAGE_TYPE64 ePageType = 0;
	PAGE_PERMISSION ePagePermission = 0;
	IA32_PAT_MEMTYPE eMemType = 0;

	if (	(NULL == ptPageTable)
		||	(NULL == pfnPhysicalToVirtual)
		||	(NULL == qwVirtualAddress)
		||	(NULL == phOutPageTable))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	// Open a handle to current page-table which CR3 points to
	tCr3.qwValue = ASM64_ReadCr3();
	qwCurrentPml4PhysicalAddress = tCr3.NoPcid.Pml4;
	if (!PAGING64_OpenPageTableHandle(
		&hCurrentPageTable,
		pfnPhysicalToVirtual,
		qwCurrentPml4PhysicalAddress))
	{
		// Failed to open a handle to current page-table
		goto lblCleanup;
	}
	
	// Find the physical address of the page-table to initialize
	if (!PAGING64_VirtualToPhysical(
		&hCurrentPageTable,
		(UINT64)ptPageTable,
		&qwPml4PhysicalAddress,
		&ePageType,
		&ePagePermission,
		&eMemType))
	{
		// Failed to translate virtual page-table pointer to a physical address
		goto lblCleanup;
	}

	// Zero out the page-table we wish to initialize
	MemFill(ptPageTable, 0, sizeof(PAGE_TABLE64));

	// Open a handle to the page-table we wish to initialize
	if (!PAGING64_OpenPageTableHandle(
		&hDstPageTable,
		pfnPhysicalToVirtual,
		qwPml4PhysicalAddress))
	{
		// Failed to open a handle to current page-table
		goto lblCleanup;
	}
	
	// Create a mapping for the page-table in itself at the given virtual address
	if (!PAGING64_MapPhysicalToVirtual(
		&hDstPageTable,
		qwPml4PhysicalAddress,
		qwVirtualAddress,
		sizeof(*ptPageTable),
		PAGE_READWRITE,
		IA32_PAT_MEMTYPE_UC))
	{
		// Failed to map the page-table in itself at a virtual address
		goto lblCleanup;
	}

	bSuccess = TRUE;
	MemCopy(phOutPageTable, &hDstPageTable, sizeof(*phOutPageTable));

lblCleanup:
	return bSuccess;
}

BOOLEAN
PAGING64_CopyPageTable(
	INOUT PPAGE_TABLE64_HANDLE phDstPageTable,
	IN const PPAGE_TABLE64_HANDLE phSrcPageTable
)
{
	BOOLEAN bSuccess = FALSE;
	UINT64 qwVirtualAddress = 0;
	UINT64 qwPhysicalAddress = 0;
	PAGE_PERMISSION ePermissions = 0;
	IA32_PAT_MEMTYPE eMemType = IA32_PAT_MEMTYPE_INVALID;
	PPML4E64 ptPml4e = NULL;
	PPDPTE1G64 ptPdpte1gb = NULL;
	PPDPTE64 ptPdpte = NULL;
	PPDE2MB64 ptPde2mb = NULL;
	PPDE64 ptPde = NULL;
	PPTE64 ptPte = NULL;
	UINT16 wPml4Index = 0;
	UINT16 wPdptIndex = 0;
	UINT16 wPdeIndex = 0;
	UINT16 wPteIndex = 0;
	VA_ADDRESS64 tVa;

	if (	(NULL == phDstPageTable)
		||	(NULL == phSrcPageTable))
	{
		goto lblCleanup;
	}
	
	// Iterate over all present entries in the source page-table
	// and add the same mapping to the destination page-table
	for (; wPml4Index < PAGING64_PML4E_COUNT; wPml4Index++)
	{
		// Skip PML4E if it's not present
		ptPml4e = (PPML4E64)&phSrcPageTable->patPml4[wPml4Index];
		if (!ptPml4e->Present)
		{
			continue;
		}

		// Iterate all present PDPTE entries in source PML4E
		for (; wPdptIndex < PAGING64_PDPTE_COUNT; wPdptIndex++)
		{
			// Skip PDPTE if it's not present
			ptPdpte = (PPDPTE64)&phSrcPageTable->patPdpt[wPdptIndex];
			if (!ptPdpte->Present)
			{
				continue;
			}
			
			// Check if this is a 1GB page
			if (ptPdpte->PageSize)
			{
				ptPdpte1gb = (PPDPTE1G64)ptPdpte;

				tVa.OneGb.Pml4eIndex = wPml4Index;
				tVa.OneGb.PdpteIndex = wPdptIndex;
				tVa.OneGb.Offset = 0;
				qwVirtualAddress = tVa.qwValue;

				// Make sure destination page-table doesn't already map
				// this virtual address
				if (PAGING64_IsVirtualMapped(
					phDstPageTable,
					qwVirtualAddress,
					PAGE_SIZE_1GB))
				{
					goto lblCleanup;
				}

				qwPhysicalAddress = ptPdpte1gb->Addr << PAGE_SHIFT_1GB;

				ePermissions = paging64_GetPagePermissions(
					(PVOID)ptPdpte1gb,
					PAGE_TYPE_1GB);
				
				if (!paging64_GetPageMemoryType(
					phSrcPageTable,
					qwPhysicalAddress,
					(PVOID)ptPdpte1gb,
					PAGE_TYPE_1GB,
					&eMemType))
				{
					goto lblCleanup;
				}

				// Copy 1GB page to destination page-table
				if (!paging64_MapPage(
					phDstPageTable,
					qwVirtualAddress,
					qwPhysicalAddress,
					PAGE_TYPE_1GB,
					ePermissions,
					eMemType))
				{
					goto lblCleanup;
				}

				continue;
			}

			// Iterate all present PDE entries in source PDPTE
			for (; wPdeIndex < PAGING64_PDE_COUNT; wPdeIndex++)
			{
				// Skip PDE if it's not present
				ptPde = (PPDE64)&phSrcPageTable->patPde[wPdeIndex];
				if (!ptPde->Present)
				{
					continue;
				}

				// Check if this is a 2MB page
				if (ptPde->PageSize)
				{
					ptPde2mb = (PPDE2MB64)ptPde;

					tVa.TwoMb.Pml4eIndex = wPml4Index;
					tVa.TwoMb.PdpteIndex = wPdptIndex;
					tVa.TwoMb.PdeIndex = wPdeIndex;
					tVa.TwoMb.Offset = 0;
					qwVirtualAddress = tVa.qwValue;

					// Make sure destination page-table doesn't already map
					// this virtual address
					if (PAGING64_IsVirtualMapped(
						phDstPageTable,
						qwVirtualAddress,
						PAGE_SIZE_2MB))
					{
						goto lblCleanup;
					}

					qwPhysicalAddress = ptPde2mb->Addr << PAGE_SHIFT_2MB;

					ePermissions = paging64_GetPagePermissions(
						(PVOID)ptPde2mb,
						PAGE_TYPE_2MB);

					if (!paging64_GetPageMemoryType(
						phSrcPageTable,
						qwPhysicalAddress,
						(PVOID)ptPde2mb,
						PAGE_TYPE_2MB,
						&eMemType))
					{
						goto lblCleanup;
					}

					// Copy 2MB page to destination page-table
					if (!paging64_MapPage(
						phDstPageTable,
						qwVirtualAddress,
						qwPhysicalAddress,
						PAGE_TYPE_2MB,
						ePermissions,
						eMemType))
					{
						goto lblCleanup;
					}

					continue;
				}

				// Iterate all present PTE entries in source PDE
				for (; wPteIndex < PAGING64_PTE_COUNT; wPteIndex++)
				{
					// Skip PTE if it's not present
					ptPte = (PPTE64)&phSrcPageTable->patPde[wPdeIndex][wPteIndex];
					if (!ptPte->Present)
					{
						continue;
					}

					tVa.FourKb.Pml4eIndex = wPml4Index;
					tVa.FourKb.PdpteIndex = wPdptIndex;
					tVa.FourKb.PdeIndex = wPdeIndex;
					tVa.FourKb.PteIndex = wPteIndex;
					tVa.FourKb.Offset = 0;
					qwVirtualAddress = tVa.qwValue;

					// Make sure destination page-table doesn't already map
					// this virtual address
					if (PAGING64_IsVirtualMapped(
						phDstPageTable,
						qwVirtualAddress,
						PAGE_SIZE_4KB))
					{
						goto lblCleanup;
					}

					qwPhysicalAddress = ptPte->Addr << PAGE_SHIFT_4KB;

					ePermissions = paging64_GetPagePermissions(
						(PVOID)ptPte,
						PAGE_TYPE_4KB);

					if (!paging64_GetPageMemoryType(
						phSrcPageTable,
						qwPhysicalAddress,
						(PVOID)ptPte,
						PAGE_TYPE_4KB,
						&eMemType))
					{
						goto lblCleanup;
					}

					// Copy 4KB page to destination page-table
					if (!paging64_MapPage(
						phDstPageTable,
						qwVirtualAddress,
						qwPhysicalAddress,
						PAGE_TYPE_4KB,
						ePermissions,
						eMemType))
					{
						goto lblCleanup;
					}
				}
			}
		}
	}

	bSuccess = TRUE;

lblCleanup:
	return bSuccess;
}
