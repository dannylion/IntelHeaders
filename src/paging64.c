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
#include "log.h"
#include "utils.h"
#include "intrinsics64.h"
#include "cpuid.h"
#include "mtrr.h"
#include "paging64.h"
#include "paging64_internal.h"

STATIC
__inline
UINT64
paging64_PageSizeByType(
	IN const PAGE_TYPE64 ePageType
)
{
	switch (ePageType)
	{
	case PAGE_TYPE_4KB:
		return PAGE_SIZE_4KB;
	case PAGE_TYPE_2MB:
		return PAGE_SIZE_2MB;
	case PAGE_TYPE_1GB:
		return PAGE_SIZE_1GB;
	default:
		// Shouldn't happen
		return 0;
	}
}

STATIC
__inline
UINT64
paging64_AlignByPageType(
	IN const PAGE_TYPE64 ePageType,
	IN const UINT64 qwAddress
)
{
	switch (ePageType)
	{
	case PAGE_TYPE_4KB:
		return (UINT64)PAGE_ALIGN_4KB(qwAddress);
	case PAGE_TYPE_2MB:
		return (UINT64)PAGE_ALIGN_2MB(qwAddress);
	case PAGE_TYPE_1GB:
		return (UINT64)PAGE_ALIGN_1GB(qwAddress);
	default:
		// Shouldn't happen
		return 0;
	}
}

STATIC
__inline
UINT64
paging64_AddressAndSizeToSpanPagesByPageType(
	IN const PAGE_TYPE64 ePageType,
	IN const UINT64 qwAddress,
	IN const UINT64 cbSize
)
{
	switch (ePageType)
	{
	case PAGE_TYPE_4KB:
		return ADDRESS_AND_SIZE_TO_SPAN_PAGES_4KB(qwAddress, cbSize);
	case PAGE_TYPE_2MB:
		return ADDRESS_AND_SIZE_TO_SPAN_PAGES_2MB(qwAddress, cbSize);
	case PAGE_TYPE_1GB:
		return ADDRESS_AND_SIZE_TO_SPAN_PAGES_1GB(qwAddress, cbSize);
	default:
		// Shouldn't happen
		return 0;
	}
}

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

STATIC
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
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
	IN const UINT64 qwPml4PhysicalAddress,
	IN const PLOG_HANDLE ptLog
)
{
	BOOLEAN bSuccess = FALSE;
	UINT64 qwPml4VirtualAddress = 0;
	IA32_EFER tEfer;
	IA32_PAT tPat;
	
	if (	(NULL == phPageTable)
		||	(NULL == pfnPhysicalToVirtual)
		||	(NULL == ptLog))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	phPageTable->ptLog = ptLog;
	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_OpenPageTableHandle(phPageTable=0x%016llx, "
		"pfnPhysicalToVirtual=0x%016llx, qwPml4PhysicalAddress=0x%016llx,"
		"ptLog=0x%016llx)",
		(UINT64)phPageTable,
		(UINT64)pfnPhysicalToVirtual,
		qwPml4PhysicalAddress,
		(UINT64)ptLog);

	if (!PAGING64_IsIa32ePagingEnabled())
	{
		LOG_ERROR(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_OpenPageTableHandle: 64bit paging is not enabled");
		goto lblCleanup;
	}

	// Convert physical addresses of tables to virtual addresses
	if (!(*pfnPhysicalToVirtual)(qwPml4PhysicalAddress, &qwPml4VirtualAddress))
	{
		LOG_ERROR(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_OpenPageTableHandle: pfnPhysicalToVirtual failed (0x%016llx)",
			(UINT64)pfnPhysicalToVirtual);
		goto lblCleanup;
	}

	// Initialize handle structure
	phPageTable->qwPml4PhysicalAddress = qwPml4PhysicalAddress;
	phPageTable->patPml4 = (PPML4E64)qwPml4VirtualAddress;
	phPageTable->pfnPhysicalToVirtual = pfnPhysicalToVirtual;

	phPageTable->bOneGbSupported = CPUID_CheckOneGbPageSupport();

	tEfer.qwValue = ASM64_Rdmsr((UINT32)MSR_CODE_IA32_EFER);
	phPageTable->bNxBitSupported = (BOOL)tEfer.Nxe;

	phPageTable->bMtrrSupported = (BOOL)MTRR_IsMtrrSupported();

	phPageTable->bPatSupported = (BOOL)paging64_IsPatSupported();
	if (phPageTable->bPatSupported)
	{
		tPat.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_PAT);
		phPageTable->acPatMemTypes[0] = (UINT8)tPat.Pa0;
		phPageTable->acPatMemTypes[1] = (UINT8)tPat.Pa1;
		phPageTable->acPatMemTypes[2] = (UINT8)tPat.Pa2;
		phPageTable->acPatMemTypes[3] = (UINT8)tPat.Pa3;
		phPageTable->acPatMemTypes[4] = (UINT8)tPat.Pa4;
		phPageTable->acPatMemTypes[5] = (UINT8)tPat.Pa5;
		phPageTable->acPatMemTypes[6] = (UINT8)tPat.Pa6;
		phPageTable->acPatMemTypes[7] = (UINT8)tPat.Pa7;
	}

	LOG_INFO(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_OpenPageTableHandle: qwPageTablePhysicalAddress=0x%016llx, "
		"bOneGbSupported=%d, bNxBitSupported=%d, bMtrrSupported=%d, bPatSupported=%d",
		phPageTable->qwPml4PhysicalAddress,
		phPageTable->bOneGbSupported,
		phPageTable->bNxBitSupported,
		phPageTable->bMtrrSupported,
		phPageTable->bPatSupported);
	
	bSuccess = TRUE;
lblCleanup:
	if (	(NULL != phPageTable)
		&&	(NULL != ptLog))
	{
		LOG_TRACE(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"<-- PAGING64_OpenPageTableHandle return bSuccess=%d",
			bSuccess);
	}
	return bSuccess;
}

STATIC
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
	UINT64 qwPdptPhysicalAddress = 0;
	PPDPTE64 patPdpt = NULL;
	PPDPTE64 ptPdpte = NULL;
	UINT64 qwPdPhysicalAddress = 0;
	PPDE64 patPd = NULL;
	PPDE64 ptPde = NULL;
	UINT64 qwPtPhysicalAddress = 0;
	PPTE64 patPt = NULL;
	PPTE64 ptPte = NULL;
	BOOLEAN bFound = FALSE;

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> paging64_GetMappedEntryAtVirtualAddress(phPageTable=0x%016llx, "
		"qwVirtualAddress=0x%016llx, ppvEntry=0x%016llx, pePageType=0x%016llx)",
		(UINT64)phPageTable,
		qwVirtualAddress,
		(UINT64)ppvEntry,
		(UINT64)pePageType);

	tVa.qwValue = qwVirtualAddress;

	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.OneGb.Pml4eIndex];
	if (!ptPml4e->Present)
	{
		LOG_WARN(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetMappedEntryAtVirtualAddress: PML4E %d not present "
			"(patPml4=0x%016llx, ptPml4e=0x%016llx)",
			tVa.OneGb.Pml4eIndex,
			(UINT64)phPageTable->patPml4,
			(UINT64)ptPml4e);
		goto lblCleanup;
	}

	// Get PDPT virtual address from PML4E
	qwPdptPhysicalAddress = ptPml4e->Addr << 12;
	if (!phPageTable->pfnPhysicalToVirtual(qwPdptPhysicalAddress, (PUINT64)&patPdpt))
	{
		goto lblCleanup;
	}

	// Get PDPTE by index from virtual address
	ptPdpte = (PPDPTE64)&patPdpt[tVa.OneGb.PdpteIndex];
	if (!ptPdpte->Present)
	{
		LOG_WARN(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetMappedEntryAtVirtualAddress: PDPTE %d not present "
			"(patPdpt=0x%016llx, ptPdpte=0x%016llx)",
			tVa.TwoMb.PdpteIndex,
			(UINT64)patPdpt,
			(UINT64)ptPdpte);
		goto lblCleanup;
	}

	if (ptPdpte->PageSize)
	{
		// PDPTE points to a 1GB page
		bFound = TRUE;
		*ppvEntry = (PVOID)ptPdpte;
		*pePageType = PAGE_TYPE_1GB;
		goto lblCleanup;
	}

	// Get PDE by index from virtual address
	qwPdPhysicalAddress = ptPdpte->Addr << 12;
	if (!phPageTable->pfnPhysicalToVirtual(qwPdPhysicalAddress, (PUINT64)&patPd))
	{
		goto lblCleanup;
	}

	// PDPTE points to PDE
	ptPde = (PPDE64)&patPd[tVa.TwoMb.PdeIndex];
	if (!ptPde->Present)
	{
		LOG_WARN(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetMappedEntryAtVirtualAddress: PDE %d not present "
			"(patPd=0x%016llx, ptPde=0x%016llx)",
			tVa.FourKb.PdeIndex,
			(UINT64)patPd,
			(UINT64)ptPde);
		goto lblCleanup;
	}

	if (ptPde->PageSize)
	{
		// PDE points to a 2MB page
		bFound = TRUE;
		*ppvEntry = (PVOID)ptPde;
		*pePageType = PAGE_TYPE_2MB;
		goto lblCleanup;
	}

	// Get PT virtual address from PDE
	qwPtPhysicalAddress = ptPde->Addr << 12;
	if (!phPageTable->pfnPhysicalToVirtual(qwPtPhysicalAddress, (PUINT64)&patPt))
	{
		goto lblCleanup;
	}
	
	// Get PTE by index from virtual address
	ptPte = (PPTE64)(&patPt[tVa.FourKb.PteIndex]);
	if (!ptPte->Present)
	{
		LOG_WARN(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetMappedEntryAtVirtualAddress: PTE %d not present "
			"(patPt=0x%016llx, ptPte=0x%016llx)",
			tVa.FourKb.PteIndex,
			(UINT64)patPt,
			(UINT64)ptPte);
		goto lblCleanup;
	}

	// PTE points to a 4KB page
	bFound = TRUE;
	*ppvEntry = (PVOID)ptPte;
	*pePageType = PAGE_TYPE_4KB;

lblCleanup:
	if (bFound)
	{
		LOG_DEBUG(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetMappedEntryAtVirtualAddress: pvEntry=0x%016llx, "
			"qwEntry=0x%016llx, ePageType=%d",
			(UINT64)*ppvEntry,
			*((PUINT64)*ppvEntry),
			*pePageType);
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"<-- paging64_GetMappedEntryAtVirtualAddress return bFound=%d",
		bFound);
	return bFound;
}

STATIC
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
		eExecute = (!ptPdpte1gb->Nx) ? PAGE_EXECUTE : 0;
		break;

	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		eSupervisor = (ptPde2mb->Us) ? PAGE_SUPERVISOR : 0;
		eWrite = (ptPde2mb->Rw) ? PAGE_WRITE : 0;
		eExecute = (!ptPde2mb->Nx) ? PAGE_EXECUTE : 0;
		break;

	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		eSupervisor = (ptPte->Us) ? PAGE_SUPERVISOR : 0;
		eWrite = (ptPte->Rw) ? PAGE_WRITE : 0;
		eExecute = (!ptPte->Nx) ? PAGE_EXECUTE : 0;
		break;
	}

	ePermissions = (eSupervisor | eWrite | eExecute);
	return ePermissions;
}

STATIC
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

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> paging64_GetPageMemoryType(phPageTable=0x%016llx, "
		"qwPhysicalAddress=0x%016llx, pvEntry=0x%016llx, ePageType=%d, "
		"peMemType=0x%016llx)",
		(UINT64)phPageTable,
		qwPhysicalAddress,
		(UINT64)pvEntry,
		ePageType,
		(UINT64)peMemType);

	// Extract PAT flags from page-table entry
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		ptPdpte1gb = (PPDPTE1G64)pvEntry;
		bPwt = (BOOLEAN)ptPdpte1gb->Pwt;
		bPcd = (BOOLEAN)ptPdpte1gb->Pcd;
		bPat = (BOOLEAN)ptPdpte1gb->Pat;
		break;

	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		bPwt = (BOOLEAN)ptPde2mb->Pwt;
		bPcd = (BOOLEAN)ptPde2mb->Pcd;
		bPat = (BOOLEAN)ptPde2mb->Pat;
		break;

	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		bPwt = (BOOLEAN)ptPte->Pwt;
		bPcd = (BOOLEAN)ptPte->Pcd;
		bPat = (BOOLEAN)ptPte->Pat;
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

		LOG_DEBUG(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetPageMemoryType: PAT is supported, ePatMemType=%d from index=%d",
			ePatMemType,
			cPatIndex);
	}
	else
	{
		if (bPat)
		{
			// If PAT is not supported. The PAT flag in page-table entry must be 0,
			// but in this case it's not... the entry is invalid
			LOG_ERROR(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"paging64_GetPageMemoryType: PAT isn't supported and PAT flag in "
				"entry is set",
				ePatMemType,
				cPatIndex);
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

		LOG_DEBUG(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetPageMemoryType: PAT isn't supported, ePatMemType=%d from index=%d",
			ePatMemType,
			cPatIndex);
	}

	// If MTRR is supported, get the memory type for the physical address from it
	if (phPageTable->bMtrrSupported)
	{
		if (!MTRR_GetMemTypeForPhysicalAddress(
			qwPhysicalAddress,
			FALSE,
			&eMtrrMemType))
		{
			LOG_ERROR(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"paging64_GetPageMemoryType: MTRR_GetMemTypeForPhysicalAddress failed");
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

		LOG_DEBUG(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_GetPageMemoryType: eEffectiveMemType=%x, ePatMemType=%x, "
			"eMtrrMemType=%x",
			eEffectiveMemType,
			ePatMemType,
			eMtrrMemType);
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"<-- paging64_GetPageMemoryType return bSuccess=%d",
		bSuccess);
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
	const UINT64 qwMaxPhyAddr = MAXPHYADDR;

	if (	(NULL == phPageTable)
		||	(NULL == pqwPhysicalAddress)
		||	(NULL == pePageType)
		||	(NULL == pePagePermissions)
		||	(NULL == peMemType))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_VirtualToPhysical(phPageTable=0x%016llx, qwVirtualAddress=0x%016llx,"
		"pqwPhysicalAddress=0x%016llx, pePageType=0x%016llx, pePagePermissions=0x%016llx, "
		"peMemType=0x%016llx)",
		(UINT64)phPageTable,
		qwVirtualAddress,
		(UINT64)pqwPhysicalAddress,
		(UINT64)pePageType,
		(UINT64)pePagePermissions,
		(UINT64)peMemType);

	tVa.qwValue = qwVirtualAddress;

	if (!paging64_GetMappedEntryAtVirtualAddress(
		phPageTable,
		qwVirtualAddress,
		&pvEntry,
		&ePageType))
	{
		// Virtual address isn't mapped in page-table
		LOG_WARN(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_VirtualToPhysical: paging64_GetMappedEntryAtVirtualAddress"
			" failed qwVirtualAddress=0x%016llx",
			qwVirtualAddress);
		goto lblCleanup;
	}

	// Calculate physical address from entry
	switch (ePageType)
	{
	case PAGE_TYPE_1GB:
		ptPdpte1gb = (PPDPTE1G64)pvEntry;
		qwPhysicalAddress = (
				((ptPdpte1gb->Addr << PAGE_SHIFT_1GB) & qwMaxPhyAddr)
			|	(tVa.OneGb.Offset & PAGE_OFFSET_MASK_1GB));
		break;
	case PAGE_TYPE_2MB:
		ptPde2mb = (PPDE2MB64)pvEntry;
		qwPhysicalAddress = (
				((ptPde2mb->Addr << PAGE_SHIFT_2MB) & qwMaxPhyAddr)
			|	(tVa.TwoMb.Offset & PAGE_OFFSET_MASK_2MB));
		break;
	case PAGE_TYPE_4KB:
		ptPte = (PPTE64)pvEntry;
		qwPhysicalAddress = (
				((ptPte->Addr << PAGE_SHIFT_4KB) & qwMaxPhyAddr)
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
		LOG_ERROR(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_VirtualToPhysical: paging64_GetPageMemoryType failed "
			"pvEntry=0x%016llx, ePageType=%d",
			(UINT64)pvEntry,
			ePageType);
		goto lblCleanup;
	}

	ePermissions = paging64_GetPagePermissions(
		pvEntry,
		ePageType);

	LOG_DEBUG(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_VirtualToPhysical: phPageTable=0x%016llx, qwVirtualAddres=0x%016llx "
		"maps qwPhysicalAddres=0x%016llx, ePageType=%d, ePermissions=0x%x, eMemType=%d",
		(UINT64)phPageTable,
		qwVirtualAddress,
		qwPhysicalAddress,
		ePageType,
		ePermissions,
		eMemType);

	bSuccess = TRUE;

lblCleanup:
	if (bSuccess)
	{
		*pqwPhysicalAddress = qwPhysicalAddress;
		*pePageType = ePageType;
		*pePagePermissions = ePermissions;
		*peMemType = eMemType;
	}

	if (NULL != phPageTable)
	{
		LOG_TRACE(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"<-- PAGING64_VirtualToPhysical return bSuccess=%d",
			bSuccess);
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
	BOOLEAN bSuccess = FALSE;
	UINT64 qwPageSize = 0;
	UINT64 qwCurrentVa = qwVirtualAddress;
	UINT64 cbCurrentSize = 0;
	UINT64 qwPhysicalAddress = 0;
	PAGE_TYPE64 ePageType = 0;
	PAGE_PERMISSION ePagePermissions = 0;
	IA32_PAT_MEMTYPE eMemType = 0;

	if (	(NULL == phPageTable)
		||	(0 == cbSize))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_IsVirtualMapped(phPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
		"cbSize=%d)",
		(UINT64)phPageTable,
		qwVirtualAddress,
		cbSize);

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
			LOG_WARN(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"PAGING64_IsVirtualMapped: PAGING64_VirtualToPhysical failed "
				"qwVirtualAddres=0x%016llx",
				qwCurrentVa);
			goto lblCleanup;
		}

		// Add current page size to current virtual address and size
		qwPageSize = paging64_GetPageSize(ePageType);
		cbCurrentSize += qwPageSize;
		qwCurrentVa += qwPageSize;
	}

	// All pages are mapped
	LOG_DEBUG(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_IsVirtualMapped: qwVirtualAddres=0x%016llx, cbSize=%d mapped!",
		qwVirtualAddress,
		cbSize);

	bSuccess = TRUE;

lblCleanup:
	if (NULL != phPageTable)
	{
		LOG_TRACE(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"<-- PAGING64_IsVirtualMapped return bSuccess=%d",
			bSuccess);
	}
	return bSuccess;
}

STATIC
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

	if (	(NULL == phPageTable)
		||	(0 == cbSize))
	{
		// Invalid parameters
		return;
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_UnmapVirtual(phPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
		"cbSize=%d)",
		(UINT64)phPageTable,
		qwVirtualAddress,
		cbSize);

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
			LOG_DEBUG(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"PAGING64_UnmapVirtual: Marking entry not present pvEntry=0x%016llx, "
				"ePageType=%d",
				(UINT64)pvEntry,
				ePageType);

			// Page is mapped, unmap it
			paging64_UnmapPage(pvEntry, ePageType);
		}

		// Add current page size to current virtual address and size
		qwPageSize = paging64_GetPageSize(ePageType);
		cbCurrentSize += qwPageSize;
		qwCurrentVa += qwPageSize;
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"<-- PAGING64_UnmapVirtual");
}

STATIC
BOOLEAN
paging64_GetPatFlagsForMemType(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const IA32_PAT_MEMTYPE eMemType,
	OUT PBOOLEAN pbPwtFlag,
	OUT PBOOLEAN pbPcdFlag,
	OUT PBOOLEAN pbPatFlag
)
{
	BOOLEAN bSuccess = FALSE;
	UINT8 ucPatIndex = 0;
	IA32_PAT_MEMTYPE ePatMemType = 0;

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> paging64_GetPatFlagsForMemType(phPageTable=0x%016llx, eMemType=%d, "
		"pbPwtFlag=0x%016llx, pbPcdFlag=0x%016llx, pbPatFlag=0x%016llx)",
		(UINT64)phPageTable,
		eMemType,
		(UINT64)pbPwtFlag,
		(UINT64)pbPcdFlag,
		(UINT64)pbPatFlag);

	if (phPageTable->bPatSupported)
	{
		//! Vol 3A, Table 11-11. Selection of PAT Entries with PAT, PCD, and PWT Flags
		// Iterate over all PAT entries from MSR and see which one contains
		// the given memory type
		for (; ucPatIndex < ARRAYSIZE(phPageTable->acPatMemTypes); ucPatIndex++)
		{
			ePatMemType = (IA32_PAT_MEMTYPE)phPageTable->acPatMemTypes[ucPatIndex];
			if (ePatMemType == eMemType)
			{
				*pbPwtFlag = (0 != (ucPatIndex & (1 << 0)));
				*pbPcdFlag = (0 != (ucPatIndex & (1 << 1)));
				*pbPatFlag = (0 != (ucPatIndex & (1 << 2)));
				bSuccess = TRUE;
				break;
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
			bSuccess = TRUE;
			break;
		case IA32_PAT_MEMTYPE_WT:
			// WT is by default at entry 1 (See PAT1_DEFAULT_MEMTYPE)
			*pbPwtFlag = 1;
			*pbPcdFlag = 0;
			*pbPatFlag = 0;
			bSuccess = TRUE;
			break;
		case IA32_PAT_MEMTYPE_UCM:
			// UC- is by default at entry 2 (See PAT2_DEFAULT_MEMTYPE)
			*pbPwtFlag = 0;
			*pbPcdFlag = 1;
			*pbPatFlag = 0;
			bSuccess = TRUE;
			break;
		case IA32_PAT_MEMTYPE_UC:
			// UC is by default at entry 3 (See PAT3_DEFAULT_MEMTYPE)
			*pbPwtFlag = 1;
			*pbPcdFlag = 1;
			*pbPatFlag = 0;
			bSuccess = TRUE;
			break;
		}
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"<-- paging64_GetPatFlagsForMemType return bSuccess=%d (Pwt=%d, Pcd=%d, Pat=%d)",
		bSuccess,
		*pbPwtFlag,
		*pbPcdFlag,
		*pbPatFlag);
	return bSuccess;
}

STATIC
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
	BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
	BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
	BOOLEAN bNoExecute = (
			phPageTable->bNxBitSupported
		&&	(0 == (ePagePermission & PAGE_EXECUTE)));
	VA_ADDRESS64 tVa;

	tVa.qwValue = qwVirtualAddress;

	// Get PML4E from PML4 table using index from virtual address
	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.OneGb.Pml4eIndex];

	// Get PDPTE from PDPT table using index from virtual address
	ptPdpte1gb = (PPDPTE1G64)&phPageTable->patPdpt[tVa.OneGb.PdpteIndex];

	// Initialize PML4E to point to PDPTE
	MemFill(ptPml4e, 0, sizeof(*ptPml4e));
	ptPml4e->Present = TRUE;
	ptPml4e->Addr = phPageTable->qwPdptPhysicalAddress >> 12;
	ptPml4e->Us = bSupervisor;
	ptPml4e->Rw = bWrite;
	ptPml4e->Nx = bNoExecute;
	ptPml4e->Pwt = bPwtFlag;
	ptPml4e->Pcd = bPcdFlag;

	// Initialize PDPTE to point to physical address
	MemFill(ptPdpte1gb, 0, sizeof(*ptPdpte1gb));
	ptPdpte1gb->Present = TRUE;
	ptPdpte1gb->PageSize = 1;
	ptPdpte1gb->Addr = qwPhysicalAddress >> PAGE_SHIFT_1GB;
	ptPdpte1gb->Us = bSupervisor;
	ptPdpte1gb->Rw = bWrite;
	ptPdpte1gb->Nx = bNoExecute;
	ptPdpte1gb->Pwt = bPwtFlag;
	ptPdpte1gb->Pcd = bPcdFlag;
	ptPdpte1gb->Pat = bPatFlag;
}

STATIC
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
	UINT64 qwPdOffset = 0;
	BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
	BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
	BOOLEAN bNoExecute = (
			phPageTable->bNxBitSupported
		&&	(0 == (ePagePermission & PAGE_EXECUTE)));
	VA_ADDRESS64 tVa;

	tVa.qwValue = qwVirtualAddress;

	// Get pointers to all relevant page-table entries for page
	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.TwoMb.Pml4eIndex];
	ptPdpte = (PPDPTE64)&phPageTable->patPdpt[tVa.TwoMb.PdpteIndex];
	ptPde2mb = (PPDE2MB64)&phPageTable->patPdArray[tVa.TwoMb.PdpteIndex][tVa.TwoMb.PdeIndex];

	// Calculate page-directory table offset from array start
	qwPdOffset = tVa.TwoMb.PdpteIndex * sizeof(*phPageTable->patPdArray);

	// Initialize PML4E to point to PDPTE
	MemFill(ptPml4e, 0, sizeof(*ptPml4e));
	ptPml4e->Present = 1;
	ptPml4e->Addr = phPageTable->qwPdptPhysicalAddress >> 12;
	ptPml4e->Us = bSupervisor;
	ptPml4e->Rw = bWrite;
	ptPml4e->Nx = bNoExecute;
	ptPml4e->Pwt = bPwtFlag;
	ptPml4e->Pcd = bPcdFlag;

	// Initialize PDPTE to point to PDE
	MemFill(ptPdpte, 0, sizeof(*ptPdpte));
	ptPdpte->Present = 1;
	ptPdpte->Addr = (phPageTable->qwPdArrayPhysicalAddress + qwPdOffset) >> 12;
	ptPdpte->Us = bSupervisor;
	ptPdpte->Rw = bWrite;
	ptPdpte->Nx = bNoExecute;
	ptPdpte->Pwt = bPwtFlag;
	ptPdpte->Pcd = bPcdFlag;

	// Initialize PDE to point to physical address
	MemFill(ptPde2mb, 0, sizeof(*ptPde2mb));
	ptPde2mb->Present = 1;
	ptPde2mb->PageSize = 1;
	ptPde2mb->Addr = qwPhysicalAddress >> PAGE_SHIFT_2MB;
	ptPde2mb->Us = bSupervisor;
	ptPde2mb->Rw = bWrite;
	ptPde2mb->Nx = bNoExecute;
	ptPde2mb->Pwt = bPwtFlag;
	ptPde2mb->Pcd = bPcdFlag;
	ptPde2mb->Pat = bPatFlag;
}

STATIC
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
	UINT64 qwPdOffset = 0;
	UINT64 qwPtOffset = 0;
	BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
	BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
	BOOLEAN bNoExecute = (
			phPageTable->bNxBitSupported
		&&	(0 == (ePagePermission & PAGE_EXECUTE)));
	VA_ADDRESS64 tVa;

	tVa.qwValue = qwVirtualAddress;

	// Get pointers to all relevant page-table entries for page
	ptPml4e = (PPML4E64)&phPageTable->patPml4[tVa.FourKb.Pml4eIndex];
	ptPdpte = (PPDPTE64)&phPageTable->patPdpt[tVa.FourKb.PdpteIndex];
	ptPde = (PPDE64)&phPageTable->patPdArray[tVa.FourKb.PdpteIndex][tVa.FourKb.PdeIndex];
	ptPte = (PPTE64)&phPageTable->patPtArray[tVa.FourKb.PdpteIndex][tVa.FourKb.PdeIndex][tVa.FourKb.PteIndex];

	// Calculate page-directory and page-table offsets from array starts
	qwPdOffset = tVa.FourKb.PdpteIndex * sizeof(*phPageTable->patPdArray);
	qwPtOffset = tVa.FourKb.PdeIndex * sizeof(*phPageTable->patPtArray);

	// Initialize PML4E to point to PDPTE
	MemFill(ptPml4e, 0, sizeof(*ptPml4e));
	ptPml4e->Present = TRUE;
	ptPml4e->Addr = phPageTable->qwPdptPhysicalAddress >> 12;
	ptPml4e->Us = bSupervisor;
	ptPml4e->Rw = bWrite;
	ptPml4e->Nx = bNoExecute;
	ptPml4e->Pwt = bPwtFlag;
	ptPml4e->Pcd = bPcdFlag;

	// Initialize PDPTE to point to PDE
	MemFill(ptPdpte, 0, sizeof(*ptPdpte));
	ptPdpte->Present = TRUE;
	ptPdpte->Addr = (phPageTable->qwPdArrayPhysicalAddress + qwPdOffset) >> 12;
	ptPdpte->Us = bSupervisor;
	ptPdpte->Rw = bWrite;
	ptPdpte->Nx = bNoExecute;
	ptPdpte->Pwt = bPwtFlag;
	ptPdpte->Pcd = bPcdFlag;

	// Initialize PDE to point to PTE
	MemFill(ptPde, 0, sizeof(*ptPde));
	ptPde->Present = TRUE;
	ptPde->Addr = (phPageTable->qwPtArrayPhysicalAddress + qwPtOffset) >> 12;
	ptPde->Us = bSupervisor;
	ptPde->Rw = bWrite;
	ptPde->Nx = bNoExecute;
	ptPde->Pwt = bPwtFlag;
	ptPde->Pcd = bPcdFlag;

	// Initialize PTE to point to physical address
	MemFill(ptPte, 0, sizeof(*ptPte));
	ptPte->Present = TRUE;
	ptPte->Addr = qwPhysicalAddress >> PAGE_SHIFT_4KB;
	ptPte->Us = bSupervisor;
	ptPte->Rw = bWrite;
	ptPte->Nx = bNoExecute;
	ptPte->Pwt = bPwtFlag;
	ptPte->Pcd = bPcdFlag;
	ptPte->Pat = bPatFlag;
}

STATIC
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

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> paging64_MapPage(phPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
		"qwPhysicalAddress=0x%016llx, ePageType=%d, ePagePermission=%d, eMemType=%d)",
		(UINT64)phPageTable,
		qwVirtualAddress,
		qwPhysicalAddress,
		ePageType,
		ePagePermission,
		eMemType);

	// Get the memory type for the physical address from MTRR to see if we
	// can use the eMemType given, or not
	if (phPageTable->bMtrrSupported)
	{
		// TODO: What do we do here if page end address exceeds MTRR range end? (TBD)
		if (!MTRR_GetMemTypeForPhysicalAddress(
			qwPhysicalAddress,
			FALSE,
			&eMtrrMemType))
		{
			LOG_ERROR(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"paging64_MapPage: MTRR_GetMemTypeForPhysicalAddress failed "
				"qwPhysicalAddress=0x%016llx",
				qwPhysicalAddress);
			goto lblCleanup;
		}

		// Vol 3A, 11.5.2 Precedence of Cache Controls
		// If there is an overlap of page-level and MTRR caching controls, 
		// the mechanism that prevents caching has precedence
		if (eMemType > eMtrrMemType)
		{
			LOG_ERROR(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"paging64_MapPage: According to MTRR we can't use eMemType=%d "
				"given (eMttrMemType=%d)",
				eMemType,
				eMtrrMemType);
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
		LOG_ERROR(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"paging64_MapPage: paging64_GetPatFlagsForMemType failed eMemType=%d",
			eMemType);
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

	LOG_INFO(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"paging64_MapPage: Page mapped qwVirtualAddress=0x%016llx->"
		"qwPhysicalAddress=0x%016llx, ePageType=%d, ePermission=0x%x, "
		"bPwt=%d, bPcd=%d, bPat=%d",
		qwVirtualAddress,
		qwPhysicalAddress,
		ePageType,
		ePagePermission,
		bPwtFlag,
		bPcdFlag,
		bPatFlag);
	bSuccess = TRUE;

lblCleanup:
	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"<-- paging64_MapPage return bSuccess=%d",
		bSuccess);
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
	UINT64 nPagesToMap = 0;
	UINT64 qwCurrentVa = 0;
	UINT64 qwStartVa = 0;
	UINT64 qwEndVa = 0;
	UINT64 qwStartPhysical = 0;
	UINT64 qwEndPhysical = 0;
	UINT64 qwCurrentPhysical = 0;
	UINT64 cbMinPageSize = 0;
	const UINT64 qwMaxPhyAddr = MAXPHYADDR;

	if (	(NULL == phPageTable)
		||	(qwMaxPhyAddr <= qwPhysicalAddress)
		||	(0 == cbSize)
		||	(0 > eMemType)
		||	(IA32_PAT_MEMTYPE_UCM < eMemType)
		||	(0 == phPageTable->qwMaxVirtualAddress)
		||	(0 == phPageTable->qwPdptPhysicalAddress)
		||	(0 == phPageTable->qwPdArrayPhysicalAddress)
		||	(0 == phPageTable->qwPtArrayPhysicalAddress)
		||	(NULL == phPageTable->patPdpt)
		||	(NULL == phPageTable->patPdArray)
		||	(NULL == phPageTable->patPtArray)
		||	(qwPhysicalAddress >= (qwPhysicalAddress + cbSize))
		||	(qwVirtualAddress >= (qwVirtualAddress + cbSize)))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	LOG_TRACE(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_MapPhysicalToVirtual(phPageTable=0x%016llx, "
		"qwPhysicalAddress=0x%016llx, qwVirtualAddress=0x%016llx, cbSize=%d, "
		"ePagePermission=0x%x, ePageType=%d)",
		(UINT64)phPageTable,
		qwPhysicalAddress,
		qwVirtualAddress,
		cbSize,
		ePagePermission,
		ePageType);

	// Calculate start and end virtual and physical addresses of mapping
	// and how many pages we'll need to allocate
	cbMinPageSize = paging64_PageSizeByType(phPageTable->eMinPageType);
	qwStartVa = paging64_AlignByPageType(
		phPageTable->eMinPageType,
		qwVirtualAddress);
	qwStartPhysical = paging64_AlignByPageType(
		phPageTable->eMinPageType,
		qwPhysicalAddress);
	nPagesToMap = paging64_AddressAndSizeToSpanPagesByPageType(
		phPageTable->eMinPageType,
		qwVirtualAddress,
		cbSize);
	qwEndVa = qwStartVa + nPagesToMap * cbMinPageSize;
	qwEndPhysical = qwStartPhysical + nPagesToMap * cbMinPageSize;

	// Check mapping won't exceed page-table max virtual address or MAXPHYADDR
	if (	(qwEndVa <= qwStartVa)
		||	(qwEndVa >= phPageTable->qwMaxVirtualAddress)
		||	(qwEndPhysical <= qwStartPhysical)
		||	(qwEndPhysical >= qwMaxPhyAddr))
	{
		LOG_ERROR(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_MapPhysicalToVirtual: requested mapping exceeds max virtual address"
			" or MAXPHYADDR (qwVirtualAddress=0x%016llx, qwPhysicalAddress=0x%016llx "
			"cbSize=0x%016llx, qwMaxVa=0x%016llx, MAXPHYADDR=0x%016llx)",
			qwVirtualAddress,
			qwPhysicalAddress,
			cbSize,
			phPageTable->qwMaxVirtualAddress,
			qwMaxPhyAddr);
		goto lblCleanup;
	}

	// Verify none of the pages in the virtual address range are already mapped
	for (qwCurrentVa = qwStartVa;
		qwCurrentVa < qwEndVa;
		qwCurrentVa += cbMinPageSize)
	{
		if (paging64_GetMappedEntryAtVirtualAddress(
			phPageTable,
			qwCurrentVa,
			&pvEntry,
			&ePageType))
		{
			LOG_ERROR(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"PAGING64_MapPhysicalToVirtual: A page is already mapped at the given "
				"range qwPageTablePhysicalAddress=0x%016llx, qwVirtualAddres=0x%016llx, "
				"cbSize=%d",
				phPageTable->qwPml4PhysicalAddress,
				qwVirtualAddress,
				cbSize);
			goto lblCleanup;
		}
	}

	// Map pages until all of the requested range is in the page-table
	bStartedMapping = TRUE;
	for (qwCurrentVa = qwStartVa, qwCurrentPhysical = qwStartPhysical;
		qwCurrentVa < qwEndVa;
		qwCurrentVa += cbMinPageSize, qwCurrentPhysical += cbMinPageSize)
	{
		if (!paging64_MapPage(
			phPageTable,
			qwCurrentVa,
			qwCurrentPhysical,
			phPageTable->eMinPageType,
			ePagePermission,
			eMemType))
		{
			LOG_ERROR(
				phPageTable->ptLog,
				LOG_MODULE_PAGING,
				"PAGING64_MapPhysicalToVirtual: paging64_MapPage failed "
				"qwPageTablePhysicalAddress=0x%016llx, qwVirtualAddress=0x%016llx, "
				"qwPhysicalAddress=0x%016llx, ePermissions=0x%x, eMemType=%d",
				phPageTable->qwPml4PhysicalAddress,
				qwCurrentVa,
				qwCurrentPhysical,
				ePagePermission,
				eMemType);
			goto lblCleanup;
		}
	}

	LOG_INFO(
		phPageTable->ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_MapPhysicalToVirtual: Range mapped qwPageTablePhysicalAddress=0x%016llx, "
		"qwVirtualAddress=0x%016llx, cbSize=%d, ePermission=0x%x, eMemType=%d",
		phPageTable->qwPml4PhysicalAddress,
		qwVirtualAddress,
		cbSize,
		ePagePermission,
		eMemType);

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

	if (NULL != phPageTable)
	{
		LOG_TRACE(
			phPageTable->ptLog,
			LOG_MODULE_PAGING,
			"<-- PAGING64_MapPhysicalToVirtual return bSuccess=%d",
			bSuccess);
	}
	return bSuccess;
}

BOOLEAN
PAGING64_InitPageTable(
	INOUT PPAGE_TABLE64 ptPageTable,
	IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
	IN const PLOG_HANDLE ptLog,
	IN const UINT64 qwMaxVirtualAddress,
	IN const PAGE_TYPE64 eMinPageType,
	OUT PPAGE_TABLE64_HANDLE phOutPageTable
)
{
	BOOLEAN bSuccess = FALSE;
	PAGE_TABLE64_HANDLE hCurrentPageTable;
	PAGE_TABLE64_HANDLE hDstPageTable;
	UINT64 qwCurrentPml4PhysicalAddress = 0;
	UINT64 qwDstPml4PhysicalAddress = 0;
	PAGE_TYPE64 ePageType = 0;
	PAGE_PERMISSION ePagePermission = 0;
	IA32_PAT_MEMTYPE eMemType = 0;
	UINT16 wPdptIndex = 0;
	UINT16 wPdIndex = 0;
	VA_ADDRESS64 tMaxVa;
	PDE64(*patCurrentPd)[PAGING64_PDE_COUNT] = NULL;
	PTE64(*patCurrentPt)[PAGING64_PTE_COUNT] = NULL;
	C_ASSERT(0x1000 == sizeof(*patCurrentPd));
	C_ASSERT(0x1000 == sizeof(*patCurrentPt));

	if (	(NULL == ptPageTable)
		||	(NULL == pfnPhysicalToVirtual)
		||	(NULL == ptLog)
		||	(0 > eMinPageType)
		||	(PAGE_TYPE_1GB < eMinPageType)
		||	(PAGE_SIZE_1GB > qwMaxVirtualAddress)
		||	(PAGE_TABLE64_MAX_VIRTUAL_ADDRESS < qwMaxVirtualAddress)
		||	(NULL == phOutPageTable))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	LOG_TRACE(
		ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_InitPageTable(ptPageTable=0x%016llx, pfnPhysicalToVirtual=0x%016llx, "
		"ptLog=0x%016llx, qwMaxVirtualAddress=0x%016llx, eMinPageType=%d,"
		"phOutPageTable=0x%016llx)",
		(UINT64)ptPageTable,
		(UINT64)pfnPhysicalToVirtual,
		(UINT64)ptLog,
		qwMaxVirtualAddress,
		eMinPageType,
		(UINT64)phOutPageTable);

	// Open a handle to current page-table which CR3 points to
	qwCurrentPml4PhysicalAddress = ASM64_ReadCr3();
	if (!PAGING64_OpenPageTableHandle(
		&hCurrentPageTable,
		pfnPhysicalToVirtual,
		qwCurrentPml4PhysicalAddress,
		ptLog))
	{
		LOG_ERROR(
			ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_InitPageTable: PAGING64_OpenPageTableHandle failed on CR3=0x%016llx",
			qwCurrentPml4PhysicalAddress);
		goto lblCleanup;
	}
	
	// Find the physical address of the page-table to initialize
	if (!PAGING64_VirtualToPhysical(
		&hCurrentPageTable,
		(UINT64)ptPageTable,
		&qwDstPml4PhysicalAddress,
		&ePageType,
		&ePagePermission,
		&eMemType))
	{
		LOG_ERROR(
			ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_InitPageTable: PAGING64_VirtualToPhysical failed CR3=0x%016llx, "
			"qwVirtualAddress=0x%016llx",
			qwCurrentPml4PhysicalAddress,
			(UINT64)ptPageTable);
		goto lblCleanup;
	}

	// Open a handle to the page-table we wish to initialize
	if (!PAGING64_OpenPageTableHandle(
		&hDstPageTable,
		pfnPhysicalToVirtual,
		qwDstPml4PhysicalAddress,
		ptLog))
	{
		LOG_ERROR(
			ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_InitPageTable: PAGING64_OpenPageTableHandle failed on "
			"ptPageTable=0x%016llx",
			(UINT64)ptPageTable);
		goto lblCleanup;
	}

	if (	(PAGE_TYPE_1GB == eMinPageType)
		&&	(!hDstPageTable.bOneGbSupported))
	{
		LOG_ERROR(
			ptLog,
			LOG_MODULE_PAGING,
			"PAGING64_InitPageTable: 1GB pages are not supported and minimum "
			"page-type to use is 1GB");
		goto lblCleanup;
	}

	// Initialize members we need to edit page-table
	hDstPageTable.eMinPageType = eMinPageType;
	hDstPageTable.qwMaxVirtualAddress = qwMaxVirtualAddress;
	
	hDstPageTable.qwPdptPhysicalAddress = (
			qwDstPml4PhysicalAddress
		+	FIELD_OFFSET(PAGE_TABLE64, atPdpt));
	hDstPageTable.qwPdArrayPhysicalAddress = (
			qwDstPml4PhysicalAddress
		+	FIELD_OFFSET(PAGE_TABLE64, atPd));
	hDstPageTable.qwPtArrayPhysicalAddress = (
			qwDstPml4PhysicalAddress
		+	FIELD_OFFSET(PAGE_TABLE64, atPt));

	hDstPageTable.patPdpt = (PPDPTE64)(&ptPageTable->atPdpt);
	hDstPageTable.patPdArray= (PDE64(*)[PAGING64_PDPTE_COUNT])(
		&ptPageTable->atPd);
	hDstPageTable.patPtArray= (PTE64(*)[PAGING64_PDPTE_COUNT][PAGING64_PDE_COUNT])(
		&ptPageTable->atPt);

	// Zero out the PML4 and PDPT tables
	tMaxVa.qwValue = qwMaxVirtualAddress;
	LOG_DEBUG(
		ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_InitPageTable: Zero PML4=0x%016llx (cbSize=0x%x)",
		(UINT64)ptPageTable->atPml4,
		sizeof(ptPageTable->atPml4));
	MemZero(ptPageTable->atPml4, sizeof(ptPageTable->atPml4));
	LOG_DEBUG(
		ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_InitPageTable: Zero PDPT=0x%016llx (cbSize=0x%x)",
		(UINT64)ptPageTable->atPdpt,
		sizeof(ptPageTable->atPdpt));
	MemZero(ptPageTable->atPdpt, sizeof(ptPageTable->atPdpt));
	
	// Zero out the PD and PT tables if they exist
	if (PAGE_TYPE_2MB >= eMinPageType)
	{
		for (wPdptIndex = 0; wPdptIndex < tMaxVa.FourKb.PdpteIndex; wPdptIndex++)
		{
			if (PAGE_TYPE_4KB == eMinPageType)
			{
				for (wPdIndex = 0; wPdIndex < tMaxVa.FourKb.PdeIndex; wPdIndex++)
				{
					patCurrentPt = (PTE64(*)[PAGING64_PTE_COUNT])(
						&hDstPageTable.patPtArray[wPdptIndex][wPdIndex]);
					LOG_DEBUG(
						ptLog,
						LOG_MODULE_PAGING,
						"PAGING64_InitPageTable: Zero PT=0x%016llx (cbSize=0x%x)",
						(UINT64)patCurrentPt,
						sizeof(*patCurrentPt));
					MemZero(patCurrentPt, sizeof(*patCurrentPt));
				}
			}

			patCurrentPd = (PDE64(*)[PAGING64_PDE_COUNT])(
				&hDstPageTable.patPdArray[wPdptIndex]);
			LOG_DEBUG(
				ptLog,
				LOG_MODULE_PAGING,
				"PAGING64_InitPageTable: Zero PD=0x%016llx (cbSize=0x%x)",
				(UINT64)patCurrentPd,
				sizeof(*patCurrentPd));
			MemZero(patCurrentPd, sizeof(*patCurrentPd));
		}
	}
	
	LOG_INFO(
		ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_InitPageTable: Page table initialized qwPhysicalAddress=0x%016llx",
		qwDstPml4PhysicalAddress);

	bSuccess = TRUE;
	MemCopy(phOutPageTable, &hDstPageTable, sizeof(*phOutPageTable));

lblCleanup:
	if (NULL != ptLog)
	{
		LOG_TRACE(
			ptLog,
			LOG_MODULE_PAGING,
			"<-- PAGING64_InitPageTable return bSuccess=%d",
			bSuccess);
	}
	return bSuccess;
}

BOOLEAN
PAGING64_CopyPageTable(
	INOUT PPAGE_TABLE64_HANDLE phDstPageTable,
	IN const PPAGE_TABLE64_HANDLE phSrcPageTable
)
{
	BOOLEAN bSuccess = FALSE;
	UINT64 qwPageVirtualAddress = 0;
	UINT64 qwPagePhysicalAddress = 0;
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
	UINT64 qwPdptPhysicalAddress = 0;
	PPDPTE64 patPdpt = NULL;
	UINT64 qwPdPhysicalAddress = 0;
	PPDE64 patPd = NULL;
	UINT64 qwPtPhysicalAddress = 0;
	PPTE64 patPt = NULL;
	const UINT64 qwMaxPhyAddr = MAXPHYADDR;
	VA_ADDRESS64 tDstMaxVa;
	VA_ADDRESS64 tVa;
	tVa.qwValue = 0;

	if (	(NULL == phDstPageTable)
		||	(NULL == phSrcPageTable)
		||	(0 == phDstPageTable->qwMaxVirtualAddress)
		||	(0 == phDstPageTable->qwPdptPhysicalAddress)
		||	(0 == phDstPageTable->qwPdArrayPhysicalAddress)
		||	(0 == phDstPageTable->qwPtArrayPhysicalAddress)
		||	(NULL == phDstPageTable->patPdpt)
		||	(NULL == phDstPageTable->patPdArray)
		||	(NULL == phDstPageTable->patPtArray))
	{
		// Invalid parameters
		goto lblCleanup;
	}

	LOG_TRACE(
		phDstPageTable->ptLog,
		LOG_MODULE_PAGING,
		"--> PAGING64_CopyPageTable(phDstPageTable=0x%016llx, phSrcPageTable=0x%016llx)",
		(UINT64)phDstPageTable,
		(UINT64)phSrcPageTable);

	tDstMaxVa.qwValue = phDstPageTable->qwMaxVirtualAddress;
	
	// Iterate over all present entries in the source page-table
	// and add the same mapping to the destination page-table
	//
	// NOTE: We use PAGING64_MapPhysicalToVirtual instead of paging64_MapPage
	// to create mappings in destination page-table, since it contains logic 
	// to use the eMinPageType and does boundary checks and the latter doesn't
	for (; wPml4Index <= tDstMaxVa.FourKb.Pml4eIndex; wPml4Index++)
	{
		// Skip PML4E if it's not present
		ptPml4e = (PPML4E64)&phSrcPageTable->patPml4[wPml4Index];
		if (!ptPml4e->Present)
		{
			continue;
		}

		// Get PDPT virtual address from PML4E
		qwPdptPhysicalAddress = ptPml4e->Addr << 12;
		if (!phSrcPageTable->pfnPhysicalToVirtual(qwPdptPhysicalAddress, (PUINT64)&patPdpt))
		{
			LOG_ERROR(
				phDstPageTable->ptLog,
				LOG_MODULE_PAGING,
				"PAGING64_CopyPageTable: pfnPhysicalToVirtual=0x%016llx failed "
				"on PML4E=0x%016llx qwPdptPhysicalAddress=0x%016llx",
				(UINT64)phSrcPageTable->pfnPhysicalToVirtual,
				ptPml4e->qwValue,
				qwPdptPhysicalAddress);
			goto lblCleanup;
		}

		// Iterate all present PDPTE entries in source PML4E
		for (; wPdptIndex <= tDstMaxVa.FourKb.PdpteIndex; wPdptIndex++)
		{
			// Skip PDPTE if it's not present
			ptPdpte = (PPDPTE64)&patPdpt[wPdptIndex];
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
				qwPageVirtualAddress = tVa.qwValue;

				// Make sure destination page-table doesn't already map
				// this virtual address
				if (PAGING64_IsVirtualMapped(
					phDstPageTable,
					qwPageVirtualAddress,
					PAGE_SIZE_1GB))
				{
					LOG_WARN(
						phDstPageTable->ptLog,
						LOG_MODULE_PAGING,
						"PAGING64_CopyPageTable: PAGING64_IsVirtualMapped returned "
						"TRUE (1GB) qwVirtualAddress=0x%016llx",
						qwPageVirtualAddress);
					continue;
				}

				qwPagePhysicalAddress = (ptPdpte1gb->Addr << PAGE_SHIFT_1GB) & qwMaxPhyAddr;

				ePermissions = paging64_GetPagePermissions(
					(PVOID)ptPdpte1gb,
					PAGE_TYPE_1GB);
				
				if (!paging64_GetPageMemoryType(
					phSrcPageTable,
					qwPagePhysicalAddress,
					(PVOID)ptPdpte1gb,
					PAGE_TYPE_1GB,
					&eMemType))
				{
					LOG_ERROR(
						phDstPageTable->ptLog,
						LOG_MODULE_PAGING,
						"PAGING64_CopyPageTable: paging64_GetPageMemoryType failed "
						"qwPhysicalAddress=0x%016llx, ptPdpte1gb=0x%016llx",
						qwPagePhysicalAddress,
						(UINT64)ptPdpte1gb);
					goto lblCleanup;
				}

				// Map the same addresses as the PDPTE1GB from source page-table
				// in destination page-table with same permissions and memory type
				if (!PAGING64_MapPhysicalToVirtual(
					phDstPageTable,
					qwPagePhysicalAddress,
					qwPageVirtualAddress,
					PAGE_SIZE_1GB,
					ePermissions,
					eMemType))
				{
					goto lblCleanup;
				}

				// Any PDE/PTE below this PDPTE1GB is irrelevant so just continue
				continue;
			}

			// Get PD virtual address from PDPTE
			qwPdPhysicalAddress = ptPdpte->Addr << 12;
			if (!phSrcPageTable->pfnPhysicalToVirtual(qwPdPhysicalAddress, (PUINT64)&patPd))
			{
				LOG_ERROR(
					phDstPageTable->ptLog,
					LOG_MODULE_PAGING,
					"PAGING64_CopyPageTable: pfnPhysicalToVirtual=0x%016llx failed "
					"on PDPTE=0x%016llx qwPdPhysicalAddress=0x%016llx",
					(UINT64)phSrcPageTable->pfnPhysicalToVirtual,
					ptPdpte->qwValue,
					qwPdPhysicalAddress);
				goto lblCleanup;
			}

			// Iterate all present PDE entries in source PDPTE
			for (; wPdeIndex <= tDstMaxVa.FourKb.PdeIndex; wPdeIndex++)
			{
				// Skip PDE if it's not present
				ptPde = (PPDE64)&patPd[wPdeIndex];
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
					qwPageVirtualAddress = tVa.qwValue;

					// Make sure destination page-table doesn't already map
					// this virtual address
					if (PAGING64_IsVirtualMapped(
						phDstPageTable,
						qwPageVirtualAddress,
						PAGE_SIZE_2MB))
					{
						LOG_WARN(
							phDstPageTable->ptLog,
							LOG_MODULE_PAGING,
							"PAGING64_CopyPageTable: PAGING64_IsVirtualMapped returned "
							"TRUE (2MB) qwVirtualAddress=0x%016llx",
							qwPageVirtualAddress);
						continue;
					}

					qwPagePhysicalAddress = (ptPde2mb->Addr << PAGE_SHIFT_2MB) & qwMaxPhyAddr;

					ePermissions = paging64_GetPagePermissions(
						(PVOID)ptPde2mb,
						PAGE_TYPE_2MB);

					if (!paging64_GetPageMemoryType(
						phSrcPageTable,
						qwPagePhysicalAddress,
						(PVOID)ptPde2mb,
						PAGE_TYPE_2MB,
						&eMemType))
					{
						LOG_ERROR(
							phDstPageTable->ptLog,
							LOG_MODULE_PAGING,
							"PAGING64_CopyPageTable: paging64_GetPageMemoryType failed "
							"qwPhysicalAddress=0x%016llx, ptPde2mb=0x%016llx",
							qwPagePhysicalAddress,
							(UINT64)ptPde2mb);

						goto lblCleanup;
					}

					// Map the same addresses as the PDE2MB from source page-table
					// in destination page-table with same permissions and memory type
					if (!PAGING64_MapPhysicalToVirtual(
						phDstPageTable,
						qwPagePhysicalAddress,
						qwPageVirtualAddress,
						PAGE_SIZE_2MB,
						ePermissions,
						eMemType))
					{
						goto lblCleanup;
					}

					// Any PTE below this PDE2MB is irrelevant so just continue
					continue;
				}

				// Get PT virtual address from PDE
				qwPtPhysicalAddress = ptPde->Addr << 12;
				if (!phSrcPageTable->pfnPhysicalToVirtual(qwPtPhysicalAddress, (PUINT64)&patPt))
				{
					LOG_ERROR(
						phDstPageTable->ptLog,
						LOG_MODULE_PAGING,
						"PAGING64_CopyPageTable: pfnPhysicalToVirtual=0x%016llx "
						"failed on PDE=0x%016llx qwPtPhysicalAddress=0x%016llx",
						(UINT64)phSrcPageTable->pfnPhysicalToVirtual,
						ptPdpte->qwValue,
						qwPtPhysicalAddress);
					goto lblCleanup;
				}

				// Iterate all present PTE entries in source PDE
				for (; wPteIndex <= tDstMaxVa.FourKb.PteIndex; wPteIndex++)
				{
					// Skip PTE if it's not present
					ptPte = (PPTE64)&patPt[wPteIndex];
					if (!ptPte->Present)
					{
						continue;
					}

					tVa.FourKb.Pml4eIndex = wPml4Index;
					tVa.FourKb.PdpteIndex = wPdptIndex;
					tVa.FourKb.PdeIndex = wPdeIndex;
					tVa.FourKb.PteIndex = wPteIndex;
					tVa.FourKb.Offset = 0;
					qwPageVirtualAddress = tVa.qwValue;

					// Make sure destination page-table doesn't already map
					// this virtual address
					if (PAGING64_IsVirtualMapped(
						phDstPageTable,
						qwPageVirtualAddress,
						PAGE_SIZE_4KB))
					{
						LOG_WARN(
							phDstPageTable->ptLog,
							LOG_MODULE_PAGING,
							"PAGING64_CopyPageTable: PAGING64_IsVirtualMapped returned "
							"TRUE (4KB) qwVirtualAddress=0x%016llx",
							qwPageVirtualAddress);
						continue;
					}

					qwPagePhysicalAddress = (ptPte->Addr << PAGE_SHIFT_4KB) & qwMaxPhyAddr;

					ePermissions = paging64_GetPagePermissions(
						(PVOID)ptPte,
						PAGE_TYPE_4KB);

					if (!paging64_GetPageMemoryType(
						phSrcPageTable,
						qwPagePhysicalAddress,
						(PVOID)ptPte,
						PAGE_TYPE_4KB,
						&eMemType))
					{
						LOG_ERROR(
							phDstPageTable->ptLog,
							LOG_MODULE_PAGING,
							"PAGING64_CopyPageTable: paging64_GetPageMemoryType failed "
							"qwPhysicalAddress=0x%016llx, ptPte=0x%016llx",
							qwPagePhysicalAddress,
							(UINT64)ptPte);

						goto lblCleanup;
					}

					// Map the same addresses as the PDE2MB from source page-table
					// in destination page-table with same permissions and memory type
					if (!PAGING64_MapPhysicalToVirtual(
						phDstPageTable,
						qwPagePhysicalAddress,
						qwPageVirtualAddress,
						PAGE_SIZE_4KB,
						ePermissions,
						eMemType))
					{
						goto lblCleanup;
					}
				}
			}
		}
	}

	LOG_INFO(
		phDstPageTable->ptLog,
		LOG_MODULE_PAGING,
		"PAGING64_CopyPageTable: Copied page-table qwSrcPhysical=0x%016llx to "
		"qwDstPhysical=0x%016llx",
		phSrcPageTable->qwPml4PhysicalAddress,
		phDstPageTable->qwPml4PhysicalAddress);

	bSuccess = TRUE;

lblCleanup:
	if (NULL != phSrcPageTable)
	{
		LOG_TRACE(
			phSrcPageTable->ptLog,
			LOG_MODULE_PAGING,
			"<-- PAGING64_CopyPageTable return bSuccess=%d",
			bSuccess);
	}
	return bSuccess;
}
