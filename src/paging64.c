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
* @file        paging64.c
* @section    Intel x64 Page Tables structures and constants
*            See Intel's: Software Developers Manual Vol 3A, Section 4.5 IA-32E PAGING
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
BOOLEAN
paging64_VerifyPageTableHandle(
    IN const PPAGING64_PT_HANDLE ptPageTable
)
{
    BOOLEAN bSuccess = FALSE;
    UINTN i = 0;

    if (    (NULL == ptPageTable)
        ||    (NULL == ptPageTable->ptLog))
    {
        goto lblCleanup;
    }

    // HACK: I know this is ugly, but it's also a lot easier to debug
    // Create a temporary log macro to verify page-table fields
    #ifdef __ON_FALSE_LOG_ERROR_AND_GOTO__
    #undef __ON_FALSE_LOG_ERROR_AND_GOTO__
    #endif
    #define __ON_FALSE_LOG_ERROR_AND_GOTO__(condition) \
    do \
    { \
        if (!(condition)) \
        { \
            LOG_ERROR( \
                ptPageTable->ptLog, \
                LOG_MODULE_PAGING, \
                "paging64_VerifyPageTableHandle: failed ptPageTable=0x%016llx", \
                (UINT64)ptPageTable); \
            goto lblCleanup; \
        } \
    } while (FALSE);

    // Use temporary log macro to verify all page-table fields
    __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->patPml4);
    __ON_FALSE_LOG_ERROR_AND_GOTO__(0 != ptPageTable->qwPml4PhysicalAddress);
    __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->pfnPhysicalToVirtual);

    for (; i < 8; i++)
    {
        __ON_FALSE_LOG_ERROR_AND_GOTO__(
            ptPageTable->acPatMemTypes[i] <= IA32_PAT_MEMTYPE_UCM);
    }
    
    // Skip checking variables used for editing if page-table is read-only
    if (!ptPageTable->bIsReadOnly)
    {
        __ON_FALSE_LOG_ERROR_AND_GOTO__(PAGE_TYPE_1GB >= ptPageTable->eMinPageType);
        __ON_FALSE_LOG_ERROR_AND_GOTO__(0 != ptPageTable->qwMaxVirtualAddress);

        if (ptPageTable->bIsStatic)
        {
            __ON_FALSE_LOG_ERROR_AND_GOTO__(0 != ptPageTable->qwStaticPdptPhysicalAddress);
            __ON_FALSE_LOG_ERROR_AND_GOTO__(0 != ptPageTable->qwStaticPdArrayPhysicalAddress);
            __ON_FALSE_LOG_ERROR_AND_GOTO__(0 != ptPageTable->qwStaticPtArrayPhysicalAddress);
            __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->patStaticPdpt);
            __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->patStaticPdArray);
            __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->patStaticPtArray);
        }
        else
        {
            __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->pfnAlloc);
            __ON_FALSE_LOG_ERROR_AND_GOTO__(NULL != ptPageTable->pfnFree);
        }
    }

    // Delete temporary log macro
    #undef __ON_FALSE_LOG_ERROR_AND_GOTO__

    bSuccess = TRUE;
lblCleanup:
    return bSuccess;
}

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
    INOUT PPAGING64_PT_HANDLE ptPageTable,
    IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
    IN const UINT64 qwPml4PhysicalAddress,
    IN const PLOG_HANDLE ptLog
)
{
    BOOLEAN bSuccess = FALSE;
    UINT64 qwPml4VirtualAddress = 0;
    IA32_EFER tEfer;
    IA32_PAT tPat;
    
    if (    (NULL == ptPageTable)
        ||    (NULL == pfnPhysicalToVirtual)
        ||    (NULL == ptLog))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_OpenPageTableHandle(ptPageTable=0x%016llx, "
        "pfnPhysicalToVirtual=0x%016llx, qwPml4PhysicalAddress=0x%016llx,"
        "ptLog=0x%016llx)",
        (UINT64)ptPageTable,
        (UINT64)pfnPhysicalToVirtual,
        qwPml4PhysicalAddress,
        (UINT64)ptLog);

    // Zero the handle structure and set read-only flag to avoid prohibit
    // editing of the page-table by this module
    MemZero(ptPageTable, sizeof(*ptPageTable));
    ptPageTable->bIsReadOnly = TRUE;
    ptPageTable->ptLog = ptLog;

    if (!PAGING64_IsIa32ePagingEnabled())
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_OpenPageTableHandle: 64bit paging is not enabled");
        goto lblCleanup;
    }

    // Convert physical addresses of tables to virtual addresses
    if (!(*pfnPhysicalToVirtual)(qwPml4PhysicalAddress, &qwPml4VirtualAddress))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_OpenPageTableHandle: pfnPhysicalToVirtual failed (0x%016llx)",
            (UINT64)pfnPhysicalToVirtual);
        goto lblCleanup;
    }

    // Initialize handle structure
    ptPageTable->qwPml4PhysicalAddress = qwPml4PhysicalAddress;
    ptPageTable->patPml4 = (PPML4E64)qwPml4VirtualAddress;
    ptPageTable->pfnPhysicalToVirtual = pfnPhysicalToVirtual;

    ptPageTable->bOneGbSupported = CPUID_CheckOneGbPageSupport();

    tEfer.qwValue = ASM64_Rdmsr((UINT32)MSR_CODE_IA32_EFER);
    ptPageTable->bNxBitSupported = (BOOL)tEfer.Nxe;

    ptPageTable->bMtrrSupported = (BOOL)MTRR_IsMtrrSupported();

    ptPageTable->bPatSupported = (BOOL)paging64_IsPatSupported();
    if (ptPageTable->bPatSupported)
    {
        tPat.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_PAT);
        ptPageTable->acPatMemTypes[0] = (UINT8)tPat.Pa0;
        ptPageTable->acPatMemTypes[1] = (UINT8)tPat.Pa1;
        ptPageTable->acPatMemTypes[2] = (UINT8)tPat.Pa2;
        ptPageTable->acPatMemTypes[3] = (UINT8)tPat.Pa3;
        ptPageTable->acPatMemTypes[4] = (UINT8)tPat.Pa4;
        ptPageTable->acPatMemTypes[5] = (UINT8)tPat.Pa5;
        ptPageTable->acPatMemTypes[6] = (UINT8)tPat.Pa6;
        ptPageTable->acPatMemTypes[7] = (UINT8)tPat.Pa7;
    }

    LOG_INFO(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_OpenPageTableHandle: qwPageTablePhysicalAddress=0x%016llx, "
        "bOneGbSupported=%d, bNxBitSupported=%d, bMtrrSupported=%d, bPatSupported=%d",
        ptPageTable->qwPml4PhysicalAddress,
        ptPageTable->bOneGbSupported,
        ptPageTable->bNxBitSupported,
        ptPageTable->bMtrrSupported,
        ptPageTable->bPatSupported);
    
    bSuccess = TRUE;
lblCleanup:
    if (    (NULL != ptPageTable)
        &&    (NULL != ptLog))
    {
        LOG_TRACE(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_OpenPageTableHandle return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

STATIC
BOOLEAN
paging64_GetMappedEntryAtVirtualAddress(
    IN const PPAGING64_PT_HANDLE ptPageTable,
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_GetMappedEntryAtVirtualAddress(ptPageTable=0x%016llx, "
        "qwVirtualAddress=0x%016llx, ppvEntry=0x%016llx, pePageType=0x%016llx)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        (UINT64)ppvEntry,
        (UINT64)pePageType);

    tVa.qwValue = qwVirtualAddress;

    ptPml4e = (PPML4E64)&ptPageTable->patPml4[tVa.OneGb.Pml4eIndex];
    if (!ptPml4e->Present)
    {
        LOG_WARN(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetMappedEntryAtVirtualAddress: PML4E %d not present "
            "(patPml4=0x%016llx, ptPml4e=0x%016llx)",
            tVa.OneGb.Pml4eIndex,
            (UINT64)ptPageTable->patPml4,
            (UINT64)ptPml4e);
        *pePageType = PAGE_TYPE_1GB;
        goto lblCleanup;
    }

    // Get PDPT virtual address from PML4E
    qwPdptPhysicalAddress = ptPml4e->Addr << 12;
    if (!ptPageTable->pfnPhysicalToVirtual(qwPdptPhysicalAddress, (PUINT64)&patPdpt))
    {
        goto lblCleanup;
    }

    // Get PDPTE by index from virtual address
    ptPdpte = (PPDPTE64)&patPdpt[tVa.OneGb.PdpteIndex];
    if (!ptPdpte->Present)
    {
        LOG_WARN(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetMappedEntryAtVirtualAddress: PDPTE %d not present "
            "(patPdpt=0x%016llx, ptPdpte=0x%016llx)",
            tVa.TwoMb.PdpteIndex,
            (UINT64)patPdpt,
            (UINT64)ptPdpte);
        *pePageType = PAGE_TYPE_1GB;
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
    if (!ptPageTable->pfnPhysicalToVirtual(qwPdPhysicalAddress, (PUINT64)&patPd))
    {
        goto lblCleanup;
    }

    // PDPTE points to PDE
    ptPde = (PPDE64)&patPd[tVa.TwoMb.PdeIndex];
    if (!ptPde->Present)
    {
        LOG_WARN(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetMappedEntryAtVirtualAddress: PDE %d not present "
            "(patPd=0x%016llx, ptPde=0x%016llx)",
            tVa.FourKb.PdeIndex,
            (UINT64)patPd,
            (UINT64)ptPde);
        *pePageType = PAGE_TYPE_2MB;
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
    if (!ptPageTable->pfnPhysicalToVirtual(qwPtPhysicalAddress, (PUINT64)&patPt))
    {
        goto lblCleanup;
    }
    
    // Get PTE by index from virtual address
    ptPte = (PPTE64)(&patPt[tVa.FourKb.PteIndex]);
    if (!ptPte->Present)
    {
        LOG_WARN(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetMappedEntryAtVirtualAddress: PTE %d not present "
            "(patPt=0x%016llx, ptPte=0x%016llx)",
            tVa.FourKb.PteIndex,
            (UINT64)patPt,
            (UINT64)ptPte);
        *pePageType = PAGE_TYPE_4KB;
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
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetMappedEntryAtVirtualAddress: pvEntry=0x%016llx, "
            "qwEntry=0x%016llx, ePageType=%d",
            (UINT64)*ppvEntry,
            *((PUINT64)*ppvEntry),
            *pePageType);
    }

    LOG_TRACE(
        ptPageTable->ptLog,
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
    IN const PPAGING64_PT_HANDLE ptPageTable,
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_GetPageMemoryType(ptPageTable=0x%016llx, "
        "qwPhysicalAddress=0x%016llx, pvEntry=0x%016llx, ePageType=%d, "
        "peMemType=0x%016llx)",
        (UINT64)ptPageTable,
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
        |    (bPcd << 1)
        |    (bPat << 2));

    // Determine the PAT memory type according to the flags
    if (ptPageTable->bPatSupported)
    {
        // Vol 3A, Table 11-11. Selection of PAT Entries with PAT, PCD, and PWT Flags
        ePatMemType = ptPageTable->acPatMemTypes[cPatIndex];

        LOG_DEBUG(
            ptPageTable->ptLog,
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
                ptPageTable->ptLog,
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
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetPageMemoryType: PAT isn't supported, ePatMemType=%d from index=%d",
            ePatMemType,
            cPatIndex);
    }

    // If MTRR is supported, get the memory type for the physical address from it
    if (ptPageTable->bMtrrSupported)
    {
        if (!MTRR_GetMemTypeForPhysicalAddress(
            qwPhysicalAddress,
            FALSE,
            &eMtrrMemType))
        {
            LOG_ERROR(
                ptPageTable->ptLog,
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
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_GetPageMemoryType: eEffectiveMemType=%x, ePatMemType=%x, "
            "eMtrrMemType=%x",
            eEffectiveMemType,
            ePatMemType,
            eMtrrMemType);
    }

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_GetPageMemoryType return bSuccess=%d",
        bSuccess);
    return bSuccess;
}

BOOLEAN
PAGING64_VirtualToPhysical(
    IN const PPAGING64_PT_HANDLE ptPageTable,
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

    if (    (NULL == ptPageTable)
        ||    (NULL == pqwPhysicalAddress)
        ||    (NULL == pePageType)
        ||    (NULL == pePagePermissions)
        ||    (NULL == peMemType))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_VirtualToPhysical(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx,"
        "pqwPhysicalAddress=0x%016llx, pePageType=0x%016llx, pePagePermissions=0x%016llx, "
        "peMemType=0x%016llx)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        (UINT64)pqwPhysicalAddress,
        (UINT64)pePageType,
        (UINT64)pePagePermissions,
        (UINT64)peMemType);

    tVa.qwValue = qwVirtualAddress;

    if (!paging64_GetMappedEntryAtVirtualAddress(
        ptPageTable,
        qwVirtualAddress,
        &pvEntry,
        &ePageType))
    {
        // Virtual address isn't mapped in page-table
        LOG_WARN(
            ptPageTable->ptLog,
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
            |    (tVa.OneGb.Offset & PAGE_OFFSET_MASK_1GB));
        break;
    case PAGE_TYPE_2MB:
        ptPde2mb = (PPDE2MB64)pvEntry;
        qwPhysicalAddress = (
                ((ptPde2mb->Addr << PAGE_SHIFT_2MB) & qwMaxPhyAddr)
            |    (tVa.TwoMb.Offset & PAGE_OFFSET_MASK_2MB));
        break;
    case PAGE_TYPE_4KB:
        ptPte = (PPTE64)pvEntry;
        qwPhysicalAddress = (
                ((ptPte->Addr << PAGE_SHIFT_4KB) & qwMaxPhyAddr)
            |    (tVa.FourKb.Offset & PAGE_OFFSET_MASK_4KB));
        break;
    default:
        // Shouldn't happen
        goto lblCleanup;
    }

    if (!paging64_GetPageMemoryType(
        ptPageTable,
        qwPhysicalAddress,
        pvEntry,
        ePageType,
        &eMemType))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_VirtualToPhysical: ptPageTable=0x%016llx, qwVirtualAddres=0x%016llx "
        "maps qwPhysicalAddres=0x%016llx, ePageType=%d, ePermissions=0x%x, eMemType=%d",
        (UINT64)ptPageTable,
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

    if (NULL != ptPageTable)
    {
        LOG_TRACE(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_VirtualToPhysical return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

BOOLEAN
PAGING64_VirtualToPhysicalFromCR3(
    IN const UINT64 qwVirtualAddress,
    IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
    IN const PLOG_HANDLE ptLog,
    OUT PUINT64 pqwPhysicalAddress,
    OUT PPAGE_TYPE64 pePageType,
    OUT PPAGE_PERMISSION pePagePermissions,
    OUT PIA32_PAT_MEMTYPE peMemType
)
{
    BOOLEAN bSuccess = FALSE;
    PAGING64_PT_HANDLE tCurrentPageTable;
    UINT64 qwCurrentPml4PhysicalAddress = 0;

    if (    (0 == qwVirtualAddress)
        ||    (NULL == pfnPhysicalToVirtual)
        ||    (NULL == ptLog)
        ||    (NULL == pqwPhysicalAddress)
        ||    (NULL == pePageType)
        ||    (NULL == pePagePermissions)
        ||    (NULL == peMemType))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_VirtualToPhysicalFromCR3(qwVirtualAddress=0x%016llx, "
        "pfnPhysicalToVirtual=0x%016llx, ptLog=0x%016llx, pqwPhysicalAddress=0x%016llx, "
        "pePageType=0x%016llx, pePagePermissions=0x%016llx, peMemType=0x%016llx)",
        qwVirtualAddress,
        (UINT64)pfnPhysicalToVirtual,
        (UINT64)ptLog,
        (UINT64)pqwPhysicalAddress,
        (UINT64)pePageType,
        (UINT64)pePagePermissions,
        (UINT64)peMemType);

    qwCurrentPml4PhysicalAddress = ASM64_ReadCr3();
    if (!PAGING64_OpenPageTableHandle(
        &tCurrentPageTable,
        pfnPhysicalToVirtual,
        qwCurrentPml4PhysicalAddress,
        ptLog))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_VirtualToPhysicalFromCurrentPageTable: "
            "PAGING64_OpenPageTableHandle failed on CR3=0x%016llx",
            qwCurrentPml4PhysicalAddress);
        goto lblCleanup;
    }

    // Find the physical address of the page-table to initialize
    if (!PAGING64_VirtualToPhysical(
        &tCurrentPageTable,
        (UINT64)qwVirtualAddress,
        pqwPhysicalAddress,
        pePageType,
        pePagePermissions,
        peMemType))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_VirtualToPhysicalFromCurrentPageTable: "
            "PAGING64_VirtualToPhysical failed CR3=0x%016llx, "
            "qwVirtualAddress=0x%016llx",
            qwCurrentPml4PhysicalAddress,
            (UINT64)qwVirtualAddress);
        goto lblCleanup;
    }

    bSuccess = TRUE;

lblCleanup:
    if (NULL != ptLog)
    {
        LOG_TRACE(
            ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_VirtualToPhysicalFromCurrentPageTable return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

BOOLEAN
PAGING64_IsVirtualMapped(
    IN const PPAGING64_PT_HANDLE ptPageTable,
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

    if (    (NULL == ptPageTable)
        ||    (0 == cbSize))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_IsVirtualMapped(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
        "cbSize=%d)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        cbSize);

    // Check all pages in the virtual address range are mapped
    while(cbCurrentSize < cbSize)
    {
        if (!PAGING64_VirtualToPhysical(
            ptPageTable,
            qwCurrentVa,
            &qwPhysicalAddress,
            &ePageType,
            &ePagePermissions,
            &eMemType))
        {
            LOG_WARN(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "PAGING64_IsVirtualMapped: PAGING64_VirtualToPhysical failed "
                "qwVirtualAddres=0x%016llx",
                qwCurrentVa);
            goto lblCleanup;
        }

        // Add current page size to current virtual address and size
        qwPageSize = paging64_PageSizeByType(ePageType);
        cbCurrentSize += qwPageSize;
        qwCurrentVa += qwPageSize;
    }

    // All pages are mapped
    LOG_DEBUG(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_IsVirtualMapped: qwVirtualAddres=0x%016llx, cbSize=%d mapped!",
        qwVirtualAddress,
        cbSize);

    bSuccess = TRUE;

lblCleanup:
    if (NULL != ptPageTable)
    {
        LOG_TRACE(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_IsVirtualMapped return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

STATIC
BOOLEAN
paging64_IsPdptTableEmpty(
    IN const PPDPTE64 patPdpt
)
{
    PPDPTE64 ptCurrentPdpte = patPdpt;
    UINTN i = 0;

    for (; i < PAGING64_PDPTE_COUNT; i++, ptCurrentPdpte++)
    {
        if (ptCurrentPdpte->Present)
        {
            return FALSE;
        }
    }
    return TRUE;
}

STATIC
BOOLEAN
paging64_IsPdTableEmpty(
    IN const PPDE64 patPd
)
{
    PPDE64 ptCurrentPde = patPd;
    UINTN i = 0;

    for (; i < PAGING64_PDE_COUNT; i++, ptCurrentPde++)
    {
        if (ptCurrentPde->Present)
        {
            return FALSE;
        }
    }
    return TRUE;
}

STATIC
BOOLEAN
paging64_IsPtTableEmpty(
    IN const PPTE64 patPt
)
{
    PPTE64 ptCurrentPte = patPt;
    UINTN i = 0;

    for (; i < PAGING64_PDE_COUNT; i++, ptCurrentPte++)
    {
        if (ptCurrentPte->Present)
        {
            return FALSE;
        }
    }
    return TRUE;
}

STATIC
VOID
paging64_CollectGarbageFromPdTable(
    IN PPAGING64_PT_HANDLE ptPageTable,
    IN PPDE64 patPd
)
{
    UINTN i = 0;
    UINT64 qwPtPhysicalAddress = 0;
    PPDE64 ptCurrentPde = patPd;
    PPTE64 patPt = NULL;

    // Free empty PT tables pointed to by PDEs in current PD table
    for (i = 0; i < PAGING64_PDE_COUNT; i++, ptCurrentPde++)
    {
        if (ptCurrentPde->Present)
        {
            // Get PT table virtual address
            qwPtPhysicalAddress = ptCurrentPde->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPtPhysicalAddress,
                (PUINT64)&patPt))
            {
                break;
            }

            if (paging64_IsPtTableEmpty(patPt))
            {
                // Set PDE as non-present and free the empty PT table
                ptCurrentPde->Present = FALSE;
                ptCurrentPde->Addr = NULL;
                ptPageTable->pfnFree(patPt);
                patPt = NULL;
                
            }
        }
    }
}

STATIC
VOID
paging64_CollectGarbageFromPdptTable(
    IN PPAGING64_PT_HANDLE ptPageTable,
    IN PPDPTE64 patPdpt
)
{
    UINTN i = 0;
    UINT64 qwPdPhysicalAddress = 0;
    PPDPTE64 ptCurrentPdpte = patPdpt;
    PPDE64 patPd = NULL;

    // Find all present PD tables and cleanup garbage from them
    for (i = 0; i < PAGING64_PDPTE_COUNT; i++, ptCurrentPdpte++)
    {
        if (ptCurrentPdpte->Present)
        {
            // Get PD table virtual address
            qwPdPhysicalAddress = ptCurrentPdpte->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPdPhysicalAddress,
                (PUINT64)&patPd))
            {
                break;
            }

            // Collect garbage from PD table, and if it's empty afterwards
            // then free it from heap
            paging64_CollectGarbageFromPdTable(ptPageTable, patPd);
            if (paging64_IsPdTableEmpty(patPd))
            {
                // Set PDPTE as non-present and free the empty PD table
                ptCurrentPdpte->Present = FALSE;
                ptCurrentPdpte->Addr = NULL;
                ptPageTable->pfnFree(patPd);
                patPd = NULL;
            }
        }
    }
}

STATIC
VOID
paging64_CollectGarabageFromPml4Table(
    IN PPAGING64_PT_HANDLE ptPageTable,
    IN PPML4E64 patPml4
)
{
    UINTN i = 0;
    UINT64 qwPdptPhysicalAddress = 0;
    PPML4E64 ptCurrentPml4e = patPml4;
    PPDPTE64 patPdpt = NULL;

    // Find all present PDPT tables and cleanup garbage from them
    for (i = 0; i < PAGING64_PML4E_COUNT; i++, ptCurrentPml4e++)
    {
        if (ptCurrentPml4e->Present)
        {
            // Get PDPT table virtual address
            qwPdptPhysicalAddress = ptCurrentPml4e->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPdptPhysicalAddress,
                (PUINT64)&patPdpt))
            {
                break;
            }

            // Collect garbage from PDPT table, and if it's empty afterwards
            // then free it from heap
            paging64_CollectGarbageFromPdptTable(ptPageTable, patPdpt);
            if (paging64_IsPdptTableEmpty(patPdpt))
            {
                // Set PML4E as non-present and free the empty PDPT table
                ptCurrentPml4e->Present = FALSE;
                ptCurrentPml4e->Addr = NULL;
                ptPageTable->pfnFree(patPdpt);
                patPdpt = NULL;
            }
        }
    }
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

    // Zero out the entire entry
    switch (ePageType)
    {
    case PAGE_TYPE_1GB:
        ptPdtpe1gb = (PPDPTE1G64)pvEntry;
        ptPdtpe1gb->qwValue = 0;
        break;
    case PAGE_TYPE_2MB:
        ptPde2mb = (PPDE2MB64)pvEntry;
        ptPde2mb->qwValue = 0;
        break;
    case PAGE_TYPE_4KB:
        ptPte = (PPTE64)pvEntry;
        ptPte->qwValue = 0;
        break;
    }
}

VOID
PAGING64_UnmapVirtual(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
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

    if (    (!paging64_VerifyPageTableHandle(ptPageTable))
        ||    (ptPageTable->bIsReadOnly)
        ||    (NULL == qwVirtualAddress)
        ||    (0 == cbSize))
    {
        // Invalid parameters
        return;
    }

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_UnmapVirtual(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
        "cbSize=%d)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        cbSize);
    LOCK_SpinlockAcquire(&ptPageTable->tEditLock);

    // Unmap all pages in requested range - best effort
    while (cbCurrentSize < cbSize)
    {
        bEntryMapped = paging64_GetMappedEntryAtVirtualAddress(
            ptPageTable,
            qwCurrentVa,
            &pvEntry,
            &ePageType);
        if (bEntryMapped)
        {
            LOG_DEBUG(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "PAGING64_UnmapVirtual: Unmapping pvEntry=0x%016llx, "
                "ePageType=%d",
                (UINT64)pvEntry,
                ePageType);

            // Page is mapped, unmap it
            paging64_UnmapPage(pvEntry, ePageType);

            // Add current page size to current virtual address and size
            qwPageSize = paging64_PageSizeByType(ePageType);
            cbCurrentSize += qwPageSize;
            qwCurrentVa += qwPageSize;
        }

        cbCurrentSize += PAGE_SIZE_4KB;
        qwCurrentVa += PAGE_SIZE_4KB;
    }

    if (!ptPageTable->bIsStatic)
    {
        // Cleanup empty-tables
        paging64_CollectGarabageFromPml4Table(
            ptPageTable,
            ptPageTable->patPml4);
    }
    
    LOCK_SpinlockRelease(&ptPageTable->tEditLock);
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- PAGING64_UnmapVirtual");
}

STATIC
BOOLEAN
paging64_GetPatFlagsForMemType(
    IN const PPAGING64_PT_HANDLE ptPageTable,
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_GetPatFlagsForMemType(ptPageTable=0x%016llx, eMemType=%d, "
        "pbPwtFlag=0x%016llx, pbPcdFlag=0x%016llx, pbPatFlag=0x%016llx)",
        (UINT64)ptPageTable,
        eMemType,
        (UINT64)pbPwtFlag,
        (UINT64)pbPcdFlag,
        (UINT64)pbPatFlag);

    if (ptPageTable->bPatSupported)
    {
        //! Vol 3A, Table 11-11. Selection of PAT Entries with PAT, PCD, and PWT Flags
        // Iterate over all PAT entries from MSR and see which one contains
        // the given memory type
        for (; ucPatIndex < ARRAYSIZE(ptPageTable->acPatMemTypes); ucPatIndex++)
        {
            ePatMemType = (IA32_PAT_MEMTYPE)ptPageTable->acPatMemTypes[ucPatIndex];
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_GetPatFlagsForMemType return bSuccess=%d (Pwt=%d, Pcd=%d, Pat=%d)",
        bSuccess,
        *pbPwtFlag,
        *pbPcdFlag,
        *pbPatFlag);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_GetPdpte(
    IN const PPAGING64_PT_HANDLE ptPageTable,
    IN const VA_ADDRESS64 tVa,
    IN const PPML4E64 ptPml4e,
    OUT PUINT64 pqwPdptPhysicalAddress,
    OUT PPDPTE64 *pptPdpte
)
{
    BOOLEAN bSuccess = FALSE;
    PPDPTE64 patPdpt = NULL;
    PPDPTE64 ptPdpte = NULL;
    UINT64 qwPdptPhysicalAddress = 0;
    PAGE_TYPE64 ePageType = ~0;
    PAGE_PERMISSION ePagePermissions = 0;
    IA32_PAT_MEMTYPE eMemType = IA32_PAT_MEMTYPE_INVALID;

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_GetPdpte(ptPageTable=0x%016llx, tVa=0x%016llx, "
        "ptPml4e=0x%016llx, pqwPdptPhysicalAddress=0x%016llx, pptPdpte=0x%016llx)",
        (UINT64)ptPageTable,
        tVa.qwValue,
        (UINT64)ptPml4e,
        (UINT64)pqwPdptPhysicalAddress,
        (UINT64)pptPdpte);

    if (ptPageTable->bIsStatic)
    {
        // Get PDPT virtual and physical addresses from static page-table
        patPdpt = ptPageTable->patStaticPdpt;
        qwPdptPhysicalAddress = ptPageTable->qwStaticPdptPhysicalAddress;
    }
    else
    {
        if (!ptPml4e->Present)
        {
            // PDPT table doesn't exist, allocate it
            patPdpt = (PPDPTE64)ptPageTable->pfnAlloc(PAGING64_TABLE_SIZE);
            if (NULL == patPdpt)
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPdpte: pfnAlloc=0x%016llx failed",
                    (UINT64)ptPageTable->pfnAlloc);
                goto lblCleanup;
            }

            // Get PDPT table physical address from current page-table in CR3
            // NOTE:    We assume ptPageTable->pfnPhysicalToVirtual is correct for
            //            current page-table as well
            if (!PAGING64_VirtualToPhysicalFromCR3(
                (UINT64)patPdpt,
                ptPageTable->pfnPhysicalToVirtual,
                ptPageTable->ptLog,
                &qwPdptPhysicalAddress,
                &ePageType,
                &ePagePermissions,
                &eMemType))
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPdpte: PAGING64_VirtualToPhysicalFromCR3 failed");
                goto lblCleanup;
            }

        }
        else
        {
            // Get PDPT table virtual address from PML4E
            qwPdptPhysicalAddress = ptPml4e->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPdptPhysicalAddress,
                (PUINT64)&patPdpt))
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPdpte: pfnPhysicalToVirtual=0x%016llx failed",
                    (UINT64)ptPageTable->pfnPhysicalToVirtual);
                goto lblCleanup;
            }
        }
    }

    // Get PDPTE from PDPT table using index from virtual address
    ptPdpte = (PPDPTE64)&patPdpt[tVa.OneGb.PdpteIndex];

    *pqwPdptPhysicalAddress = qwPdptPhysicalAddress;
    *pptPdpte = ptPdpte;
    bSuccess = TRUE;

lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_GetPdpte return bSuccess=%d",
        bSuccess);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_GetPde(
    IN const PPAGING64_PT_HANDLE ptPageTable,
    IN const VA_ADDRESS64 tVa,
    IN const PPDPTE64 ptPdpte,
    OUT PUINT64 pqwPdPhysicalAddress,
    OUT PPDE64 *pptPde
)
{
    BOOLEAN bSuccess = FALSE;
    PPDE64 patPd = NULL;
    PPDE64 ptPde = NULL;
    UINT64 qwPdPhysicalAddress = 0;
    UINT64 qwPdOffset = 0;
    PAGE_TYPE64 ePageType = ~0;
    PAGE_PERMISSION ePagePermissions = 0;
    IA32_PAT_MEMTYPE eMemType = IA32_PAT_MEMTYPE_INVALID;

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_GetPde(ptPageTable=0x%016llx, tVa=0x%016llx, "
        "ptPdpte=0x%016llx, pqwPdptPhysicalAddress=0x%016llx, pptPdpte=0x%016llx)",
        (UINT64)ptPageTable,
        tVa.qwValue,
        (UINT64)ptPdpte,
        (UINT64)pqwPdPhysicalAddress,
        (UINT64)pptPde);

    if (ptPageTable->bIsStatic)
    {
        // Get PD virtual and physical addresses from static page-table
        patPd = ptPageTable->patStaticPdArray[tVa.TwoMb.PdpteIndex];
        qwPdOffset = tVa.TwoMb.PdpteIndex * sizeof(*ptPageTable->patStaticPdArray);
        qwPdPhysicalAddress = ptPageTable->qwStaticPdArrayPhysicalAddress + qwPdOffset;
    }
    else
    {
        if (!ptPdpte->Present)
        {
            // PD table doesn't exist, allocate it
            patPd = (PPDE64)ptPageTable->pfnAlloc(PAGING64_TABLE_SIZE);
            if (NULL == patPd)
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPde: pfnAlloc=0x%016llx failed",
                    (UINT64)ptPageTable->pfnAlloc);
                goto lblCleanup;
            }

            // Get PDPT table physical address from current page-table in CR3
            // NOTE:    We assume ptPageTable->pfnPhysicalToVirtual is correct for 
            //            current page-table as well
            if (!PAGING64_VirtualToPhysicalFromCR3(
                (UINT64)patPd,
                ptPageTable->pfnPhysicalToVirtual,
                ptPageTable->ptLog,
                &qwPdPhysicalAddress,
                &ePageType,
                &ePagePermissions,
                &eMemType))
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPde: PAGING64_VirtualToPhysicalFromCR3 failed");
                goto lblCleanup;
            }
        }
        else
        {
            // Get PD table virtual address from PDPTE
            qwPdPhysicalAddress = ptPdpte->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPdPhysicalAddress,
                (PUINT64)&patPd))
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPde: pfnPhysicalToVirtual=0x%016llx failed",
                    (UINT64)ptPageTable->pfnPhysicalToVirtual);
                goto lblCleanup;
            }
        }
    }

    // Get PDE from PD table using index from virtual address
    ptPde = &patPd[tVa.TwoMb.PdeIndex];

    *pqwPdPhysicalAddress = qwPdPhysicalAddress;
    *pptPde = ptPde;
    bSuccess = TRUE;

lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_GetPde return bSuccess=%d",
        bSuccess);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_GetPte(
    IN const PPAGING64_PT_HANDLE ptPageTable,
    IN const VA_ADDRESS64 tVa,
    IN const PPDE64 ptPde,
    OUT PUINT64 pqwPtPhysicalAddress,
    OUT PPTE64 *pptPte
)
{
    BOOLEAN bSuccess = FALSE;
    PPTE64 patPt = NULL;
    PPTE64 ptPte = NULL;
    UINT64 qwPtPhysicalAddress = 0;
    UINT64 qwPtOffset = 0;
    PAGE_TYPE64 ePageType = ~0;
    PAGE_PERMISSION ePagePermissions = 0;
    IA32_PAT_MEMTYPE eMemType = IA32_PAT_MEMTYPE_INVALID;

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_GetPte(ptPageTable=0x%016llx, tVa=0x%016llx, "
        "ptPde=0x%016llx, pqwPdptPhysicalAddress=0x%016llx, pptPdpte=0x%016llx)",
        (UINT64)ptPageTable,
        tVa.qwValue,
        (UINT64)ptPde,
        (UINT64)pqwPtPhysicalAddress,
        (UINT64)pptPte);

    if (ptPageTable->bIsStatic)
    {
        // Get PD virtual and physical addresses from static page-table
        patPt = ptPageTable->patStaticPtArray[tVa.FourKb.PdpteIndex][tVa.FourKb.PdeIndex];
        qwPtOffset = tVa.FourKb.PdeIndex * sizeof(*ptPageTable->patStaticPtArray);
        qwPtPhysicalAddress = ptPageTable->qwStaticPtArrayPhysicalAddress + qwPtOffset;
    }
    else
    {
        if (!ptPde->Present)
        {
            // PD table doesn't exist, allocate it
            patPt = (PPTE64)ptPageTable->pfnAlloc(PAGING64_TABLE_SIZE);
            if (NULL == patPt)
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPte: pfnAlloc=0x%016llx failed",
                    (UINT64)ptPageTable->pfnAlloc);
                goto lblCleanup;
            }

            // Get PDPT table physical address from current page-table in CR3
            // NOTE:    We assume ptPageTable->pfnPhysicalToVirtual is correct for 
            //            current page-table as well
            if (!PAGING64_VirtualToPhysicalFromCR3(
                (UINT64)patPt,
                ptPageTable->pfnPhysicalToVirtual,
                ptPageTable->ptLog,
                &qwPtPhysicalAddress,
                &ePageType,
                &ePagePermissions,
                &eMemType))
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPte: PAGING64_VirtualToPhysicalFromCR3 failed");
                goto lblCleanup;
            }

        }
        else
        {
            // Get PT table virtual address from PDE
            qwPtPhysicalAddress = ptPde->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPtPhysicalAddress,
                (PUINT64)&patPt))
            {
                LOG_ERROR(
                    ptPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "paging64_GetPte: pfnPhysicalToVirtual=0x%016llx failed",
                    (UINT64)ptPageTable->pfnPhysicalToVirtual);
                goto lblCleanup;
            }
        }
    }

    // Get PTE from PT table using index from virtual address
    ptPte = &patPt[tVa.FourKb.PteIndex];

    *pqwPtPhysicalAddress = qwPtPhysicalAddress;
    *pptPte = ptPte;
    bSuccess = TRUE;

lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_GetPte return bSuccess=%d",
        bSuccess);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_SetPdpte1gb(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
    IN const UINT64 qwVirtualAddress,
    IN const UINT64 qwPhysicalAddressToMap,
    IN const PAGE_PERMISSION ePagePermission,
    IN const BOOLEAN bPwtFlag,
    IN const BOOLEAN bPcdFlag,
    IN const BOOLEAN bPatFlag
)
{
    BOOLEAN bSuccess = FALSE;
    PPML4E64 ptPml4e = NULL;
    PPDPTE1G64 ptPdpte1gb = NULL;
    BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
    BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
    BOOLEAN bNoExecute = (
            ptPageTable->bNxBitSupported
        &&    (0 == (ePagePermission & PAGE_EXECUTE)));
    VA_ADDRESS64 tVa;
    UINT64 qwPdptPhysicalAddress = 0;

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_SetPdpte1gb(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
        "qwPhysicalAddressToMap=0x%016llx, ePagePermission=0x%lx, bPwtFlag=%d, "
        "bPcdFlag=%d, bPatFlag=%d)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        qwPhysicalAddressToMap,
        ePagePermission,
        bPwtFlag,
        bPcdFlag,
        bPatFlag);

    tVa.qwValue = qwVirtualAddress;

    // Get PML4E from PML4 table using index from virtual address
    ptPml4e = (PPML4E64)&ptPageTable->patPml4[tVa.OneGb.Pml4eIndex];

    // Get PDPT-table physical address and the PDPTE virtual address
    if (!paging64_GetPdpte(
        ptPageTable,
        tVa,
        ptPml4e,
        &qwPdptPhysicalAddress,
        (PPDPTE64 *)&ptPdpte1gb))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_SetPdpte1gb: paging64_GetPdpte failed");
        goto lblCleanup;
    }

    // Initialize PML4E to point to PDPTE
    MemFill(ptPml4e, 0, sizeof(*ptPml4e));
    ptPml4e->Present = TRUE;
    ptPml4e->Addr = qwPdptPhysicalAddress >> 12;
    ptPml4e->Us = bSupervisor;
    ptPml4e->Rw = bWrite;
    ptPml4e->Nx = bNoExecute;
    ptPml4e->Pwt = bPwtFlag;
    ptPml4e->Pcd = bPcdFlag;

    // Initialize PDPTE to point to physical address
    MemFill(ptPdpte1gb, 0, sizeof(*ptPdpte1gb));
    ptPdpte1gb->Present = TRUE;
    ptPdpte1gb->PageSize = 1;
    ptPdpte1gb->Addr = qwPhysicalAddressToMap >> PAGE_SHIFT_1GB;
    ptPdpte1gb->Us = bSupervisor;
    ptPdpte1gb->Rw = bWrite;
    ptPdpte1gb->Nx = bNoExecute;
    ptPdpte1gb->Pwt = bPwtFlag;
    ptPdpte1gb->Pcd = bPcdFlag;
    ptPdpte1gb->Pat = bPatFlag;

    bSuccess = TRUE;
lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_SetPdpte1gb return bSucces=%d",
        bSuccess);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_SetPde2mb(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
    IN const UINT64 qwVirtualAddress,
    IN const UINT64 qwPhysicalAddressToMap,
    IN const PAGE_PERMISSION ePagePermission,
    IN const BOOLEAN bPwtFlag,
    IN const BOOLEAN bPcdFlag,
    IN const BOOLEAN bPatFlag
)
{
    BOOLEAN bSuccess = FALSE;
    PPML4E64 ptPml4e = NULL;
    PPDPTE64 ptPdpte = NULL;
    PPDE2MB64 ptPde2mb = NULL;
    UINT64 qwPdptPhysicalAddress = 0;
    UINT64 qwPdPhysicalAddress = 0;
    BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
    BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
    BOOLEAN bNoExecute = (
            ptPageTable->bNxBitSupported
        &&    (0 == (ePagePermission & PAGE_EXECUTE)));
    VA_ADDRESS64 tVa;

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_SetPde2mb(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
        "qwPhysicalAddressToMap=0x%016llx, ePagePermission=0x%lx, bPwtFlag=%d, "
        "bPcdFlag=%d, bPatFlag=%d)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        qwPhysicalAddressToMap,
        ePagePermission,
        bPwtFlag,
        bPcdFlag,
        bPatFlag);

    tVa.qwValue = qwVirtualAddress;

    // Get pointers to all relevant page-table entries for page
    ptPml4e = (PPML4E64)&ptPageTable->patPml4[tVa.TwoMb.Pml4eIndex];

    // Get PDPT-table physical address and the PDPTE virtual address
    if (!paging64_GetPdpte(
        ptPageTable,
        tVa,
        ptPml4e,
        &qwPdptPhysicalAddress,
        &ptPdpte))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_SetPde2mb: paging64_GetPdpte failed");
        goto lblCleanup;
    }

    // Get PD-table physical address and the PDE virtual address
    if (!paging64_GetPde(
        ptPageTable,
        tVa,
        ptPdpte,
        &qwPdPhysicalAddress,
        (PPDE64 *)&ptPde2mb))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_SetPde2mb: paging64_GetPde failed");
        goto lblCleanup;
    }

    // Initialize PML4E to point to PDPTE
    MemFill(ptPml4e, 0, sizeof(*ptPml4e));
    ptPml4e->Present = 1;
    ptPml4e->Addr = qwPdptPhysicalAddress >> 12;
    ptPml4e->Us = bSupervisor;
    ptPml4e->Rw = bWrite;
    ptPml4e->Nx = bNoExecute;
    ptPml4e->Pwt = bPwtFlag;
    ptPml4e->Pcd = bPcdFlag;

    // Initialize PDPTE to point to PDE
    MemFill(ptPdpte, 0, sizeof(*ptPdpte));
    ptPdpte->Present = 1;
    ptPdpte->Addr = qwPdPhysicalAddress >> 12;
    ptPdpte->Us = bSupervisor;
    ptPdpte->Rw = bWrite;
    ptPdpte->Nx = bNoExecute;
    ptPdpte->Pwt = bPwtFlag;
    ptPdpte->Pcd = bPcdFlag;

    // Initialize PDE to point to physical address
    MemFill(ptPde2mb, 0, sizeof(*ptPde2mb));
    ptPde2mb->Present = 1;
    ptPde2mb->PageSize = 1;
    ptPde2mb->Addr = qwPhysicalAddressToMap >> PAGE_SHIFT_2MB;
    ptPde2mb->Us = bSupervisor;
    ptPde2mb->Rw = bWrite;
    ptPde2mb->Nx = bNoExecute;
    ptPde2mb->Pwt = bPwtFlag;
    ptPde2mb->Pcd = bPcdFlag;
    ptPde2mb->Pat = bPatFlag;
    
    bSuccess = TRUE;

lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_SetPde2mb return bSucces=%d",
        bSuccess);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_SetPte(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
    IN const UINT64 qwVirtualAddress,
    IN const UINT64 qwPhysicalAddressToMap,
    IN const PAGE_PERMISSION ePagePermission,
    IN const BOOLEAN bPwtFlag,
    IN const BOOLEAN bPcdFlag,
    IN const BOOLEAN bPatFlag
)
{
    BOOLEAN bSuccess = FALSE;
    PPML4E64 ptPml4e = NULL;
    PPDPTE64 ptPdpte = NULL;
    PPDE64 ptPde = NULL;
    PPTE64 ptPte = NULL;
    UINT64 qwPdptPhysicalAddress = 0;
    UINT64 qwPdPhysicalAddress = 0;
    UINT64 qwPtPhysicalAddress = 0;
    BOOLEAN bSupervisor = (0 != (ePagePermission & PAGE_SUPERVISOR));
    BOOLEAN bWrite = (0 != (ePagePermission & PAGE_WRITE));
    BOOLEAN bNoExecute = (
            ptPageTable->bNxBitSupported
        &&    (0 == (ePagePermission & PAGE_EXECUTE)));
    VA_ADDRESS64 tVa;

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_SetPte(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
        "qwPhysicalAddressToMap=0x%016llx, ePagePermission=0x%lx, bPwtFlag=%d, "
        "bPcdFlag=%d, bPatFlag=%d)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        qwPhysicalAddressToMap,
        ePagePermission,
        bPwtFlag,
        bPcdFlag,
        bPatFlag);

    tVa.qwValue = qwVirtualAddress;

    // Get pointers to all relevant page-table entries for page
    ptPml4e = (PPML4E64)&ptPageTable->patPml4[tVa.FourKb.Pml4eIndex];
    
    // Get PDPT-table physical address and the PDPTE virtual address
    if (!paging64_GetPdpte(
        ptPageTable,
        tVa,
        ptPml4e,
        &qwPdptPhysicalAddress,
        &ptPdpte))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_SetPte: paging64_GetPdpte failed");
        goto lblCleanup;
    }

    // Get PD-table physical address and the PDE virtual address
    if (!paging64_GetPde(
        ptPageTable,
        tVa,
        ptPdpte,
        &qwPdPhysicalAddress,
        &ptPde))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_SetPte: paging64_GetPde failed");
        goto lblCleanup;
    }

    // Get PT-table physical address and the PTE virtual address
    if (!paging64_GetPte(
        ptPageTable,
        tVa,
        ptPde,
        &qwPtPhysicalAddress,
        &ptPte))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_SetPte: paging64_GetPde failed");
        goto lblCleanup;
    }
    
    // Initialize PML4E to point to PDPTE
    MemFill(ptPml4e, 0, sizeof(*ptPml4e));
    ptPml4e->Present = TRUE;
    ptPml4e->Addr = qwPdptPhysicalAddress >> 12;
    ptPml4e->Us = bSupervisor;
    ptPml4e->Rw = bWrite;
    ptPml4e->Nx = bNoExecute;
    ptPml4e->Pwt = bPwtFlag;
    ptPml4e->Pcd = bPcdFlag;

    // Initialize PDPTE to point to PDE
    MemFill(ptPdpte, 0, sizeof(*ptPdpte));
    ptPdpte->Present = TRUE;
    ptPdpte->Addr = qwPdPhysicalAddress >> 12;
    ptPdpte->Us = bSupervisor;
    ptPdpte->Rw = bWrite;
    ptPdpte->Nx = bNoExecute;
    ptPdpte->Pwt = bPwtFlag;
    ptPdpte->Pcd = bPcdFlag;

    // Initialize PDE to point to PTE
    MemFill(ptPde, 0, sizeof(*ptPde));
    ptPde->Present = TRUE;
    ptPde->Addr = qwPtPhysicalAddress >> 12;
    ptPde->Us = bSupervisor;
    ptPde->Rw = bWrite;
    ptPde->Nx = bNoExecute;
    ptPde->Pwt = bPwtFlag;
    ptPde->Pcd = bPcdFlag;

    // Initialize PTE to point to physical address
    MemFill(ptPte, 0, sizeof(*ptPte));
    ptPte->Present = TRUE;
    ptPte->Addr = qwPhysicalAddressToMap >> PAGE_SHIFT_4KB;
    ptPte->Us = bSupervisor;
    ptPte->Rw = bWrite;
    ptPte->Nx = bNoExecute;
    ptPte->Pwt = bPwtFlag;
    ptPte->Pcd = bPcdFlag;
    ptPte->Pat = bPatFlag;
    
    bSuccess = TRUE;

lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_SetPte return bSucces=%d",
        bSuccess);
    return bSuccess;
}

STATIC
BOOLEAN
paging64_MapPage(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_MapPage(ptPageTable=0x%016llx, qwVirtualAddress=0x%016llx, "
        "qwPhysicalAddress=0x%016llx, ePageType=%d, ePagePermission=%d, eMemType=%d)",
        (UINT64)ptPageTable,
        qwVirtualAddress,
        qwPhysicalAddress,
        ePageType,
        ePagePermission,
        eMemType);

    // Get the memory type for the physical address from MTRR to see if we
    // can use the eMemType given, or not
    if (ptPageTable->bMtrrSupported)
    {
        // TODO: What do we do here if page end address exceeds MTRR range end? (TBD)
        if (!MTRR_GetMemTypeForPhysicalAddress(
            qwPhysicalAddress,
            FALSE,
            &eMtrrMemType))
        {
            LOG_ERROR(
                ptPageTable->ptLog,
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
                ptPageTable->ptLog,
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
        ptPageTable,
        eMemType,
        &bPwtFlag,
        &bPcdFlag,
        &bPatFlag))
    {
        // No PAT entry contains the given memory type
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "paging64_MapPage: paging64_GetPatFlagsForMemType failed eMemType=%d",
            eMemType);
        goto lblCleanup;
    }
    
    switch (ePageType)
    {
    case PAGE_TYPE_1GB:
        if (!paging64_SetPdpte1gb(
            ptPageTable,
            qwVirtualAddress,
            qwPhysicalAddress,
            ePagePermission,
            bPwtFlag,
            bPcdFlag,
            bPatFlag))
        {
            LOG_INFO(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "paging64_MapPage: paging64_SetPdpte1gb failed");
            goto lblCleanup;
        }
        break;
    case PAGE_TYPE_2MB:
        if (!paging64_SetPde2mb(
            ptPageTable,
            qwVirtualAddress,
            qwPhysicalAddress,
            ePagePermission,
            bPwtFlag,
            bPcdFlag,
            bPatFlag))
        {
            LOG_INFO(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "paging64_MapPage: paging64_SetPde2mb failed");
            goto lblCleanup;
        }
        break;
    case PAGE_TYPE_4KB:
        if (!paging64_SetPte(
            ptPageTable,
            qwVirtualAddress,
            qwPhysicalAddress,
            ePagePermission,
            bPwtFlag,
            bPcdFlag,
            bPatFlag))
        {
            LOG_INFO(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "paging64_MapPage: paging64_SetPte failed");
            goto lblCleanup;
        }
        break;
    }

    LOG_INFO(
        ptPageTable->ptLog,
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
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_MapPage return bSuccess=%d",
        bSuccess);
    return bSuccess;
}

BOOLEAN
paging64_MapRangeUsingPageType(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
    INOUT const UINT64 qwStartVa,
    INOUT const UINT64 qwStartPhysical,
    IN const UINT64 qwEndVa,
    IN const PAGE_TYPE64 ePageType,
    IN const PAGE_PERMISSION ePagePermission,
    IN const IA32_PAT_MEMTYPE eMemType
)
{
    BOOLEAN bSuccess = FALSE;
    UINT64 qwCurrentVa = qwStartVa;
    UINT64 qwCurrentPhysical= qwStartPhysical;
    const UINT64 qwPageSize = paging64_PageSizeByType(ePageType);
    const UINT64 qwRangeEndVa = paging64_AlignByPageType(ePageType, qwEndVa);

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> paging64_MapRangeUsingPageType(ptPageTable=0x%016llx, "
        "qwStartVa=0x%016llx, qwStartPhysical=0x%016llx, qwEndVa=0x%016llx, "
        "ePageType=%d, ePagePermission=0x%x, eMemType=%d)",
        ptPageTable,
        qwStartVa,
        qwStartPhysical,
        qwEndVa,
        ePageType,
        ePagePermission,
        eMemType);

    while (qwCurrentVa < qwRangeEndVa)
    {
        if (!paging64_MapPage(
            ptPageTable,
            qwCurrentVa,
            qwCurrentPhysical,
            ePageType,
            ePagePermission,
            eMemType))
        {
            LOG_ERROR(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "paging64_MapRangeUsingPageType: paging64_MapPage failed "
                "qwPageTablePhysicalAddress=0x%016llx, qwVirtualAddress=0x%016llx, "
                "qwPhysicalAddress=0x%016llx, ePermissions=0x%x, eMemType=%d",
                ptPageTable->qwPml4PhysicalAddress,
                qwCurrentVa,
                qwCurrentPhysical,
                ePagePermission,
                eMemType);
            goto lblCleanup;
        }

        qwCurrentVa += qwPageSize;
        qwCurrentPhysical += qwPageSize;
    }

    bSuccess = TRUE;

lblCleanup:
    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "<-- paging64_MapRangeUsingPageType return bSuccess=%d",
        bSuccess);
    return bSuccess;
}

BOOLEAN
PAGING64_MapPhysicalToVirtual(
    INOUT PPAGING64_PT_HANDLE ptPageTable,
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
    UINT64 qwCurrentRangeEndVa = 0;
    BOOLEAN bIsLocked = FALSE;
    const UINT64 qwMaxPhyAddr = MAXPHYADDR;

    if (    (NULL == ptPageTable)
        ||    (qwMaxPhyAddr <= qwPhysicalAddress)
        ||    (0 == cbSize)
        ||    (0 > eMemType)
        ||    (IA32_PAT_MEMTYPE_UCM < eMemType)
        ||    (!paging64_VerifyPageTableHandle(ptPageTable))
        ||    (ptPageTable->bIsReadOnly)
        ||    (qwPhysicalAddress >= (qwPhysicalAddress + cbSize))
        ||    (qwVirtualAddress >= (qwVirtualAddress + cbSize)))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_MapPhysicalToVirtual(ptPageTable=0x%016llx, "
        "qwPhysicalAddress=0x%016llx, qwVirtualAddress=0x%016llx, cbSize=%d, "
        "ePagePermission=0x%x, eMemType=%d)",
        (UINT64)ptPageTable,
        qwPhysicalAddress,
        qwVirtualAddress,
        cbSize,
        ePagePermission,
        eMemType);
    LOCK_SpinlockAcquire(&ptPageTable->tEditLock);
    bIsLocked = TRUE;

    // Calculate start and end virtual and physical addresses of mapping
    // and how many pages we'll need to allocate
    cbMinPageSize = paging64_PageSizeByType(ptPageTable->eMinPageType);
    qwStartVa = paging64_AlignByPageType(
        ptPageTable->eMinPageType,
        qwVirtualAddress);
    qwStartPhysical = paging64_AlignByPageType(
        ptPageTable->eMinPageType,
        qwPhysicalAddress);
    nPagesToMap = paging64_AddressAndSizeToSpanPagesByPageType(
        ptPageTable->eMinPageType,
        qwVirtualAddress,
        cbSize);
    qwEndVa = qwStartVa + nPagesToMap * cbMinPageSize;
    qwEndPhysical = qwStartPhysical + nPagesToMap * cbMinPageSize;

    // Check mapping won't exceed page-table max virtual address or MAXPHYADDR
    if (    (qwEndVa <= qwStartVa)
        ||    (qwEndVa >= ptPageTable->qwMaxVirtualAddress)
        ||    (qwEndPhysical <= qwStartPhysical)
        ||    (qwEndPhysical >= qwMaxPhyAddr))
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_MapPhysicalToVirtual: requested mapping exceeds max virtual address"
            " or MAXPHYADDR (qwVirtualAddress=0x%016llx, qwPhysicalAddress=0x%016llx "
            "cbSize=0x%016llx, qwMaxVa=0x%016llx, MAXPHYADDR=0x%016llx)",
            qwVirtualAddress,
            qwPhysicalAddress,
            cbSize,
            ptPageTable->qwMaxVirtualAddress,
            qwMaxPhyAddr);
        goto lblCleanup;
    }

    // Verify none of the pages in the virtual address range are already mapped
    qwCurrentVa = qwStartVa;
    while (qwCurrentVa < qwEndVa)
    {
        if (paging64_GetMappedEntryAtVirtualAddress(
            ptPageTable,
            qwCurrentVa,
            &pvEntry,
            &ePageType))
        {
            LOG_ERROR(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "PAGING64_MapPhysicalToVirtual: A page is already mapped at the given "
                "range qwPageTablePhysicalAddress=0x%016llx, qwVirtualAddres=0x%016llx, "
                "cbSize=%d",
                ptPageTable->qwPml4PhysicalAddress,
                qwVirtualAddress,
                cbSize);
            goto lblCleanup;
        }

        // Skip the non-present entry
        qwCurrentVa += paging64_PageSizeByType(ePageType);
    }

    // Map pages until all of the requested range is in the page-table
    bStartedMapping = TRUE;
    qwCurrentVa = qwStartVa;
    qwCurrentPhysical = qwStartPhysical;

    // Map the range using the least amount of entries possible
    // First we map what we can with 1GB pages, then 2MB and finally 4KB.
    // We do not map page-types that are below the minimum page-type
    for (ePageType = PAGE_TYPE_1GB;
        ptPageTable->eMinPageType <= ePageType;
        ePageType--)
    {
        qwCurrentRangeEndVa = paging64_AlignByPageType(ePageType, qwEndVa);
        if (qwCurrentVa >= qwCurrentRangeEndVa)
        {
            // Can't map entries with current page-type
            continue;
        }

        // Map everything we can with the current page-type
        if (!paging64_MapRangeUsingPageType(
            ptPageTable,
            qwCurrentVa,
            qwCurrentPhysical,
            qwCurrentRangeEndVa,
            ePageType,
            ePagePermission,
            eMemType))
        {
            LOG_ERROR(
                ptPageTable->ptLog,
                LOG_MODULE_PAGING,
                "PAGING64_MapPhysicalToVirtual: paging64_MapRangeUsingPageType "
                "ePageType=%d failed",
                ePageType);
            goto lblCleanup;
        }

        qwCurrentPhysical += (qwCurrentRangeEndVa - qwCurrentVa);
        qwCurrentVa = qwCurrentRangeEndVa;
    }
    
    // Verify we mapped the entire range
    if (qwCurrentVa != qwEndVa)
    {
        LOG_ERROR(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_MapPhysicalToVirtual: range wasn't entirely mapped "
            "qwStartVa=0x%016llx, qwEndVa=0x%016llx, qwCurrentVa=0x%016llx",
            qwStartVa,
            qwEndVa,
            qwCurrentVa);
        goto lblCleanup;
    }
    
    LOG_INFO(
        ptPageTable->ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_MapPhysicalToVirtual: Range mapped qwPageTablePhysicalAddress=0x%016llx, "
        "qwVirtualAddress=0x%016llx, cbSize=%d, ePermission=0x%x, eMemType=%d",
        ptPageTable->qwPml4PhysicalAddress,
        qwVirtualAddress,
        cbSize,
        ePagePermission,
        eMemType);

    bSuccess = TRUE;

lblCleanup:
    if (bIsLocked)
    {
        LOCK_SpinlockRelease(&ptPageTable->tEditLock);
        bIsLocked = FALSE;
    }

    if (    (!bSuccess)
        &&    bStartedMapping)
    {
        PAGING64_UnmapVirtual(
            ptPageTable,
            qwVirtualAddress,
            cbSize);
    }

    if (    (NULL != ptPageTable)
        &&    (NULL != ptPageTable->ptLog))
    {
        LOG_TRACE(
            ptPageTable->ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_MapPhysicalToVirtual return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

BOOLEAN
PAGING64_CreateStaticPageTable(
    INOUT PPAGING64_STATIC_TABLE ptStaticPageTable,
    IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
    IN const PLOG_HANDLE ptLog,
    IN const UINT64 qwMaxVirtualAddress,
    IN const PAGE_TYPE64 eMinPageType,
    OUT PPAGING64_PT_HANDLE ptOutPageTable
)
{
    BOOLEAN bSuccess = FALSE;
    PAGING64_PT_HANDLE tDstPageTable;
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

    if (    (NULL == ptStaticPageTable)
        ||    (NULL == pfnPhysicalToVirtual)
        ||    (NULL == ptLog)
        ||    (0 > eMinPageType)
        ||    (PAGE_TYPE_1GB < eMinPageType)
        ||    (PAGE_SIZE_1GB > qwMaxVirtualAddress)
        ||    (PAGE_TABLE64_MAX_VIRTUAL_ADDRESS < qwMaxVirtualAddress)
        ||    (NULL == ptOutPageTable))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_CreateStaticPageTable(ptPageTable=0x%016llx, "
        "pfnPhysicalToVirtual=0x%016llx, ptLog=0x%016llx, "
        "qwMaxVirtualAddress=0x%016llx, eMinPageType=%d, phOutPageTable=0x%016llx)",
        (UINT64)ptStaticPageTable,
        (UINT64)pfnPhysicalToVirtual,
        (UINT64)ptLog,
        qwMaxVirtualAddress,
        eMinPageType,
        (UINT64)ptOutPageTable);

    // Find the physical address of the page - table to initialize
    if (!PAGING64_VirtualToPhysicalFromCR3(
        (UINT64)ptStaticPageTable,
        pfnPhysicalToVirtual,
        ptLog,
        &qwDstPml4PhysicalAddress,
        &ePageType,
        &ePagePermission,
        &eMemType))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_CreateStaticPageTable: "
            "PAGING64_VirtualToPhysicalFromCurrentPageTable failed");
        goto lblCleanup;
    }

    // Open a handle to the page-table we wish to initialize
    if (!PAGING64_OpenPageTableHandle(
        &tDstPageTable,
        pfnPhysicalToVirtual,
        qwDstPml4PhysicalAddress,
        ptLog))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_CreateStaticPageTable: PAGING64_OpenPageTableHandle failed on "
            "ptPageTable=0x%016llx",
            (UINT64)ptStaticPageTable);
        goto lblCleanup;
    }

    if (    (PAGE_TYPE_1GB == eMinPageType)
        &&    (!tDstPageTable.bOneGbSupported))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_CreateStaticPageTable: 1GB pages are not supported and minimum "
            "page-type to use is 1GB");
        goto lblCleanup;
    }

    // Initialize members we need to edit static page-table
    tDstPageTable.bIsReadOnly = FALSE;
    tDstPageTable.bIsStatic = TRUE;
    tDstPageTable.eMinPageType = eMinPageType;
    tDstPageTable.qwMaxVirtualAddress = qwMaxVirtualAddress;
    
    tDstPageTable.qwStaticPdptPhysicalAddress = (
            qwDstPml4PhysicalAddress
        +    FIELD_OFFSET(PAGING64_STATIC_TABLE, atPdpt));
    tDstPageTable.qwStaticPdArrayPhysicalAddress = (
            qwDstPml4PhysicalAddress
        +    FIELD_OFFSET(PAGING64_STATIC_TABLE, atPd));
    tDstPageTable.qwStaticPtArrayPhysicalAddress = (
            qwDstPml4PhysicalAddress
        +    FIELD_OFFSET(PAGING64_STATIC_TABLE, atPt));

    tDstPageTable.patStaticPdpt = (PPDPTE64)(&ptStaticPageTable->atPdpt);
    tDstPageTable.patStaticPdArray= (PDE64(*)[PAGING64_PDPTE_COUNT])(
        &ptStaticPageTable->atPd);
    tDstPageTable.patStaticPtArray= (PTE64(*)[PAGING64_PDPTE_COUNT][PAGING64_PDE_COUNT])(
        &ptStaticPageTable->atPt);

    // Zero out the PML4 and PDPT tables
    tMaxVa.qwValue = qwMaxVirtualAddress;
    LOG_DEBUG(
        ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_CreateStaticPageTable: Zero PML4=0x%016llx (cbSize=0x%x)",
        (UINT64)ptStaticPageTable->atPml4,
        sizeof(ptStaticPageTable->atPml4));
    MemZero(ptStaticPageTable->atPml4, sizeof(ptStaticPageTable->atPml4));
    LOG_DEBUG(
        ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_CreateStaticPageTable: Zero PDPT=0x%016llx (cbSize=0x%x)",
        (UINT64)ptStaticPageTable->atPdpt,
        sizeof(ptStaticPageTable->atPdpt));
    MemZero(ptStaticPageTable->atPdpt, sizeof(ptStaticPageTable->atPdpt));
    
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
                        &tDstPageTable.patStaticPtArray[wPdptIndex][wPdIndex]);
                    LOG_DEBUG(
                        ptLog,
                        LOG_MODULE_PAGING,
                        "PAGING64_CreateStaticPageTable: Zero PT=0x%016llx (cbSize=0x%x)",
                        (UINT64)patCurrentPt,
                        sizeof(*patCurrentPt));
                    MemZero(patCurrentPt, sizeof(*patCurrentPt));
                }
            }

            patCurrentPd = (PDE64(*)[PAGING64_PDE_COUNT])(
                &tDstPageTable.patStaticPdArray[wPdptIndex]);
            LOG_DEBUG(
                ptLog,
                LOG_MODULE_PAGING,
                "PAGING64_CreateStaticPageTable: Zero PD=0x%016llx (cbSize=0x%x)",
                (UINT64)patCurrentPd,
                sizeof(*patCurrentPd));
            MemZero(patCurrentPd, sizeof(*patCurrentPd));
        }
    }
    
    LOG_INFO(
        ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_CreateStaticPageTable: Page table initialized qwPhysicalAddress=0x%016llx",
        qwDstPml4PhysicalAddress);

    bSuccess = TRUE;
    MemCopy(ptOutPageTable, &tDstPageTable, sizeof(*ptOutPageTable));

lblCleanup:
    if (NULL != ptLog)
    {
        LOG_TRACE(
            ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_CreateStaticPageTable return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

BOOLEAN
PAGING64_CreateDynamicPageTable(
    IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
    IN const PAGING64_HEAP_ALLOC_PFN pfnHeapAlloc,
    IN const PAGING64_HEAP_FREE_PFN pfnHeapFree,
    IN const PLOG_HANDLE ptLog,
    OUT PPAGING64_PT_HANDLE ptOutPageTable
)
{
    BOOLEAN bSuccess = FALSE;
    PAGING64_PT_HANDLE tDstPageTable = { 0 };
    UINT64 qwDstPml4PhysicalAddress = 0;
    PAGE_TYPE64 ePageType = 0;
    PAGE_PERMISSION ePagePermission = 0;
    IA32_PAT_MEMTYPE eMemType = 0;
    PPML4E64 patPml4 = NULL;

    if (    (NULL == pfnPhysicalToVirtual)
        ||    (NULL == pfnHeapAlloc)
        ||    (NULL == pfnHeapFree)
        ||    (NULL == ptLog)
        ||    (NULL == ptOutPageTable))
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_CreateDynamicPageTable(pfnPhysicalToVirtual=0x%016llx, )"
        "pfnHeapAlloc=0x%016llx, pfnHeapFree=0x%016llx, ptLog=0x%016llx, "
        "ptOutPageTable=0x%016llx)",
        (UINT64)pfnPhysicalToVirtual,
        (UINT64)pfnHeapAlloc,
        (UINT64)pfnHeapFree,
        (UINT64)ptLog,
        (UINT64)ptOutPageTable);

    // NOTE: We always allocate only 1 PML4 table, since it's more than enough:
    // 1 PML4 can point to up to 512GB of memory. This limits us to a maximum 
    // virtual address of 0x7fffffffff == ((1 << 39) - 1).
    // See PAGE_TABLE64_MAX_VIRTUAL_ADDRESS
    patPml4 = (PPML4E64)pfnHeapAlloc(PAGING64_TABLE_SIZE);
    if (NULL == patPml4)
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_CreateDynamicPageTable: HeapAlloc failed (pfnHeapAlloc=0x%016llx)",
            (UINT64)pfnHeapAlloc);
        goto lblCleanup;
    }
    MemZero(patPml4, PAGING64_TABLE_SIZE);

    // Find the physical address of the page - table to initialize
    if (!PAGING64_VirtualToPhysicalFromCR3(
        (UINT64)patPml4,
        pfnPhysicalToVirtual,
        ptLog,
        &qwDstPml4PhysicalAddress,
        &ePageType,
        &ePagePermission,
        &eMemType))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_CreateStaticPageTable: "
            "PAGING64_VirtualToPhysicalFromCurrentPageTable failed");
        goto lblCleanup;
    }

    // Open a handle to the page-table we wish to initialize
    if (!PAGING64_OpenPageTableHandle(
        &tDstPageTable,
        pfnPhysicalToVirtual,
        qwDstPml4PhysicalAddress,
        ptLog))
    {
        LOG_ERROR(
            ptLog,
            LOG_MODULE_PAGING,
            "PAGING64_CreateDynamicPageTable: PAGING64_OpenPageTableHandle failed");
        goto lblCleanup;
    }

    // Initialize members we need to edit dynamic page-table
    tDstPageTable.bIsReadOnly = FALSE;
    tDstPageTable.bIsStatic = FALSE;
    tDstPageTable.pfnAlloc = pfnHeapAlloc;
    tDstPageTable.pfnFree = pfnHeapFree;
    tDstPageTable.qwMaxVirtualAddress = PAGE_TABLE64_MAX_VIRTUAL_ADDRESS;
    tDstPageTable.eMinPageType = PAGE_TYPE_4KB;

    MemCopy(ptOutPageTable, &tDstPageTable, sizeof(*ptOutPageTable));
    bSuccess = TRUE;

lblCleanup:
    if (    (!bSuccess)
        &&    (NULL != tDstPageTable.patPml4)
        &&    (NULL != pfnHeapFree))
    {
        pfnHeapFree((PVOID)tDstPageTable.patPml4);
        tDstPageTable.patPml4 = NULL;
    }

    if (NULL != ptLog)
    {
        LOG_TRACE(
            ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_CreateDynamicPageTable return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}

STATIC
VOID
paging64_DestroyPdTable(
    IN PPAGING64_PT_HANDLE ptPageTable,
    IN PPDE64 patPd
)
{
    UINTN i = 0;
    UINT64 qwPtPhysicalAddress = 0;
    PPDE64 ptCurrentPde = patPd;
    PPTE64 patPt = NULL;

    // Find all present PD tables and destroy them
    for (; i < PAGING64_PDE_COUNT; i++, ptCurrentPde++)
    {
        if (ptCurrentPde->Present)
        {
            qwPtPhysicalAddress = ptCurrentPde->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPtPhysicalAddress,
                (PUINT64)&patPt))
            {
                break;
            }

            // Free PT table
            ptPageTable->pfnFree(patPt);
            patPt = NULL;
        }
    }

    // Free this PDPT table
    ptPageTable->pfnFree(patPd);
    patPd = NULL;
}

STATIC
VOID
paging64_DestroyPdptTable(
    IN PPAGING64_PT_HANDLE ptPageTable,
    IN PPDPTE64 patPdpt
)
{
    UINTN i = 0;
    UINT64 qwPdPhysicalAddress = 0;
    PPDPTE64 ptCurrentPdpte = patPdpt;
    PPDE64 patPd = NULL;

    // Find all present PD tables and destroy them
    for (; i < PAGING64_PDPTE_COUNT; i++, ptCurrentPdpte++)
    {
        if (ptCurrentPdpte->Present)
        {
            qwPdPhysicalAddress = ptCurrentPdpte->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPdPhysicalAddress,
                (PUINT64)&patPd))
            {
                break;
            }

            paging64_DestroyPdTable(ptPageTable, patPd);
            patPd = NULL;
        }
    }

    // Free this PDPT table
    ptPageTable->pfnFree(patPdpt);
    patPdpt = NULL;
}

STATIC
VOID
paging64_DestroyPml4Table(
    IN PPAGING64_PT_HANDLE ptPageTable,
    IN PPML4E64 patPml4
)
{
    UINTN i = 0;
    UINT64 qwPdptPhysicalAddress = 0;
    PPML4E64 ptCurrentPml4e = patPml4;
    PPDPTE64 patPdpt = NULL;

    // Find all present PDPT tables and destroy them
    for (; i < PAGING64_PML4E_COUNT; i++, ptCurrentPml4e++)
    {
        if (ptCurrentPml4e->Present)
        {
            qwPdptPhysicalAddress = ptCurrentPml4e->Addr << 12;
            if (!ptPageTable->pfnPhysicalToVirtual(
                qwPdptPhysicalAddress,
                (PUINT64)&patPdpt))
            {
                break;
            }

            paging64_DestroyPdptTable(ptPageTable, patPdpt);
            patPdpt = NULL;
        }
    }

    // Free this PML4 table
    ptPageTable->pfnFree(patPml4);
    patPml4 = NULL;
}

VOID
PAGING64_DestroyDynamicPageTable(
    INOUT PPAGING64_PT_HANDLE ptPageTable
)
{
    if (paging64_VerifyPageTableHandle(ptPageTable)
        && (!ptPageTable->bIsReadOnly)
        && (!ptPageTable->bIsStatic))
    {
        // We have only 1 PML4 table
        paging64_DestroyPml4Table(ptPageTable, ptPageTable->patPml4);

        MemZero(ptPageTable, sizeof(*ptPageTable));
    }
}

BOOLEAN
PAGING64_CopyPageTable(
    INOUT PPAGING64_PT_HANDLE ptDstPageTable,
    IN const PPAGING64_PT_HANDLE ptSrcPageTable
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

    if (    (!paging64_VerifyPageTableHandle(ptDstPageTable))
        ||    (!paging64_VerifyPageTableHandle(ptSrcPageTable))
        ||    ptDstPageTable->bIsReadOnly)
    {
        // Invalid parameters
        goto lblCleanup;
    }

    LOG_TRACE(
        ptDstPageTable->ptLog,
        LOG_MODULE_PAGING,
        "--> PAGING64_CopyPageTable(phDstPageTable=0x%016llx, phSrcPageTable=0x%016llx)",
        (UINT64)ptDstPageTable,
        (UINT64)ptSrcPageTable);

    tDstMaxVa.qwValue = ptDstPageTable->qwMaxVirtualAddress;
    
    // Iterate over all present entries in the source page-table
    // and add the same mapping to the destination page-table
    //
    // NOTE: We use PAGING64_MapPhysicalToVirtual instead of paging64_MapPage
    // to create mappings in destination page-table, since it contains logic 
    // to use the eMinPageType and does boundary checks and the latter doesn't
    for (; wPml4Index <= tDstMaxVa.FourKb.Pml4eIndex; wPml4Index++)
    {
        // Skip PML4E if it's not present
        ptPml4e = (PPML4E64)&ptSrcPageTable->patPml4[wPml4Index];
        if (!ptPml4e->Present)
        {
            continue;
        }

        // Get PDPT virtual address from PML4E
        qwPdptPhysicalAddress = ptPml4e->Addr << 12;
        if (!ptSrcPageTable->pfnPhysicalToVirtual(qwPdptPhysicalAddress, (PUINT64)&patPdpt))
        {
            LOG_ERROR(
                ptDstPageTable->ptLog,
                LOG_MODULE_PAGING,
                "PAGING64_CopyPageTable: pfnPhysicalToVirtual=0x%016llx failed "
                "on PML4E=0x%016llx qwPdptPhysicalAddress=0x%016llx",
                (UINT64)ptSrcPageTable->pfnPhysicalToVirtual,
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
                    ptDstPageTable,
                    qwPageVirtualAddress,
                    PAGE_SIZE_1GB))
                {
                    LOG_WARN(
                        ptDstPageTable->ptLog,
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
                    ptSrcPageTable,
                    qwPagePhysicalAddress,
                    (PVOID)ptPdpte1gb,
                    PAGE_TYPE_1GB,
                    &eMemType))
                {
                    LOG_ERROR(
                        ptDstPageTable->ptLog,
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
                    ptDstPageTable,
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
            if (!ptSrcPageTable->pfnPhysicalToVirtual(qwPdPhysicalAddress, (PUINT64)&patPd))
            {
                LOG_ERROR(
                    ptDstPageTable->ptLog,
                    LOG_MODULE_PAGING,
                    "PAGING64_CopyPageTable: pfnPhysicalToVirtual=0x%016llx failed "
                    "on PDPTE=0x%016llx qwPdPhysicalAddress=0x%016llx",
                    (UINT64)ptSrcPageTable->pfnPhysicalToVirtual,
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
                        ptDstPageTable,
                        qwPageVirtualAddress,
                        PAGE_SIZE_2MB))
                    {
                        LOG_WARN(
                            ptDstPageTable->ptLog,
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
                        ptSrcPageTable,
                        qwPagePhysicalAddress,
                        (PVOID)ptPde2mb,
                        PAGE_TYPE_2MB,
                        &eMemType))
                    {
                        LOG_ERROR(
                            ptDstPageTable->ptLog,
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
                        ptDstPageTable,
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
                if (!ptSrcPageTable->pfnPhysicalToVirtual(qwPtPhysicalAddress, (PUINT64)&patPt))
                {
                    LOG_ERROR(
                        ptDstPageTable->ptLog,
                        LOG_MODULE_PAGING,
                        "PAGING64_CopyPageTable: pfnPhysicalToVirtual=0x%016llx "
                        "failed on PDE=0x%016llx qwPtPhysicalAddress=0x%016llx",
                        (UINT64)ptSrcPageTable->pfnPhysicalToVirtual,
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
                        ptDstPageTable,
                        qwPageVirtualAddress,
                        PAGE_SIZE_4KB))
                    {
                        LOG_WARN(
                            ptDstPageTable->ptLog,
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
                        ptSrcPageTable,
                        qwPagePhysicalAddress,
                        (PVOID)ptPte,
                        PAGE_TYPE_4KB,
                        &eMemType))
                    {
                        LOG_ERROR(
                            ptDstPageTable->ptLog,
                            LOG_MODULE_PAGING,
                            "PAGING64_CopyPageTable: paging64_GetPageMemoryType failed "
                            "qwPhysicalAddress=0x%016llx, ptPte=0x%016llx",
                            qwPagePhysicalAddress,
                            (UINT64)ptPte);

                        goto lblCleanup;
                    }

                    // Map the same addresses as the PTE from source page-table
                    // in destination page-table with same permissions and memory type
                    if (!PAGING64_MapPhysicalToVirtual(
                        ptDstPageTable,
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
        ptDstPageTable->ptLog,
        LOG_MODULE_PAGING,
        "PAGING64_CopyPageTable: Copied page-table qwSrcPhysical=0x%016llx to "
        "qwDstPhysical=0x%016llx",
        ptSrcPageTable->qwPml4PhysicalAddress,
        ptDstPageTable->qwPml4PhysicalAddress);

    bSuccess = TRUE;

lblCleanup:
    if (    (NULL != ptSrcPageTable)
        &&    (NULL != ptSrcPageTable->ptLog))
    {
        LOG_TRACE(
            ptSrcPageTable->ptLog,
            LOG_MODULE_PAGING,
            "<-- PAGING64_CopyPageTable return bSuccess=%d",
            bSuccess);
    }
    return bSuccess;
}
