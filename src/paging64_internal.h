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
* @file		paging64.h
* @section	Intel x64 Page Tables structures and constants
*			See Intel's: Software Developers Manual Vol 3A, Section 4.5 IA-32E PAGING
*/

#ifndef __INTEL_PAGING64_INTERNAL_H__
#define __INTEL_PAGING64_INTERNAL_H__

#include "paging64.h"
#include "msr64.h"
#include "mtrr.h"
#include "cpuid.h"
#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

/**
* Verify the page-table handle structure contains valid values
* @param ptPageTable - page type 4KB/2MB/1GB
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_VerifyPageTableHandle(
	IN const PPAGING64_PT_HANDLE ptPageTable
);

/**
* Get page size by type enum
* @param ePageType - page type 4KB/2MB/1GB
* @return Page size that matches type
*/
STATIC
__inline
UINT64
paging64_PageSizeByType(
	IN const PAGE_TYPE64 ePageType
);

/**
* Run the appropriate PAGE_ALIGN macro by the given page-type on the address
* @param ePageType - page type 4KB/2MB/1GB
* @param qwAddress - address to align
* @return Aligned address
*/
STATIC
__inline
UINT64
paging64_AlignByPageType(
	IN const PAGE_TYPE64 ePageType,
	IN const UINT64 qwAddress
);

/**
* Run the appropriate ADDRESS_AND_SIZE_TO_SPAN_PAGES macro by the given page-type
* @param ePageType - page type 4KB/2MB/1GB
* @param qwAddress - buffer address
* @param cbSize - buffer size
* @return Number of pages to span buffer
*/
STATIC
__inline
UINT64
paging64_AddressAndSizeToSpanPagesByPageType(
	IN const PAGE_TYPE64 ePageType,
	IN const UINT64 qwAddress,
	IN const UINT64 cbSize
);

//! Vol 3A, 11.12.1 Detecting Support for the PAT Feature
/**
* Verify if PAT is supported
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_IsPatSupported(
	VOID
);

/**
* Traverse the page table to find the entry that matches the virtual address
* @param ptPageTable - Page-Table handle initialized by PAGING64_InitStaticPageTableHandle
* @param qwVirtualAddress - virtual address to find in page-table
* @param ppvEntry - page-table entry found
* @param pePageType - found page type, or on error the type that wasn't present (1GB/2MB/4KB)
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_GetMappedEntryAtVirtualAddress(
	IN const PPAGING64_PT_HANDLE ptPageTable,
	IN const UINT64 qwVirtualAddress,
	OUT PVOID *ppvEntry,
	OUT PPAGE_TYPE64 pePageType
);

/**
* Parse page permissions from entry structure
* @param pvEntry - pointer to entry structure
* @param ePageType - type of page 1GB/2MB/4KB
* @return See PAGE_PERMISSON enum
*/
STATIC
PAGE_PERMISSION
paging64_GetPagePermissions(
	IN const PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType
);

/**
* Get the effective memory type of the given page by checking MTRR & PAT
* @param ptPageTable - open handle to the page-table
* @param qwPhysicalAddress - physical address that the entry points to
* @param pvEntry - pointer to entry structure
* @param ePageType - type of page 1GB/2MB/4KB
* @param peMemType - memory type used in this page
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_GetPageMemoryType(
	IN const PPAGING64_PT_HANDLE ptPageTable,
	IN const UINT64 qwPhysicalAddress,
	IN const PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType,
	OUT PIA32_PAT_MEMTYPE peMemType
);

/**
* Check if all entries in the table are marked as not-present
* @param patPdpt - PDPT table
* @return TRUE if table is empty, else FALSE
*/
STATIC
BOOLEAN
paging64_IsPdptTableEmpty(
	IN const PPDPTE64 patPdpt
);

/**
* Check if all entries in the table are marked as not-present
* @param patPd - PD table
* @return TRUE if table is empty, else FALSE
*/
STATIC
BOOLEAN
paging64_IsPdTableEmpty(
	IN const PPDE64 patPd
);

/**
* Check if all entries in the table are marked as not-present
* @param patPt - PT table
* @return TRUE if table is empty, else FALSE
*/
STATIC
BOOLEAN
paging64_IsPtTableEmpty(
	IN const PPTE64 patPt
);

/**
* Free all unused PT-tables pointed to by this PD-table, then free the
* PD-table if it's also empty
* @param ptPageTable - dynamic page-table handle
* @param patPd - PD-Table to free unused entries from
*/
STATIC
VOID
paging64_CollectGarbageFromPdTable(
	IN PPAGING64_PT_HANDLE ptPageTable,
	IN PPDE64 patPd
);

/**
* Free all unused PD-tables pointed to by this PDPT-table, then free the
* PDPT-table if it's also empty
* @param ptPageTable - dynamic page-table handle
* @param patPdpt - PDPT-Table to free unused entries from
*/
STATIC
VOID
paging64_CollectGarbageFromPdptTable(
	IN PPAGING64_PT_HANDLE ptPageTable,
	IN PPDPTE64 patPdpt
);

/**
* Free all unused PDPT-tables pointed to by this PML4-table, then free the
* PML4-table if it's also empty
* @param ptPageTable - dynamic page-table handle
* @param patPml4 - PML4-Table to free unused entries from
*/
STATIC
VOID
paging64_CollectGarabageFromPml4Table(
	IN PPAGING64_PT_HANDLE ptPageTable,
	IN PPML4E64 patPml4
);

/**
* Unmap an entry from the page-table by clearing it's present bit
* @param pvEntry - pointer to page table entry
* @param ePageType - type of page 1gb/2mb/4kb
*/
STATIC
VOID
paging64_UnmapPage(
	INOUT PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType
);

/**
* Seek a PAT entry that holds the given memory type and return its index through the flags
* @param ptPageTable - page table handle initialized by PAGING64_InitStaticPageTableHandle
* @param eMemType - See IA32_PAT_MEMTYPE in msr64.h
* @param pbPwtFlag - PWT flag calculated from PAT entry index
* @param pbPcdFlag - PCD flag calculated from PAT entry index
* @param pbPatFlag - PAT flag calculated from PAT entry index
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_GetPatFlagsForMemType(
	IN const PPAGING64_PT_HANDLE ptPageTable,
	IN const IA32_PAT_MEMTYPE eMemType,
	OUT PBOOLEAN pbPwtFlag,
	OUT PBOOLEAN pbPcdFlag,
	OUT PBOOLEAN pbPatFlag
);

/**
* Get the virtual address of PDPTE entry for given virtual address from PML4E
* in the page-table and the physical address of the PDPT table it's in
* @param ptPageTable - open page table handle
* @param tVa - virtual address to entries of
* @param ptPml4e - PML4E entry that points to PDPT table
* @param pqwPdptPhysicalAddress - physical address of PDPT table
* @param pptPdpte - virtual address of PDPTE in PDPT table
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_GetPdpte(
	IN const PPAGING64_PT_HANDLE ptPageTable,
	IN const VA_ADDRESS64 tVa,
	IN const PPML4E64 ptPml4e,
	OUT PUINT64 pqwPdptPhysicalAddress,
	OUT PPDPTE64 *pptPdpte
);

/**
* Get the virtual address of PDE entry for given virtual address from PDPTE
* in the page-table and the physical address of the PD table it's in
* @param ptPageTable - open page table handle
* @param tVa - virtual address to entries of
* @param ptPdpte - PDPTE entry that points to PD table
* @param pqwPdPhysicalAddress - physical address of PD table
* @param pptPde - virtual address of PDE in PD table
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_GetPde(
	IN const PPAGING64_PT_HANDLE ptPageTable,
	IN const VA_ADDRESS64 tVa,
	IN const PPDPTE64 ptPdpte,
	OUT PUINT64 pqwPdPhysicalAddress,
	OUT PPDE64 *pptPde
);

/**
* Get the virtual address of PTE entry for given virtual address from PDE
* in the page-table and the physical address of the PT table it's in
* @param ptPageTable - open page table handle
* @param tVa - virtual address to entries of
* @param ptPde - PDE entry that points to PT table
* @param pqwPtPhysicalAddress - physical address of PT table
* @param pptPte - virtual address of PTE in PT table
* @return TRUE on success, else FALSE
*/
STATIC
BOOLEAN
paging64_GetPte(
	IN const PPAGING64_PT_HANDLE ptPageTable,
	IN const VA_ADDRESS64 tVa,
	IN const PPDE64 ptPde,
	OUT PUINT64 pqwPtPhysicalAddress,
	OUT PPTE64 *pptPte
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 1GB page at the given virtual address
* @param ptPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddressToMap - physical address of page to map
* @param ePagePermission - permissions granted
* @param bPwtFlag - Part of the PAT index that holds the page memory type
* @param bPcdFlag - Part of the PAT index that holds the page memory type
* @param bPatFlag - Part of the PAT index that holds the page memory type
* @return TRUE on success, else FALSE
*/
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
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 2MB page at the given virtual address
* @param ptPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddressToMap - physical address of page to map
* @param ePagePermission - permissions granted
* @param bPwtFlag - Part of the PAT index that holds the page memory type
* @param bPcdFlag - Part of the PAT index that holds the page memory type
* @param bPatFlag - Part of the PAT index that holds the page memory type
* @return TRUE on success, else FALSE
*/
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
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 4KB page at the given virtual address
* @param ptPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddressToMap - physical address of page to map
* @param ePagePermission - permissions granted
* @param bPwtFlag - Part of the PAT index that holds the page memory type
* @param bPcdFlag - Part of the PAT index that holds the page memory type
* @param bPatFlag - Part of the PAT index that holds the page memory type
* @return TRUE on success, else FALSE
*/
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
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 4KB page at the given virtual address
* @param ptPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddress - physical address of page
* @param eMemType - page type 1GB/2MB/4KB
* @param ePagePermission - permissions to grant
* @param eMemType - memory type to use
*/
STATIC
BOOLEAN
paging64_MapPage(
	INOUT PPAGING64_PT_HANDLE ptPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_TYPE64 ePageType,
	IN const PAGE_PERMISSION ePagePermission,
	IN const IA32_PAT_MEMTYPE eMemType
);

/**
* Free all PT-tables pointed to by this PD-table, then free the PD-table
* @param ptPageTable - dynamic page-table handle
* @param patPd - PD-Table to destroy
*/
STATIC
VOID
paging64_DestroyPdTable(
	IN PPAGING64_PT_HANDLE ptPageTable,
	IN PPDE64 patPd
);

/**
* Free all PD-tables pointed to by this PDPT-table, then free the PDPT-table
* @param ptPageTable - dynamic page-table handle
* @param patPd - PDPT-Table to destroy
*/
STATIC
VOID
paging64_DestroyPdptTable(
	IN PPAGING64_PT_HANDLE ptPageTable,
	IN PPDPTE64 patPdpt
);

/**
* Free all PDPT-tables pointed to by this PML4-table, then free the PML4-table
* @param ptPageTable - dynamic page-table handle
* @param patPd - PML4-Table to destroy
*/
STATIC
VOID
paging64_DestroyPml4Table(
	IN PPAGING64_PT_HANDLE ptPageTable,
	IN PPML4E64 patPml4
);

/**
* Map the range given in the page-table using only pages of the specified type (1GB/2MB/4KB)
* NOTE: We don't map pages that might exceed the given range!
* @param ptPageTable - page-table handle
* @param qwStartVa - range start virtual address
* @param qwStartPhysical - range start physical address
* @param qwEndVa - range end virtual address
* @param ePageType - page-type to use (1GB/2MB/4KB)
* @param ePagePermission - page permission to set in pages
* @param eMemType - memory cache type to set in pages
* @return TRUE on success, else FALSE
*/
BOOLEAN
paging64_MapRangeUsingPageType(
	INOUT PPAGING64_PT_HANDLE ptPageTable,
	INOUT const UINT64 qwStartVa,
	INOUT const UINT64 qwStartPhysical,
	IN const UINT64 qwEndVa,
	IN const PAGE_TYPE64 ePageType,
	IN const PAGE_PERMISSION ePagePermission,
	IN const IA32_PAT_MEMTYPE eMemType
);

#pragma pack(pop)
#pragma warning(pop)
#endif  /* __INTEL_PAGING64_INTERNAL_H__ */
