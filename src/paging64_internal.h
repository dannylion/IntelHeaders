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

//! Vol 3A, 11.12.1 Detecting Support for the PAT Feature
/**
* Verify if PAT is supported
* @return TRUE on success, else FALSE
*/
BOOLEAN
paging64_IsPatSupported(
	VOID
);

/**
* Traverse the page table to find the entry that matches the virtual address
* @param ptPageTable - Page-Table handle initialized by PAGING64_InitPageTableHandle
* @param qwVirtualAddress - virtual address to find in page-table
* @param ppvEntry - page-table entry found
* @param pePageType - type of found page (1GB/2MB/4KB)
* @return TRUE on success, else FALSE
*/
BOOLEAN
paging64_GetMappedEntryAtVirtualAddress(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
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
PAGE_PERMISSION
paging64_GetPagePermissions(
	IN const PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType
);

/**
* Get the effective memory type of the given page by checking MTRR & PAT
* @param phPageTable - open handle to the page-table
* @param qwPhysicalAddress - physical address that the entry points to
* @param pvEntry - pointer to entry structure
* @param ePageType - type of page 1GB/2MB/4KB
* @param peMemType - memory type used in this page
* @return TRUE on success, else FALSE
*/
BOOLEAN
paging64_GetPageMemoryType(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwPhysicalAddress,
	IN const PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType,
	OUT PIA32_PAT_MEMTYPE peMemType
);

/**
* Mark given page as not present to unmap it
* @param pvEntry - pointer to page table entry
* @param ePageType - type of page 1gb/2mb/4kb
*/
VOID
paging64_UnmapPage(
	INOUT PVOID pvEntry,
	IN const PAGE_TYPE64 ePageType
);

/**
* Seek a PAT entry that holds the given memory type and return its index through the flags
* @param phPageTable - page table handle initialized by PAGING64_InitPageTableHandle
* @param eMemType - See IA32_PAT_MEMTYPE in msr64.h
* @param pbPwtFlag - PWT flag calculated from PAT entry index
* @param pbPcdFlag - PCD flag calculated from PAT entry index
* @param pbPatFlag - PAT flag calculated from PAT entry index
* @return TRUE on success, else FALSE
*/
BOOLEAN
paging64_GetPatFlagsForMemType(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const IA32_PAT_MEMTYPE eMemType,
	OUT PBOOLEAN pbPwtFlag,
	OUT PBOOLEAN pbPcdFlag,
	OUT PBOOLEAN pbPatFlag
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 1GB page at the given virtual address
* @param phPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddress - physical address of page
* @param ePagePermission - permissions granted
* @param bPwtFlag - Part of the PAT index that holds the page memory type
* @param bPcdFlag - Part of the PAT index that holds the page memory type
* @param bPatFlag - Part of the PAT index that holds the page memory type
*/
VOID
paging64_SetPdpte1gb(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_PERMISSION ePagePermission,
	IN const BOOLEAN bPwtFlag,
	IN const BOOLEAN bPcdFlag,
	IN const BOOLEAN bPatFlag
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 2MB page at the given virtual address
* @param phPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddress - physical address of page
* @param ePagePermission - permissions granted
* @param bPwtFlag - Part of the PAT index that holds the page memory type
* @param bPcdFlag - Part of the PAT index that holds the page memory type
* @param bPatFlag - Part of the PAT index that holds the page memory type
*/
VOID
paging64_SetPde2mb(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_PERMISSION ePagePermission,
	IN const BOOLEAN bPwtFlag,
	IN const BOOLEAN bPcdFlag,
	IN const BOOLEAN bPatFlag
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 4KB page at the given virtual address
* @param phPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddress - physical address of page
* @param ePagePermission - permissions granted
* @param bPwtFlag - Part of the PAT index that holds the page memory type
* @param bPcdFlag - Part of the PAT index that holds the page memory type
* @param bPatFlag - Part of the PAT index that holds the page memory type
*/
VOID
paging64_SetPte(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_PERMISSION ePagePermission,
	IN const BOOLEAN bPwtFlag,
	IN const BOOLEAN bPcdFlag,
	IN const BOOLEAN bPatFlag
);

/**
* Set the given memory type flags, permissions and physical address in all entries
* in page table that will point to the 4KB page at the given virtual address
* @param phPageTable - page table to set entries in
* @param qwVirtualAddress - virtual address of page
* @param qwPhysicalAddress - physical address of page
* @param eMemType - page type 1GB/2MB/4KB
* @param ePagePermission - permissions to grant
* @param eMemType - memory type to use
*/
BOOLEAN
paging64_MapPage(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 qwPhysicalAddress,
	IN const PAGE_TYPE64 ePageType,
	IN const PAGE_PERMISSION ePagePermission,
	IN const IA32_PAT_MEMTYPE eMemType
);

#pragma pack(pop)
#pragma warning(pop)
#endif  /* __INTEL_PAGING64_INTERNAL_H__ */
