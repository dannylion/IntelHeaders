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

#ifndef __INTEL_PAGING64_H__
#define __INTEL_PAGING64_H__

#include "ntdatatypes.h"
#include "log.h"
#include "msr64.h"
#include "cr64.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

#define PAGING64_PML4E_COUNT	512
#define PAGING64_PDPTE_COUNT	512
#define PAGING64_PDE_COUNT		512
#define PAGING64_PTE_COUNT		512

#define PAGE_SIZE_4KB	PAGE_SIZE
#define PAGE_SIZE_2MB	(0x1000 * 512)
#define PAGE_SIZE_1GB	(0x1000 * 512 * 512)

#define PAGE_SHIFT_1GB 30L
#define PAGE_SHIFT_2MB 21L
#define PAGE_SHIFT_4KB 12L

#define PAGE_OFFSET_MASK_1GB (PAGE_SIZE_1GB - 1)
#define PAGE_OFFSET_MASK_2MB (PAGE_SIZE_2MB - 1)
#define PAGE_OFFSET_MASK_4KB (PAGE_SIZE_4KB - 1)

// The ROUND_TO_PAGES macro takes a size in bytes and rounds it up to a
// multiple of the page size.
// NOTE: This macro fails for values 0xFFFFFFFF - (PAGE_SIZE - 1).
#define ROUND_TO_PAGES_1GB(Size)  (((UINT64)(Size) + PAGE_SIZE_1GB - 1) & ~(PAGE_SIZE_1GB - 1))
#define ROUND_TO_PAGES_2MB(Size)  (((UINT64)(Size) + PAGE_SIZE_2MB - 1) & ~(PAGE_SIZE_2MB - 1))
#define ROUND_TO_PAGES_4KB(Size)  (((UINT64)(Size) + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1))

// The BYTES_TO_PAGES macro takes the size in bytes and calculates the
// number of pages required to contain the bytes.
#define BYTES_TO_PAGES_1GB(Size)  (((Size) >> PAGE_SHIFT_1GB) + \
                                  (((Size) & (PAGE_SIZE_1GB - 1)) != 0))
#define BYTES_TO_PAGES_2MB(Size)  (((Size) >> PAGE_SHIFT_2MB) + \
                                  (((Size) & (PAGE_SIZE_2MB - 1)) != 0))
#define BYTES_TO_PAGES_4KB(Size)  (((Size) >> PAGE_SHIFT_4KB) + \
                                  (((Size) & (PAGE_SIZE_4KB - 1)) != 0))
// The BYTE_OFFSET macro takes a virtual address and returns the byte offset
// of that address within the page.
#define BYTE_OFFSET_1GB(Va) ((UINT64)(Va) & PAGE_OFFSET_MASK_1GB)
#define BYTE_OFFSET_2MB(Va) ((UINT64)(Va) & PAGE_OFFSET_MASK_2MB)
#define BYTE_OFFSET_4KB(Va) ((UINT64)(Va) & PAGE_OFFSET_MASK_4KB)

// The PAGE_ALIGN macro takes a virtual address and returns a page-aligned
// virtual address for that page.
#define PAGE_ALIGN_1GB(Va) ((VOID*)((UINT64)(Va) & ~PAGE_OFFSET_MASK_1GB))
#define PAGE_ALIGN_2MB(Va) ((VOID*)((UINT64)(Va) & ~PAGE_OFFSET_MASK_2MB))
#define PAGE_ALIGN_4KB(Va) ((VOID*)((UINT64)(Va) & ~PAGE_OFFSET_MASK_4KB))

// The ADDRESS_AND_SIZE_TO_SPAN_PAGES macro takes a virtual address and
// size and returns the number of pages spanned by the size.
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES_1GB(Va,Size) \
    ((BYTE_OFFSET_1GB(Va) + ((UINT64) (Size)) + PAGE_OFFSET_MASK_1GB) >> PAGE_SHIFT_1GB)
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES_2MB(Va,Size) \
    ((BYTE_OFFSET_2MB(Va) + ((UINT64) (Size)) + PAGE_OFFSET_MASK_2MB) >> PAGE_SHIFT_2MB)
#define ADDRESS_AND_SIZE_TO_SPAN_PAGES_4KB(Va,Size) \
    ((BYTE_OFFSET_4KB(Va) + ((UINT64) (Size)) + PAGE_OFFSET_MASK_4KB) >> PAGE_SHIFT_4KB)

//! Vol 3A, Table 3-1. Code- and Data-Segment Types
typedef enum _PAGE_PERMISSION
{
	PAGE_WRITE = 1 << 0, // Set Rw bit in page-table entry
	PAGE_EXECUTE = 1 << 1, // If this flag isn't set, try to set NX bit
	PAGE_SUPERVISOR	= 1 << 2, // Access allowed only from (CPL < 3)

	// These are combinations of the previous flags
	PAGE_NOACCESS = 0,
	PAGE_READONLY = 0,
	PAGE_READWRITE = PAGE_WRITE,
	PAGE_EXECUTE_READ = PAGE_EXECUTE,
	PAGE_EXECUTE_READWRITE = PAGE_EXECUTE | PAGE_WRITE,
	PAGE_SUPERVISOR_READONLY = PAGE_SUPERVISOR,
	PAGE_SUPERVISOR_READWRITE = PAGE_SUPERVISOR | PAGE_WRITE,
	PAGE_SUPERVISOR_EXECUTE_READ = PAGE_SUPERVISOR | PAGE_EXECUTE,
	PAGE_SUPERVISOR_EXECUTE_READWRITE = PAGE_SUPERVISOR | PAGE_EXECUTE | PAGE_WRITE,
} PAGE_PERMISSION, *PPAGE_PERMISSION;

typedef union _VA_ADDRESS64
{
	UINT64 qwValue;

 //! Figure 4-8. Linear-Address Translation to a 4-KByte Page using IA-32e Paging
	struct {
		UINT64 Offset : 12;		//!< 0-11
		UINT64 PteIndex : 9;	//!< 12-20
		UINT64 PdeIndex : 9;	//!< 21-29
		UINT64 PdpteIndex : 9;	//!< 30-38
		UINT64 Pml4eIndex : 9;	//!< 39-47
		UINT64 Reserved0 : 16;	//!< 48-63
	} FourKb;
 //! Figure 4-9. Linear-Address Translation to a 2-MByte Page using IA-32e Paging
	struct {
		UINT64 Offset : 21;		//!< 0-20
		UINT64 PdeIndex : 9;	//!< 21-29
		UINT64 PdpteIndex : 9;	//!< 30-38
		UINT64 Pml4eIndex : 9;	//!< 39-47
		UINT64 Reserved0 : 16;	//!< 48-63
	} TwoMb;
 //! Figure 4-10. Linear-Address Translation to a 1-GByte Page using IA-32e Paging
	struct {
		UINT64 Offset : 30;		//!< 0-29
		UINT64 PdpteIndex : 9;	//!< 30-38
		UINT64 Pml4eIndex : 9;	//!< 39-47
		UINT64 Reserved0 : 16;	//!< 48-63
	} OneGb;
} VA_ADDRESS64, *PVA_ADDRESS64;
C_ASSERT(sizeof(UINT64) == sizeof(VA_ADDRESS64));

//! Vol 3A, Table 4-14. Format of an IA-32e PML4 Entry (PML4E) that References a Page-Directory-Pointer Table
typedef union _PML4E64
{
	UINT64 qwValue;
	struct {
		UINT64 Present : 1;			//!< 0 Present
		UINT64 Rw : 1;				//!< 1 Read/write; if 0, writes are not allowed
		UINT64 Us : 1;				//!< 2 User/supervisor; if 0, user-mode access isn't allowed
		UINT64 Pwt : 1;				//!< 3 Page-level write-through
		UINT64 Pcd : 1;				//!< 4 Page-level cache disable
		UINT64 Access : 1;			//!< 5 Accessed; indicates whether software has accessed the page
		UINT64 Ignored0 : 1;		//!< 6 
		UINT64 PageSize : 1;		//!< 7 Page-Size; must be 0
		UINT64 Ignored1 : 4;		//!< 8-11
		UINT64 Addr : 40;			//!< 12-51 Physical address that the entry points to
		UINT64 Ignored2 : 11;		//!< 52-62
		UINT64 Nx : 1;				//!< 63 If IA32_EFER.NXE = 1, execute-disable
	};
} PML4E64, *PPML4E64;
C_ASSERT(sizeof(UINT64) == sizeof(PML4E64));

//! Vol 3A, Table 4-15. Format of an IA-32e Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page
typedef union _PDPTE1G64
{
	UINT64 qwValue;
	struct {
		UINT64 Present : 1;			//!< 0 Present
		UINT64 Rw : 1;				//!< 1 Read/write; if 0, writes are not allowed
		UINT64 Us : 1;				//!< 2 User/supervisor; if 0, user-mode access isn't allowed
		UINT64 Pwt : 1;				//!< 3 Page-level write-through
		UINT64 Pcd : 1;				//!< 4 Page-level cache disable
		UINT64 Access : 1;			//!< 5 Accessed; indicates whether software has accessed the page
		UINT64 Dirty : 1;			//!< 6 Dirty; indicates whether software has written to the page
		UINT64 PageSize : 1;		//!< 7 Page-Size; Must be 1 for 1GB pages
		UINT64 Global : 1;			//!< 8 Global; if CR4.PGE = 1, determines whether the translation is global
		UINT64 Ignored0 : 3;		//!< 9-11
		UINT64 Pat : 1;				//!< 12 Page Attribute Table;
		UINT64 Reserved0 : 17;		//!< 13-29
		UINT64 Addr : 22;			//!< 30-51 Physical address that the entry points to
		UINT64 Ignored1 : 7;		//!< 52-58
		UINT64 Protkey : 4;			//!< 59-62 Protection key; if CR4.PKE = 1, determines the 
									//!< protection key of the page
		UINT64 Nx : 1;				//!< 63 If IA32_EFER.NXE = 1, execute-disable
	};
} PDPTE1G64, *PPDPTE1G64;
C_ASSERT(sizeof(UINT64) == sizeof(PDPTE1G64));

//! Vol 3A, Table 4-16. Format of an IA-32e Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory
typedef union _PDPTE64
{
	UINT64 qwValue;
	struct {
		UINT64 Present : 1;			//!< 0 Present
		UINT64 Rw : 1;				//!< 1 Read/write; if 0, writes are not allowed
		UINT64 Us : 1;				//!< 2 User/supervisor; if 0, user-mode access isn't allowed
		UINT64 Pwt : 1;				//!< 3 Page-level write-through
		UINT64 Pcd : 1;				//!< 4 Page-level cache disable
		UINT64 Access : 1;			//!< 5 Accessed; indicates whether software has accessed the page
		UINT64 Dirty : 1;			//!< 6 Dirty; indicates whether software has written to the page
		UINT64 PageSize : 1;		//!< 7 Page-Size; must be 0 to refernce PDE
		UINT64 Reserved1 : 4;		//!< 8-11
		UINT64 Addr : 40;			//!< 12-51 Physical address that the entry points to
		UINT64 Reserved2 : 11;		//!< 52-62
		UINT64 Nx : 1;				//!< 63 If IA32_EFER.NXE = 1, execute-disable
	};
} PDPTE64, *PPDPTE64;
C_ASSERT(sizeof(UINT64) == sizeof(PDPTE64));

//! Vol 3A, Table 4-17. Format of an IA-32e Page-Directory Entry that Maps a 2-MByte Page
typedef union _PDE2MB64
{
	UINT64 qwValue;
	struct {
		UINT64 Present : 1;			//!< 0 Present
		UINT64 Rw : 1;				//!< 1 Read/write; if 0, writes are not allowed
		UINT64 Us : 1;				//!< 2 User/supervisor; if 0, user-mode access isn't allowed
		UINT64 Pwt : 1;				//!< 3 Page-level write-through
		UINT64 Pcd : 1;				//!< 4 Page-level cache disable
		UINT64 Access : 1;			//!< 5 Accessed; indicates whether software has accessed the page
		UINT64 Dirty : 1;			//!< 6 Dirty; indicates whether software has written to the page
		UINT64 PageSize : 1;		//!< 7 Page-Size; must be 1 for 2MB pages
		UINT64 Global : 1;			//!< 8 Global; if CR4.PGE = 1, determines whether the translation is global
		UINT64 Ignored0 : 3;		//!< 9-11
		UINT64 Pat : 1;				//!< 12 Page Attribute Table;
		UINT64 Reserved0 : 8;		//!< 13-20
		UINT64 Addr : 31;			//!< 21-51 Physical address that the entry points to
		UINT64 Ignored1 : 7;		//!< 52-58
		UINT64 Protkey : 4;			//!< 59-62 Protection key; if CR4.PKE = 1, determines the 
									//!< protection key of the page
		UINT64 Nx : 1;				//!< 63 If IA32_EFER.NXE = 1, execute-disable
	};
} PDE2MB64, *PPDE2MB64;
C_ASSERT(sizeof(UINT64) == sizeof(PDE2MB64));

//! Vol 3A, Table 4-18. Format of an IA-32e Page-Directory Entry that References a Page Table
typedef union _PDE64
{
	UINT64 qwValue;
	struct {
		UINT64 Present : 1;			//!< 0 Present
		UINT64 Rw : 1;				//!< 1 Read/write; if 0, writes are not allowed
		UINT64 Us : 1;				//!< 2 User/supervisor; if 0, user-mode access isn't allowed
		UINT64 Pwt : 1;				//!< 3 Page-level write-through
		UINT64 Pcd : 1;				//!< 4 Page-level cache disable
		UINT64 Access : 1;			//!< 5 Accessed; indicates whether software has accessed the page
		UINT64 Reserved0 : 1;		//!< 6
		UINT64 PageSize : 1;		//!< 7 Page-Size; must be 0 to reference PTE
		UINT64 Reserved1 : 4;		//!< 8-11
		UINT64 Addr : 40;			//!< 12-51 Physical address that the entry points to
		UINT64 Reserved2 : 11;		//!< 52-62
		UINT64 Nx : 1;				//!< 63 If IA32_EFER.NXE = 1, execute-disable
	};
} PDE64, *PPDE64;
C_ASSERT(sizeof(UINT64) == sizeof(PDE64));

//! Vol 3A, Table 4-19. Format of an IA-32e Page-Table Entry that Maps a 4-KByte Page
typedef union _PTE64
{
	UINT64 qwValue;
	struct {
		UINT64 Present : 1;			//!< 0 Present
		UINT64 Rw : 1;				//!< 1 Read/write; if 0, writes are not allowed
		UINT64 Us : 1;				//!< 2 User/supervisor; if 0, user-mode access isn't allowed
		UINT64 Pwt : 1;				//!< 3 Page-level write-through
		UINT64 Pcd : 1;				//!< 4 Page-level cache disable
		UINT64 Access : 1;			//!< 5 Accessed; indicates whether software has accessed the page
		UINT64 Dirty : 1;			//!< 6 Dirty; indicates whether software has written to the page
		UINT64 Pat : 1;				//!< 7 Page Attribute Table;
		UINT64 Global : 1;			//!< 8 Global; if CR4.PGE = 1, determines whether the translation is global
		UINT64 Ignored0 : 3;		//!< 9-11
		UINT64 Addr : 40;			//!< 12-51 Physical address that the entry points to
		UINT64 Ignored1 : 7;		//!< 52-58
		UINT64 Protkey : 4;			//!< 59-62 Protection key; if CR4.PKE = 1, determines the 
									//!< protection key of the page
		UINT64 Nx : 1;				//!< 63 If IA32_EFER.NXE = 1, execute-disable
	};
} PTE64, *PPTE64;
C_ASSERT(sizeof(UINT64) == sizeof(PTE64));

// All available page types
typedef enum _PAGE_TYPE64
{
	PAGE_TYPE_4KB = 0,
	PAGE_TYPE_2MB,
	PAGE_TYPE_1GB,	
} PAGE_TYPE64, *PPAGE_TYPE64;

// 1 PML4 points to up to 512 PDPTE
// 1 PDPT points to up to 1*512=512GB
// 1 PD points to up to 2MB*512=1GB
// 1 PT points to up to 4KB*512=2MB
// This page table can point to a max of 128GB and it's size is 269MB
typedef struct _PAGE_TABLE64
{
	DECLSPEC_ALIGN(PAGE_SIZE) PML4E64 atPml4[PAGING64_PML4E_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) PDPTE64 atPdpt[PAGING64_PDPTE_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) PDE64 atPd[PAGING64_PDPTE_COUNT][PAGING64_PDE_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) PTE64 atPt[PAGING64_PDPTE_COUNT][PAGING64_PDE_COUNT][PAGING64_PTE_COUNT];
} PAGE_TABLE64, *PPAGE_TABLE64;
C_ASSERT(1075847168 == sizeof(PAGE_TABLE64));

// Max virtual address that can be used with this page-table is:
#define PAGE_TABLE64_MAX_VIRTUAL_ADDRESS 0x0000007fffffffff

/**
* Convert a physical address to a virtual address
* @param qwPhysicalAddress - physical address to convert
* @param pqwVirtualAddress - virtual address that maps the physical address
* @return TRUE on success, else FALSE
*/
typedef BOOLEAN(*PAGING64_PHYSICAL_TO_VIRTUAL_PFN)(
	IN const UINT64 qwPhysicalAddress,
	OUT PUINT64 pqwVirtualAddress
);
BOOLEAN
PAGING64_UefiPhysicalToVirtual(
	IN const UINT64 qwPhysicalAddress,
	OUT PUINT64 pqwVirtualAddress
);

// Everything we need to access a page table
typedef struct _PAGE_TABLE64_HANDLE
{
	PPML4E64 patPml4;					// Virtual address of PML4 table
	UINT64 qwPml4PhysicalAddress;		// Physical address of PML4 table
	BOOL bOneGbSupported;				// 1GB pages are supported by processor
	BOOL bNxBitSupported;				// NX bit is supported by processor
	BOOL bMtrrSupported;				// MTRR is supported by processor
	BOOL bPatSupported;					// PAT is supported by processor
	UINT8 acPatMemTypes[8];				// PAT memory types per index from IA32_PAT MSR
	PLOG_HANDLE ptLog;					// Log handle

	// Function pointer to a function that converts physical addresses to virtual
	PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual;

	// NOTE: We use these to edit the page-table assuming they're continuous in both
	// virtual memory and physical memory
	PAGE_TYPE64 eMinPageType;			// Page-Table doesn't contain entries to pages 
										// below this size
	UINT64 qwMaxVirtualAddress;			// Max virtual address that can be mapped 
										// with page-table
	UINT64 qwPdptPhysicalAddress;		// Physical address of PDPT
	UINT64 qwPdArrayPhysicalAddress;	// Physical address of 1st PD in PD tables array
	UINT64 qwPtArrayPhysicalAddress;	// Physical address of 1st PT in PT tables array
	PPDPTE64 patPdpt;					// Virtual address of PDPT table

	// Virtual address of 1st PD in PD tables array
	PDE64 (*patPdArray)[PAGING64_PDPTE_COUNT];

	// Virtual address of 1st PT in PT tables array
	PTE64 (*patPtArray)[PAGING64_PDPTE_COUNT][PAGING64_PDE_COUNT];
} PAGE_TABLE64_HANDLE, *PPAGE_TABLE64_HANDLE;
C_ASSERT(sizeof(PVOID) == FIELD_SIZE(PAGE_TABLE64_HANDLE, patPdArray));
C_ASSERT(sizeof(PVOID) == FIELD_SIZE(PAGE_TABLE64_HANDLE, patPtArray));
C_ASSERT(0x1000 == sizeof(PDE64[PAGING64_PDPTE_COUNT]));
C_ASSERT(0x200000 == sizeof(PTE64[PAGING64_PDPTE_COUNT][PAGING64_PDE_COUNT]));

/**
* Verify IA-32e paging is enabled (64bit)
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_IsIa32ePagingEnabled(
	VOID
);

/**
* Initialize a new page-table by zeroing out all the entries
* @param ptPageTable - Page Table to initialize
* @param pfnPhysicalToVirtual - convert a physical address to virtual address
* @param ptLog - log handle
* @param qwMaxVirtualAddress - max virtual address that can be mapped by page-table
* @param eMinPageType - page-Table won't contain entries to pages below this size
* @param phOutPageTable - open handle to the new page-table
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_InitPageTable(
	INOUT PPAGE_TABLE64 ptPageTable,
	IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
	IN const PLOG_HANDLE ptLog,
	IN const UINT64 qwMaxVirtualAddress,
	IN const PAGE_TYPE64 eMinPageType,
	OUT PPAGE_TABLE64_HANDLE phOutPageTable
);

/**
* Initialize the given page table handle
* @param phPageTable - Page Table handle to initialize
* @param pfnPhysicalToVirtual - convert a physical address to virtual address
* @param qwPml4PhysicalAddress - physical address of PML4 array
* @param ptLog - log handle
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_OpenPageTableHandle(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const PAGING64_PHYSICAL_TO_VIRTUAL_PFN pfnPhysicalToVirtual,
	IN const UINT64 qwPml4PhysicalAddress,
	IN const PLOG_HANDLE ptLog
);

/**
* Find the physical address mapped by the given virtual address
* @param phPageTable - Page-Table handle initialized with PAGING64_InitPageTableHandle
* @param qwVirtualAddress - virtual address to query
* @param pqwPhysicalAddress - physical address the virtual address is mapped to
* @param pePageType - type of mapped page
* @param pePagePermissions - permissions on page
* @param peMemType - type of physical memory mapped by the page
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_VirtualToPhysical(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	OUT PUINT64 pqwPhysicalAddress,
	OUT PPAGE_TYPE64 pePageType,
	OUT PPAGE_PERMISSION pePagePermissions,
	OUT PIA32_PAT_MEMTYPE peMemType
);

/**
* Check if virtual address is mapped by page table
* @param qwVirtualAddress - virtual address to query
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_IsVirtualMapped(
	IN const PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 cbSize
);

/**
* Unmap all pages in the virtual address range
* @param phPageTable - Page-Table handle initialized with PAGING64_InitPageTableHandle
* @param qwVirtualAddress - virtual address to unmap pages from
* @param cbSize - size of buffer to unmap
* @return TRUE on success, else FALSE
*/
VOID
PAGING64_UnmapVirtual(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 cbSize
);

/**
* Map the physical address to the given virtual address
* with set permission and memory type
* @param phPageTable - Page-Table handle initialized with PAGING64_InitPageTableHandle
* @param qwPhysicalAddress - physical address to map
* @param qwVirtualAddress - virtual address to map physical address at
* @param cbSize - size of buffer to unmap
* @param ePagePermission - permissions to set on mapped pages
* @param eMemType - memory type to use on mapped pages
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_MapPhysicalToVirtual(
	INOUT PPAGE_TABLE64_HANDLE phPageTable,
	IN const UINT64 qwPhysicalAddress,
	IN const UINT64 qwVirtualAddress,
	IN const UINT64 cbSize,
	IN const PAGE_PERMISSION ePagePermission,
	IN const IA32_PAT_MEMTYPE eMemType
);

/**
* Copy all present entries from source page-table to destination page-table
* that are below the destination page-table max virtual address
* @param phDstPageTable - Destination Page-Table to copy entries to
* @param phSrcPageTable - Source Page-Table to copy entries from
* @return TRUE on success, else FALSE
*/
BOOLEAN
PAGING64_CopyPageTable(
	INOUT PPAGE_TABLE64_HANDLE phDstPageTable,
	IN const PPAGE_TABLE64_HANDLE phSrcPageTable
);

#pragma pack(pop)
#pragma warning(pop)
#endif  /* __INTEL_PAGING64_H__ */
