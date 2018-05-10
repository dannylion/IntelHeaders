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
* @file        faults.h
* @section    Intel fault codes
*/

#ifndef __INTEL_GDT_H__
#define __INTEL_GDT_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 3A, 3.4.2 Segment Selectors
#define MAX_DESCRIPTORS_COUNT 8192

//! Vol 3A, Figure 2-6. Memory Management Registers
typedef struct _GDTR64
{
    UINT16 Limit;    //!< 0-15
    UINT64 Base;    //!< 16-79
} GDTR64, *PGDTR64;

typedef GDTR64 IDTR64;
typedef PGDTR64 PIDTR64;

//! Vol 3A, Figure 3-6. Segment Selector
typedef union _SEGMENT_SELECTOR
{
    UINT16 wValue;
    struct {
        UINT16 Rpl : 2;     //!< 0-1    Request privilege level
        UINT16 Ti : 1;      //!< 2      0=GDT, 1=LDT
        UINT16 Index : 13;  //!< 3-15   Index of segment descriptor in table
    };
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;
C_ASSERT(sizeof(UINT16) == sizeof(SEGMENT_SELECTOR));

//! Vol 3A, Figure 3-8. Segment Descriptor
typedef union _SEGMENT_DESCRIPTOR
{
    UINT64 qwValue;
    struct {
        UINT64 LimitLow : 16;   //!< 0-15   Segment size bits 0:15
        UINT64 BaseLow : 24;    //!< 16-39  Segment base address bits 0:23
        UINT64 Type : 4;        //!< 40-43  See SEGMENT_TYPE
        UINT64 S : 1;           //!< 44     1=System segment, 0=code/data segment
        UINT64 Dpl : 2;         //!< 45-46  Ring level 0=kernel, 3=user
        UINT64 P : 1;           //!< 47     1=present segment 0=invalid segment
        UINT64 LimitHigh : 4;   //!< 48-51  Segment size bits 16:19
        UINT64 Avl : 1;         //!< 52     Available for use by system software
        UINT64 L : 1;           //!< 53     1=64bit segment, 0=not 64bit
        UINT64 DB : 1;          //!< 54     Changes by section type:
                                //          Code - 1=32bit addresses, 0=16bit addresses
                                //          Stack Segment - 1=32bit stack pointer, 0=16bit
                                //          Data Expand Down - 1=4GB upper boundary, 0=64KB
        UINT64 G : 1;           //!< 55     0=1 byte granularity, 1=4KB granularity
        UINT64 BaseHigh : 8;    //!< 56-63  Segment base address bits 24:31
    };
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;
C_ASSERT(sizeof(UINT64) == sizeof(SEGMENT_DESCRIPTOR));

//! Vol 3A, Table 3-1. Code- and Data-Segment Types
// Data Segments glossary: accessed (A), writable (W), expand down (E)
// Code Segments glossary: accessed (A), readable (R), conforming (C)
// A (accessed) - the segment has been used
// W (writable) - data segment can be written to
// E (expand down) -    data segment expands down, meaning its end is at (base-limit) 
//                        instead of (base+limit) and it grows down from base (like a stack)
// R (readable) - code segment can be read
// C (conforming) - A transfer into a nonconforming segment at a different privilege level 
//                    results in #GP fault, unless a call gate or task gate is used
typedef enum _SEGMENT_TYPE
{
    SEGMENT_TYPE_DATA_READ_ONLY = 0,
    SEGMENT_TYPE_DATA_A = 1,
    SEGMENT_TYPE_DATA_W = 2,
    SEGMENT_TYPE_DATA_WA = 3,
    SEGMENT_TYPE_DATA_E = 4,
    SEGMENT_TYPE_DATA_EA = 5,
    SEGMENT_TYPE_DATA_EW = 6,
    SEGMENT_TYPE_DATA_EWA = 7,
    SEGMENT_TYPE_CODE_READ_ONLY = 8,
    SEGMENT_TYPE_CODE_A = 9,
    SEGMENT_TYPE_CODE_R = 10,
    SEGMENT_TYPE_CODE_RA = 11,
    SEGMENT_TYPE_CODE_C = 12,
    SEGMENT_TYPE_CODE_CA = 13,
    SEGMENT_TYPE_CODE_CR = 14,
    SEGMENT_TYPE_CODE_CRA = 15,
} SEGMENT_TYPE, *PSEGMENT_TYPE;

//! Vol 3A, Table 3-2. System-Segment and Gate-Descriptor Types
typedef enum _SYSTEM_SEGMENT_TYPE
{
    // 0 Reserved
    SYSTEM_SEGMENT_TYPE_16BIT_TSS_AVAILABLE = 1,
    SYSTEM_SEGMENT_TYPE_LDT = 2,
    SYSTEM_SEGMENT_TYPE_16BIT_TSS_BUSY = 3,
    SYSTEM_SEGMENT_TYPE_16BIT_CALL_GATE = 4,
    SYSTEM_SEGMENT_TYPE_TASK_GATE = 5,
    SYSTEM_SEGMENT_TYPE_16BIT_INT_GATE = 6,
    SYSTEM_SEGMENT_TYPE_16BIT_TRAP_GATE = 7,
    // 8 Reserved
    SYSTEM_SEGMENT_TYPE_32BIT_TSS_AVAILABLE = 9,
    // 10 Reserved
    SYSTEM_SEGMENT_TYPE_32BIT_TSS_BUSY = 11,
    SYSTEM_SEGMENT_TYPE_32BIT_CALL_GATE = 12,
    // 13 Reserved
    SYSTEM_SEGMENT_TYPE_32BIT_INT_GATE = 14,
    SYSTEM_SEGMENT_TYPE_32BIT_TRAP_GATE = 15,
} SYSTEM_SEGMENT_TYPE, *PSYSTEM_SEGMENT_TYPE;

typedef struct _GDT_TABLE
{
    SEGMENT_DESCRIPTOR atDescriptors[MAX_DESCRIPTORS_COUNT];
} GDT_TABLE, *PGDT_TABLE;

typedef GDT_TABLE IDT_TABLE;
typedef PGDT_TABLE PIDT_TABLE;

// Vol 3A, Figure 7-11. 64-Bit TSS Format
typedef struct _TSS64
{
    UINT32 Reserved0;
    UINT64 Rsp0;        // Stack pointers (RSP) for privilege levels 0-2
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Ist[8];      // interrupt stack table (IST) pointers
    UINT64 Reserved1;
    UINT16 Reserved2;
    UINT16 IoMapBase;   // Offset to the I/O permission bitmap from the TSS base
} TSS64, *PTSS64;

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_GDT_H__ */
