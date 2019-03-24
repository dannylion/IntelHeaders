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
* @file       tss.h
* @section    Task State Segment structures and definitions
*/

#ifndef __INTEL_TSS_H__
#define __INTEL_TSS_H__

#include "ntdatatypes.h"
#include "gdt64.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 3A, Figure 7-2. 32-Bit Task-State Segment (TSS)
typedef struct _TSS32{
    UINT16 Link;            // Segment selector for TSS of previous task
    UINT16 Reserved0;
    UINT32 Esp0;            // Stack pointer for privilege 0 task
    UINT16 Ss0;             // Stack selector for privilege 0 task
    UINT16 Reserved1;
    UINT32 Esp1;            // Stack pointer for privilege 1 task
    UINT16 Ss1;             // Stack selector for privilege 1 task
    UINT16 Reserved2;
    UINT32 Esp2;            // Stack pointer for privilege 2 task
    UINT16 Ss2;             // Stack selector for privilege 2 task
    UINT16 Reserved3;
    UINT32 Cr3;             // Page-Table used by task
    UINT32 Eip;             // GP Registers prior to task switch
    UINT32 Eflags;
    UINT32 Eax;
    UINT32 Ecx;
    UINT32 Edx;
    UINT32 Ebx;
    UINT32 Esp;
    UINT32 Ebp;
    UINT32 Esi;
    UINT32 Edi;
    UINT16 Es;              // Segment selectors prior to task switch
    UINT16 Reserved4;
    UINT16 Cs;
    UINT16 Reserved5;
    UINT16 Ss;
    UINT16 Reserved6;
    UINT16 Ds;
    UINT16 Reserved7;
    UINT16 Fs;
    UINT16 Reserved8;
    UINT16 Gs;
    UINT16 Reserved9;
    UINT16 Ldt;             // LDT selector of the task
    UINT16 Reserved10;      
    UINT16 DebugTrap : 1;   // Raise #DB when task is switched to this TSS
    UINT16 Reserved11 : 15;
    UINT16 Iopb;            // Offset from TSS base to IO permission bitmap
} TSS32, *PTSS32;
C_ASSERT(104 == sizeof(TSS32));

//! Vol 3A, Figure 7-3. TSS Descriptor
typedef union _TSS_DESCRIPTOR32 {
    UINT64 qwValue;
    struct {
        UINT64 BaseMid : 8;     //!< 0-7    TSS Base bits 16-23
        UINT64 Type : 4;        //!< 8-11   See SYSTEM_SEGMENT_TYPE
        UINT64 Reserved0 : 1;   //!< 12     0
        UINT64 Dpl : 2;         //!< 13-14  Descriptor privilege level
        UINT64 Present : 1;     //!< 15     Is descriptor present
        UINT64 LimitHigh : 4;   //!< 16-19  TSS Limit bits 16-19
        UINT64 Avl : 1;         //!< 20     Available for use by system software
        UINT64 Reserved1 : 2;   //!< 21-22  0
        UINT64 Granularity : 1; //!< 23     Granularity
        UINT64 BaseHigh : 8;    //!< 24-31  TSS Base bits 24-31
        UINT64 LimitLow : 16;   //!< 32-47  TSS Limit bits 0-15
        UINT64 BaseLow : 16;    //!< 48-63  TSS Base bits 0-15
    };
} TSS_DESCRIPTOR32, *PTSS_DESCRIPTOR32;
C_ASSERT(8 == sizeof(TSS_DESCRIPTOR32));

//! Vol 3A, Figure 7-4. Format of TSS and LDT Descriptors in 64-bit Mode
typedef struct _TSS_DESCRIPTOR64 {
    UINT16 Limit;           //!< TSS Limit bits 0-15
    UINT16 BaseLow;         //!< TSS Base bits 0-15
    UINT32 BaseMid0 : 8;    //!< TSS Base bits 16-23
    UINT32 Type : 4;        //!< See SYSTEM_SEGMENT_TYPE
    UINT32 Reserved0 : 1;
    UINT32 Dpl : 2;         //!< Descriptor privilege level
    UINT32 Present : 1;     //!< Is descriptor present
    UINT32 LimitHigh : 4;   //!< TSS Limit bits 16-19
    UINT32 Avl : 1;         //!< Available for use by system software
    UINT32 Reserved1 : 2;
    UINT32 Granularity : 1; //!< Granularity
    UINT32 BaseMid1 : 8;    //!< TSS Base bits 24-31
    UINT32 BaseHigh;        //!< TSS Base bits 24-63
    UINT32 Reserved2;
} TSS_DESCRIPTOR64, *PTSS_DESCRIPTOR64;
C_ASSERT(16 == sizeof(TSS_DESCRIPTOR64));

typedef TSS_DESCRIPTOR64 LDT_DESCRIPTOR64;
typedef PTSS_DESCRIPTOR64 PLDT_DESCRIPTOR64;

//! Vol 3A, Figure 7-11. 64-Bit TSS Format
// NOTE: According to https://wiki.osdev.org/TSS you can disable IO bitmap
// by setting: TSS64.Iopb = sizeof(TSS64)
typedef struct _TSS64
{
    UINT32 Reserved0;
    UINT64 Rsp0;        // Stack pointers (RSP) for privilege levels 0-2
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Reserved1;
    UINT64 Ist[7];      // Interrupt Stack Table (IST) pointers
    UINT64 Reserved2;
    UINT16 Reserved3;
    UINT16 Iopb;        // Offset from TSS base to IO permission bitmap
} TSS64, *PTSS64;
C_ASSERT(104 == sizeof(TSS64));

#pragma pack(pop)
#pragma warning(pop)
#endif  // __INTEL_TSS_H__
