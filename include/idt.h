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
* @file       idt.h
* @section    Intel fault codes and Interrupt Descriptor Table
*/

#ifndef __INTEL_IDT_H__
#define __INTEL_IDT_H__

#include "ntdatatypes.h"
#include "gdt64.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! http://wiki.osdev.org/Exceptions
typedef enum _FAULT_CODE {
    FAULT_CODE_DE = 0,              //!< Divide by zero Error #DE
    FAULT_CODE_DB = 1,              //!< Debug Fault/Trap #DB
    FAULT_CODE_NMI = 2,             //!< Non Maskable Interrupt
    FAULT_CODE_BP = 3,              //!< Breakpoint #BP
    FAULT_CODE_OF = 4,              //!< Overflow #OF
    FAULT_CODE_BR = 5,              //!< Bound Range Exceeded #BR
    FAULT_CODE_UD = 6,              //!< Invalid Opcode #UD
    FAULT_CODE_NM = 7,              //!< Device Not Available #NM
    FAULT_CODE_DF = 8,              //!< Double Fault #DF
    FAULT_CODE_CSO = 9,             //!< Coprocessor Segment Overrun Fault
    FAULT_CODE_TS = 10,             //!< Invalid TSS #TS
    FAULT_CODE_NP = 11,             //!< Segment Not Present #NP
    FAULT_CODE_SS = 12,             //!< Stack Segment Fault #SS
    FAULT_CODE_GP = 13,             //!< General Protection Fault #GP
    FAULT_CODE_PF = 14,             //!< Page Fault #PF
    // 15 Reserved
    FAULT_CODE_MF = 16,             //!< x87 Floating - Point Exception #MF
    FAULT_CODE_AC = 17,             //!< Alignment Check Fault #AC
    FAULT_CODE_MC = 18,             //!< Machine Check #MC
    FAULT_CODE_XM = 19,             //!< SIMD Floating - Point Exception #XM / #XF
    FAULT_CODE_XF = FAULT_CODE_XM,
    FAULT_CODE_VE = 20,             //!< Virtualization Exception #VE
    // 21 - 29 Reserved
    FAULT_CODE_SX = 30,             //!< Security Exception #SX
    // 31 Reserved
} FAULT_CODE, *PFAULT_CODE;

//! https://wiki.osdev.org/Exceptions
typedef union _PAGE_FAULT_ERROR_CODE {
    UINT32 dwValue;
    struct {
        UINT32 Present : 1;             //!< 0      0=not-present, 1=protection violation
        UINT32 Write : 1;               //!< 1      0=page read, 1=page write
        UINT32 User : 1;                //!< 2      0=ring 0-2, 1=ring 3
        UINT32 Reserved0 : 1;           //!< 3      0
        UINT32 InstructionFetch : 1;    //!< 4      Page-fault caused by instruction fetch
        UINT32 Reserved1 : 27;          //!< 5-31   0
    };
} PAGE_FAULT_ERROR_CODE, *PPAGE_FAULT_ERROR_CODE;
C_ASSERT(sizeof(UINT32) == sizeof(PAGE_FAULT_ERROR_CODE));

//! Figure 6-1. Relationship of the IDTR and IDT
// IDTR is built exactly like GDTR
typedef GDTR64 IDTR64;
typedef PGDTR64 PIDTR64;

#define IDT_MAX_ENTRIES 256

//! Vol 3A, Figure 6-2. IDT Gate Descriptors
typedef union _IDT_GATE_TASK32 {
    UINT64 qwValue;
    struct {
        UINT64 Reserved0 : 16;      //!< 0-15   0
        UINT64 TssSelector : 16;    //!< 16-31
        UINT64 Reserved1 : 8;       //!< 32-39  0
        UINT64 Type : 5;            //!< 40-44  SYSTEM_SEGMENT_TYPE_TASK_GATE
        UINT64 Dpl : 2;             //!< 45-46  Descriptor privilege level
        UINT64 Present : 1;         //!< 47     Is descriptor present
        UINT64 Reserved2 : 16;      //!< 48-63
    };
} IDT_GATE_TASK32, *PIDT_GATE_TASK32;
C_ASSERT(sizeof(UINT64) == sizeof(IDT_GATE_TASK32));

typedef union _IDT_GATE_INTERRUPT32 {
    UINT64 qwValue;
    struct {
        UINT64 OffsetLow : 16;          //!< 0-15   ISR offset bits 0-15
        UINT64 SegmentSelector : 16;    //!< 16-31  Interrupt CS selector
        UINT64 Reserved0 : 8;           //!< 32-39  0
        UINT64 Type : 5;                //!< 40-44  See SYSTEM_SEGMENT_TYPE
        UINT64 Dpl : 2;                 //!< 45-46  Descriptor privilege level
        UINT64 Present : 1;             //!< 47     Is descriptor present
        UINT64 OffsetHigh : 16;         //!< 48-63  ISR offset bits 16-31
    };
} IDT_GATE_INTERRUPT32, *PIDT_GATE_INTERRUPT32;
C_ASSERT(sizeof(UINT64) == sizeof(IDT_GATE_INTERRUPT32));

// Trap Gate looks exactly the same except the gate type field
typedef IDT_GATE_INTERRUPT32 IDT_GATE_TRAP32;
typedef PIDT_GATE_INTERRUPT32 PIDT_GATE_TRAP32;

//! Vol 3A, Figure 6-6. Error Code
typedef union _IDT_ERROR_CODE {
    UINT32 dwValue;
    struct {
        UINT32 Ext : 1;                 //!< 0      HW interrupt error
        UINT32 Idt : 1;                 //!< 1      0=GDT/LDT, 1=IDT
        UINT32 Ti : 1;                  //!< 2      0=GDT, 1=LDT
        UINT32 SegmentSelector : 16;    //!< 3-18   Segment selector index
        UINT32 Reserved0 : 13;          //!< 19-31
    };
} IDT_ERROR_CODE, *PIDT_ERROR_CODE;
C_ASSERT(sizeof(UINT32) == sizeof(IDT_ERROR_CODE));

//! Vol 3A, Figure 6-7. 64-Bit IDT Gate Descriptors
typedef struct _IDT_GATE_INTERRUPT64 {
    UINT16 OffsetLow;                   //!< 0-15   Offset bits 0-15
    SEGMENT_SELECTOR SegmentSelector;   //!< 16-31  Handler code segment
    UINT16 Ist : 3;                     //!< 32-34  Interrupt Stack Table
    UINT16 Reserved0 : 5;               //!< 35-39  0
    UINT16 Type : 4;                    //!< 40-43  See SYSTEM_SEGMENT_TYPE
    UINT16 Reserved1 : 1;               //!< 44     0
    UINT16 Dpl : 2;                     //!< 45-46  Descriptor privilege level
    UINT16 Present : 1;                 //!< 47     Is descriptor present
    UINT16 OffsetMid;                   //!< 48-63  Offset bits 16-31
    UINT32 OffsetHigh;                  //!< 64-95  Offset bits 32-63
    UINT32 Reserved2;                   //!< 96-127 0
} IDT_GATE_INTERRUPT64, *PIDT_GATE_INTERRUPT64;
C_ASSERT(16 == sizeof(IDT_GATE_INTERRUPT64));

// Trap Gate looks exactly the same except the gate type field
typedef IDT_GATE_INTERRUPT64 IDT_GATE_TRAP64;
typedef PIDT_GATE_INTERRUPT64 PIDT_GATE_TRAP64;

typedef struct _IDT_TABLE32 {
    IDT_GATE_INTERRUPT32 atDescriptors[IDT_MAX_ENTRIES];
} IDT_TABLE32, *PIDT_TABLE32;

typedef struct _IDT_TABLE64 {
    IDT_GATE_INTERRUPT64 atDescriptors[IDT_MAX_ENTRIES];
} IDT_TABLE64, *PIDT_TABLE64;

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_IDT_H__ */
