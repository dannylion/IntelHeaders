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
* @file		smm.h
* @section	System Management Mode constants and structures
*			Vol 3C, Chapter 34 SYSTEM MANAGEMENT MODE
*/

#ifndef __INTEL_SMM_H__
#define __INTEL_SMM_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 3C, 34.11 SMBASE RELOCATION
#define SMBASE_DEFAULT_ADDRESS 0x30000

//! Vol 3C, Figure 34-1. SMRAM Usage
#define SMI_HANDLER_ENTRY_POINT_OFFSET	0x8000

//! Vol 3C, 34.11 SMBASE RELOCATION
// The state save area begins at [SMBASE + 0x8000 + 0x7FFF] 
// and extends down to [SMBASE + 0x8000 + 0x7E00]
#define SMI_SAVE_STATE_START_OFFSET 0xFE00

// TODO: Vol 3C, Table 34-1. SMRAM State Save Map
typedef enum _SMI_SAVE_STATE_OFFSET
{
	SMI_SAVE_STATE_OFFSET_CR0 = 0x7FFC, 				// Read Only
	SMI_SAVE_STATE_OFFSET_CR3 = 0x7FF8, 				// Read Only
	SMI_SAVE_STATE_OFFSET_EFLAGS = 0x7FF4, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_EIP = 0x7FF0, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_EDI = 0x7FEC, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_ESI = 0x7FE8, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_EBP = 0x7FE4, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_ESP = 0x7FE0, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_EBX = 0x7FDC, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_EDX = 0x7FD8, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_ECX = 0x7FD4, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_EAX = 0x7FD0, 				// Read/Write
	SMI_SAVE_STATE_OFFSET_DR6 = 0x7FCC, 				// Read Only
	SMI_SAVE_STATE_OFFSET_DR7 = 0x7FC8, 				// Read Only
	SMI_SAVE_STATE_OFFSET_TR1 = 0x7FC4, 				// Read Only
	// 0x7FC0 Reserved
	SMI_SAVE_STATE_OFFSET_GS1 = 0x7FBC, 				// Read Only
	SMI_SAVE_STATE_OFFSET_FS1 = 0x7FB8, 				// Read Only
	SMI_SAVE_STATE_OFFSET_DS1 = 0x7FB4, 				// Read Only
	SMI_SAVE_STATE_OFFSET_SS1 = 0x7FB0, 				// Read Only
	SMI_SAVE_STATE_OFFSET_CS1 = 0x7FAC, 				// Read Only
	SMI_SAVE_STATE_OFFSET_ES1 = 0x7FA8, 				// Read Only
	SMI_SAVE_STATE_OFFSET_IO_STATE = 0x7FA4,			// Read Only, I/O State Field see Section 34.7
	SMI_SAVE_STATE_OFFSET_MEMORY_ADDRESS = 0x7FA0,		// Read Only, I/O Memory Address Field see Section 34.7
	// 0x7F9F - 0x7F03 Reserved
	SMI_SAVE_STATE_OFFSET_AUTO_HALT_RESTART = 0x7F02,	// WORD, Read/Write
	SMI_SAVE_STATE_OFFSET_IO_RESTART = 0x7F00,			// WORD, Read/Write
	SMI_SAVE_STATE_OFFSET_SMM_REVISON_ID = 0x7EFC,		// DWORD, Read Only
	SMI_SAVE_STATE_OFFSET_SMBASE = 0x7EF8,				// DWORD, Read/Write
	// 0x7EF7 - 0x7E00H Reserved
} SMI_SAVE_STATE_OFFSET, *PSMI_SAVE_STATE_OFFSET;

//! Vol 3C, Table 34-3. SMRAM State Save Map for Intel 64 Architecture
typedef enum _SMI_SAVE_STATE_OFFSET64
{
	SMI_SAVE_STATE_OFFSET64_CR0 = 0x7FF8,				// Read Only
	SMI_SAVE_STATE_OFFSET64_CR3 = 0x7FF0,				// Read Only
	SMI_SAVE_STATE_OFFSET64_RFLAGS = 0x7FE8,			// Read/Write
	SMI_SAVE_STATE_OFFSET64_IA32_EFER = 0x7FE0,			// Read/Write
	SMI_SAVE_STATE_OFFSET64_RIP = 0x7FD8,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_DR6 = 0x7FD0,				// Read Only
	SMI_SAVE_STATE_OFFSET64_DR7 = 0x7FC8,				// Read Only
	SMI_SAVE_STATE_OFFSET64_TR = 0x7FC4,				// Read Only
	SMI_SAVE_STATE_OFFSET64_LDTR = 0x7FC0,				// Read Only
	SMI_SAVE_STATE_OFFSET64_GS = 0x7FBC,				// Read Only
	SMI_SAVE_STATE_OFFSET64_FS = 0x7FB8,				// Read Only
	SMI_SAVE_STATE_OFFSET64_DS = 0x7FB4,				// Read Only
	SMI_SAVE_STATE_OFFSET64_SS = 0x7FB0,				// Read Only
	SMI_SAVE_STATE_OFFSET64_CS = 0x7FAC,				// Read Only
	SMI_SAVE_STATE_OFFSET64_ES = 0x7FA8,				// Read Only
	SMI_SAVE_STATE_OFFSET64_IO_STATE = 0x7FA4,			// Read Only
	SMI_SAVE_STATE_OFFSET64_IO_MEM_ADDR = 0x7F9C,		// Read Only
	SMI_SAVE_STATE_OFFSET64_RDI = 0x7F94,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RSI = 0x7F8C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RBP = 0x7F84,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RSP = 0x7F7C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RBX = 0x7F74,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RDX = 0x7F6C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RCX = 0x7F64,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_RAX = 0x7F5C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R8 = 0x7F54,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R9 = 0x7F4C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R10 = 0x7F44,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R11 = 0x7F3C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R12 = 0x7F34,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R13 = 0x7F2C,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R14 = 0x7F24,				// Read/Write
	SMI_SAVE_STATE_OFFSET64_R15 = 0x7F1C,				// Read/Write
	// 0x7F1B - 0x7F04 Reserved
	SMI_SAVE_STATE_OFFSET64_AUTO_HALT_RESTART = 0x7F02,	// Read/Write, Auto HALT Restart Field (WORD)
	SMI_SAVE_STATE_OFFSET64_IO_RESTART = 0x7F00,		// Read/Write, I/O Instruction Restart Field (WORD)
	SMI_SAVE_STATE_OFFSET64_SMM_REVISION_ID = 0x7EFC,	// Read Only, SMM Revision Identifier Field (DWORD)
	SMI_SAVE_STATE_OFFSET64_SMBASE = 0x7EF8,			// Read/Write, SMBASE Field (DWORD)
	// 0x7EF7 - 0x7EE4 Reserved
	SMI_SAVE_STATE_OFFSET64_ENABLE_EPT = 0x7EE0,		// Read Only, Setting of "enable EPT" VM-execution control 
	SMI_SAVE_STATE_OFFSET64_EPTP = 0x7ED8,				// Read Only, Value of EPTP VM-execution control field
	// 0x7ED7 - 0x7EA0 Reserved
	SMI_SAVE_STATE_OFFSET64_LDT_BASE_LOW = 0x7E9C,		// Read Only, LDT Base (lower 32 bits)
	// 0x7E98 Reserved
	SMI_SAVE_STATE_OFFSET64_IDT_BASE_LOW = 0x7E94,		// Read Only, IDT Base (lower 32 bits)
	// 0x7E90 Reserved
	SMI_SAVE_STATE_OFFSET64_GDT_BASE_LOW = 0x7E8C,		// Read Only, GDT Base (lower 32 bits)
	// 0x7E8B - 0x7E44 Reserved
	SMI_SAVE_STATE_OFFSET64_CR4 = 0x7E40,				// Read Only
	// 0x7E3F - 0x7DF0 Reserved
	SMI_SAVE_STATE_OFFSET64_IO_RIP = 0x7DE8,			// Read/Write
	// 0x7DE7 - 0x7DDC Reserved
	SMI_SAVE_STATE_OFFSET64_IDT_BASE_HIGH = 0x7DD8,		// Read Only, IDT Base (Upper 32 bits)
	SMI_SAVE_STATE_OFFSET64_LDT_BASE_HIGH = 0x7DD4,		// Read Only, LDT Base (Upper 32 bits)
	SMI_SAVE_STATE_OFFSET64_GDT_BASE_HIGH = 0x7DD0,		// Read Only, GDT Base (Upper 32 bits)
	// 0x7DCF - 0x7C00 Reserved
} SMI_SAVE_STATE_OFFSET64, *PSMI_SAVE_STATE_OFFSET64;

//! Vol 3C, Figure 34-2. SMM Revision Identifier (SMI_SAVE_STATE_OFFSET_SMM_REVISION_ID)
typedef union _SMM_REVISION_ID
{
	UINT32 dwValue;
	struct {
		UINT32 Revision : 16;			//!< 0-15	SMM Revision ID
		UINT32 IoRestart : 1;			//!< 16		I/O instruction restart
		UINT32 SmbaseRelocation : 1;	//!< 17		SMBASE Relocation support
		UINT32 Reserved0 : 14;			//!< 18-31	0
	};
} SMM_REVISION_ID, *PSMM_REVISION_ID;
C_ASSERT(sizeof(UINT32) == sizeof(SMM_REVISION_ID));

typedef enum _SMM_IO_LENGTH
{
	SMM_IO_LENGTH_BYTE = 1,
	SMM_IO_LENGTH_WORD = 2,
	SMM_IO_LENGTH_DWORD = 4,
} SMM_IO_LENGTH, *PSMM_IO_LENGTH;

//! Vol 3C, Table 34-6. I/O Instruction Type Encodings
typedef enum _SMM_IO_TYPE
{
	SMM_IO_TYPE_IN_IMMEDIATE = 9,
	SMM_IO_TYPE_IN_DX = 1,
	SMM_IO_TYPE_OUT_IMMEDIATE = 8,
	SMM_IO_TYPE_OUT_DX = 0,
	SMM_IO_TYPE_INS = 3,
	SMM_IO_TYPE_OUTS = 2,
	SMM_IO_TYPE_REP_INS = 7,
	SMM_IO_TYPE_REP_OUTS = 6,
} SMM_IO_TYPE, *PSMM_IO_TYPE;

//! Vol 3C, Table 34-5. I/O Instruction Information in the SMM State Save Map
//	(SMI_SAVE_STATE_OFFSET64_IO_STATE)
typedef union _SMM_IO_STATE
{
	UINT32 dwValue;
	struct {
		UINT32 IoSmi : 1;		//!< 0		If set the rest of the structure is valid
		UINT32 IoLength : 2;	//!< 1-3	See SMM_IO_LENGTH
		UINT32 IoType : 3;		//!< 4-7	See SMM_IO_TYPE
		UINT32 Reserved0 : 8;	//!< 8-15	0
		UINT32 IoPort : 16;		//!< 16-31	IO port used in instruction
	};
} SMM_IO_STATE, *PSMM_IO_STATE;
C_ASSERT(sizeof(UINT32) == sizeof(SMM_IO_STATE));

//! Vol 3C, Figure 34-3. Auto HALT Restart (SMI_SAVE_STATE_OFFSET_AUTO_HALT_RESTART)
typedef union _SMM_AUTO_HALT_RESTART
{
	UINT16 wValue;
	struct {
		UINT16 AutoHaltRestart : 1;	//!< 0		Was CPU in HALT state before SMI
		UINT16 Reserved0 : 15;		//!< 1-15
	};
} SMM_AUTO_HALT_RESTART, *PSMM_AUTO_HALT_RESTART;
C_ASSERT(sizeof(UINT16) == sizeof(SMM_AUTO_HALT_RESTART));

//!	Vol 3C, Table 34-8. I/O Instruction Restart Field
//	(SMI_SAVE_STATE_OFFSET_IO_RESTART)
typedef enum _SMM_IO_RESTART
{
	SMM_IO_RESTART_DONT_EXECUTE = 0,	// Does not re-execute trapped I/O instruction
	SMM_IO_RESTART_EXECUTE = 0xFF,		// Re-executes trapped I/O instruction
} SMM_IO_RESTART, *PSMM_IO_RESTART;

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_SMM_H__ */
