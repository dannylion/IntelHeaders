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
* @file		apic.h
* @section	Advanced Programmable Interrupt Controller (APIC) structures and constants
*/

#ifndef __INTEL_APIC_H__
#define __INTEL_APIC_H__

#include "ntdatatypes.h"
#include "msr64.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 3B, Table 10-1 Local APIC Register Address Map
typedef enum _APIC_REG_OFFSET
{
	// 0x0000 - 0x0010 Reserved
	APIC_REG_OFFSET_APICID		= 0x0020, // Local APIC ID Register (Read/Write)
	APIC_REG_OFFSET_VERSION		= 0x0030, // Local APIC Version Register (Read Only)
	// 0x0040 - 0x0070 Reserved
	APIC_REG_OFFSET_TPR			= 0x0080, // Task Priority Register (Read/Write)
	APIC_REG_OFFSET_APR			= 0x0090, // Arbitration Priority Register (Read Only)
	APIC_REG_OFFSET_PPR			= 0x00A0, // Processor Priority Register (Read Only)
	APIC_REG_OFFSET_EOI			= 0x00B0, // EOI Register (Write Only)
	APIC_REG_OFFSET_RRD			= 0x00C0, // Remote Read Register (Read Only)
	APIC_REG_OFFSET_LDR			= 0x00D0, // Logical Destination Register (Read/Write)
	APIC_REG_OFFSET_DFR			= 0x00E0, // Destination Format Register (Read/Write)
	APIC_REG_OFFSET_SIVR		= 0x00F0, // Spurious Interrupt Vector Register (Read/Write)
	APIC_REG_OFFSET_ISR0		= 0x0100, // In-Service Register; bits 31:0 (Read Only)
	APIC_REG_OFFSET_ISR1		= 0x0110, // ISR bits 63:32 (Read Only)
	APIC_REG_OFFSET_ISR2		= 0x0120, // ISR bits 95:64 (Read Only)
	APIC_REG_OFFSET_ISR3		= 0x0130, // ISR bits 127:96 (Read Only)
	APIC_REG_OFFSET_ISR4		= 0x0140, // ISR bits 159:128 (Read Only)
	APIC_REG_OFFSET_ISR5		= 0x0150, // ISR bits 191:160 (Read Only)
	APIC_REG_OFFSET_ISR6		= 0x0160, // ISR bits 223:192 (Read Only)
	APIC_REG_OFFSET_ISR7		= 0x0170, // ISR bits 255:224 (Read Only)
	APIC_REG_OFFSET_TMR0		= 0x0180, // Trigger Mode Register; bits 31:0 (Read Only)
	APIC_REG_OFFSET_TMR1		= 0x0190, // TMR bits 63:32 (Read Only)
	APIC_REG_OFFSET_TMR2		= 0x01A0, // TMR bits 95:64 (Read Only)
	APIC_REG_OFFSET_TMR3		= 0x01B0, // TMR bits 127:96 (Read Only)
	APIC_REG_OFFSET_TMR4		= 0x01C0, // TMR bits 159:128 (Read Only)
	APIC_REG_OFFSET_TMR5		= 0x01D0, // TMR bits 191:160 (Read Only)
	APIC_REG_OFFSET_TMR6		= 0x01E0, // TMR bits 223:192 (Read Only)
	APIC_REG_OFFSET_TMR7		= 0x01F0, // TMR bits 255:224 (Read Only)
	APIC_REG_OFFSET_IRR0		= 0x0200, // Interrupt Request Register; 31:0 (Read Only)
	APIC_REG_OFFSET_IRR1		= 0x0210, // IRR bits 63:32	(Read Only)
	APIC_REG_OFFSET_IRR2		= 0x0220, // IRR bits 95:64	(Read Only)
	APIC_REG_OFFSET_IRR3		= 0x0230, // IRR bits 127:96 (Read Only)
	APIC_REG_OFFSET_IRR4		= 0x0240, // IRR bits 159:128 (Read Only)
	APIC_REG_OFFSET_IRR5		= 0x0250, // IRR bits 191:160 (Read Only)
	APIC_REG_OFFSET_IRR6		= 0x0260, // IRR bits 223:192 (Read Only)
	APIC_REG_OFFSET_IRR7		= 0x0270, // IRR bits 255:224 (Read Only)
	APIC_REG_OFFSET_ESR			= 0x0280, // Error Status Register (Read Only)
	// 0x0290 - 0x02E0 Reserved 
	APIC_REG_OFFSET_LVT_CMCI	= 0x02F0, // LVT CMCI Register (Read/Write)
	APIC_REG_OFFSET_ICR0		= 0x0300, // Interrupt Command Register (Read/Write)
	APIC_REG_OFFSET_ICR1		= 0x0310, // Interrupt Command Register (Read/Write)
	APIC_REG_OFFSET_LVT_TIMER	= 0x0320, // LVT Timer Register (Read/Write)
	APIC_REG_OFFSET_LVT_THERMAL	= 0x0330, // LVT Thermal Sensor Register (Read/Write)
	APIC_REG_OFFSET_LVT_PMI		= 0x0340, // LVT Performance Monitoring Counters Register (Read/Write)
	APIC_REG_OFFSET_LVT_LINT0	= 0x0350, // LVT LINT0 Register (Read/Write)
	APIC_REG_OFFSET_LVT_LINT1	= 0x0360, // LVT LINT1 Register (Read/Write)
	APIC_REG_OFFSET_LVT_ERROR	= 0x0370, // LVT Error Register (Read/Write)
	APIC_REG_OFFSET_INIT_COUNT	= 0x0380, // Initial Count Register (Read/Write)
	APIC_REG_OFFSET_CUR_COUNT	= 0x0390, // Current Count Register (Read Only)
	// 0x03A0 - 0x03D0 Reserved
	APIC_REG_OFFSET_DIV_CONF	= 0x03E0, // Divide Configuration Register (Read/Write)
	// 0x03F0 Reserved
} APIC_REG_OFFSET, *PAPIC_REG_OFFSET;

//! Vol 3B, Table 10-6. Local APIC Register Address Map Supported by x2APIC
// x2APIC registers can also be accessed through MSRs 0x802-0x83F (See msr64.h)
typedef enum _X2APIC_REG_OFFSET
{
	X2APIC_REG_OFFSET_APICID		= 0x020, // Local APIC ID register (Read-only)
	X2APIC_REG_OFFSET_VERSION		= 0x030, // Local APIC Version register (Read Only)
	X2APIC_REG_OFFSET_TPR			= 0x080, // Task Priority Register (Read/Write)
	X2APIC_REG_OFFSET_PPR			= 0x0A0, // Processor Priority Register (Read Only)
	X2APIC_REG_OFFSET_EOI			= 0x0B0, // EOI register,Write-only3
											 // WRMSR of a non-zero value causes #GP(0)
	X2APIC_REG_OFFSET_LDR			= 0x0D0, // Logical Destination Register (Read Only)
											 // Read/write in xAPIC mode
	X2APIC_REG_OFFSET_SIVR			= 0x0F0, // Spurious Interrupt Vector (Read/Write)
	X2APIC_REG_OFFSET_ISR0			= 0x100, // In-Service Register (ISR); bits (Read Only)
	X2APIC_REG_OFFSET_ISR1			= 0x110, // ISR bits 63:32 (Read Only)
	X2APIC_REG_OFFSET_ISR2			= 0x120, // ISR bits 95:64 (Read Only)
	X2APIC_REG_OFFSET_ISR3			= 0x130, // ISR bits 127:96 (Read Only)
	X2APIC_REG_OFFSET_ISR4			= 0x140, // ISR bits 159:128 (Read Only)
	X2APIC_REG_OFFSET_ISR5			= 0x150, // ISR bits 191:160 (Read Only)
	X2APIC_REG_OFFSET_ISR6			= 0x160, // ISR bits 223:192 (Read Only)
	X2APIC_REG_OFFSET_ISR7			= 0x170, // ISR bits 255:224 (Read Only)
	X2APIC_REG_OFFSET_TMR0			= 0x180, // Trigger Mode Register (Read Only)
	X2APIC_REG_OFFSET_TMR1			= 0x190, // TMR bits 63:32 (Read Only)
	X2APIC_REG_OFFSET_TMR2			= 0x1A0, // TMR bits 95:64 (Read Only)
	X2APIC_REG_OFFSET_TMR3			= 0x1B0, // TMR bits 127:96 (Read Only)
	X2APIC_REG_OFFSET_TMR4			= 0x1C0, // TMR bits 159:128 (Read Only)
	X2APIC_REG_OFFSET_TMR5			= 0x1D0, // TMR bits 191:160 (Read Only)
	X2APIC_REG_OFFSET_TMR6			= 0x1E0, // TMR bits 223:192 (Read Only)
	X2APIC_REG_OFFSET_TMR7			= 0x1F0, // TMR bits 255:224 (Read Only)
	X2APIC_REG_OFFSET_IRR0			= 0x200, // Interrupt Request Register (Read Only)
	X2APIC_REG_OFFSET_IRR1			= 0x210, // IRR bits 63:32 (Read Only)
	X2APIC_REG_OFFSET_IRR2			= 0x220, // IRR bits 95:64 (Read Only)
	X2APIC_REG_OFFSET_IRR3			= 0x230, // IRR bits 127:96 (Read Only)
	X2APIC_REG_OFFSET_IRR4			= 0x240, // IRR bits 159:128 (Read Only)
	X2APIC_REG_OFFSET_IRR5			= 0x250, // IRR bits 191:160 (Read Only)
	X2APIC_REG_OFFSET_IRR6			= 0x260, // IRR bits 223:192 (Read Only)
	X2APIC_REG_OFFSET_IRR7			= 0x270, // IRR bits 255:224 (Read Only)
	X2APIC_REG_OFFSET_ESR			= 0x280, // Error Status Register (Read/Write)
											 // WRMSR of a non-zero value causes #GP(0)
	X2APIC_REG_OFFSET_LVT_CMCI		= 0x2F0, // LVT CMCI register (Read/Write)
	X2APIC_REG_OFFSET_ICR0			= 0x300, // Interrupt Command Register (Read/Write)
	X2APIC_REG_OFFSET_ICR1			= 0x310, // 
	X2APIC_REG_OFFSET_LVT_TIMER		= 0x320, // LVT Timer register (Read/Write)
	X2APIC_REG_OFFSET_LVT_THERMAL	= 0x330, // LVT Thermal Sensor register (Read/Write)
	X2APIC_REG_OFFSET_LVT_PMI		= 0x340, // LVT Performance Monitoring register (Read/Write)
	X2APIC_REG_OFFSET_LVT_LINT0		= 0x350, // LVT LINT0 register (Read/Write)
	X2APIC_REG_OFFSET_LVT_LINT1		= 0x360, // LVT LINT1 register (Read/Write)
	X2APIC_REG_OFFSET_LVT_ERROR		= 0x370, // LVT Error register (Read/Write)
	X2APIC_REG_OFFSET_INIT_COUNT	= 0x380, // Initial Count register (Read/write)
	X2APIC_REG_OFFSET_CUR_COUNT		= 0x390, // Current Count register (Read-only)
	X2APIC_REG_OFFSET_DIV_CONF		= 0x3E0, // Divide Configuration Register (Read/Write)
} X2APIC_REG_OFFSET, *PX2APIC_REG_OFFSET;

//! Vol 3B, Figure 10-7. Local APIC Version Register
typedef union _APIC_VER_REG
{
	UINT32 dwValue;
	struct {
		UINT32 Version : 8;					//!< 0-7	Version numbers of the local APIC
		UINT32 Reserved0 : 8;				//!< 8-15
		UINT32 MaxLvtEntry : 8;				//!< 16-23	Number of LVT entries -1
		UINT32 SuppressEoiBroadcasts : 1;	//!< 24		S/W can inhibit the broadcast of EOI message
		UINT32 Reserved1 : 7;				//!< 25-31
	};
} APIC_VER_REG, *PAPIC_VER_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_VER_REG));

// Read MSR_CODE_IA32_APIC_BASE and calculate the APIC base from it
#define READ_APIC_BASE ((__readmsr(MSR_CODE_IA32_APIC_BASE) >> 12) << 12)

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_APIC_H__ */
