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
* @file		VT-x.h
* @section	Intel VT-x structures, constants and utility functions and macros
*/

#ifndef __INTEL_VT_X_H__
#define __INTEL_VT_X_H__

#include "ntdatatypes.h"
#include "msr64.h"
#include "cr64.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 3B, Table 21-16. Structure of VMCS Component Encoding
typedef union _VMCS_COMPONENT_ENCODING
{
	UINT32 AccessType : 1;	//!< 0		Access type (0 = full; 1 = high); must be full 
							//			for 16-bit, 32-bit, and natural-width fields
	UINT32 Index : 8;		//!< 1-9	Index
	UINT32 Reserved0 : 12;	//!< 12		0
	UINT32 Width : 2;		//!< 13-14	0: 16-bit, 1: 64-bit, 2: 32-bit, 3: natural-width
	UINT32 Reserved1 : 17;	//!< 15-31	0
} VMCS_COMPONENT_ENCODING, *PVMCS_COMPONENT_ENCODING;
C_ASSERT(sizeof(UINT32) == sizeof(VMCS_COMPONENT_ENCODING));

//! Vol 3B, APPENDIX H FIELD ENCODING IN VMCS
typedef enum _VMCS_FIELD_ENCODING
{
	// Vol 3B, Table H-1. Encoding for 16-Bit Control Fields (0000_00xx_xxxx_xxx0B)
	VMCS_FIELD_VPID = 0x00000000,
	VMCS_FIELD_POSTED_INTR_NOTIFICATION_VECTOR = 0x00000002,
	VMCS_FIELD_EPTP_INDEX = 0x00000004,

	// Vol 3B, Table H-2. Encodings for 16-Bit Guest-State Fields (0000_10xx_xxxx_xxx0B)
	VMCS_FIELD_GUEST_ES_SELECTOR = 0x00000800,
	VMCS_FIELD_GUEST_CS_SELECTOR = 0x00000802,
	VMCS_FIELD_GUEST_SS_SELECTOR = 0x00000804,
	VMCS_FIELD_GUEST_DS_SELECTOR = 0x00000806,
	VMCS_FIELD_GUEST_FS_SELECTOR = 0x00000808,
	VMCS_FIELD_GUEST_GS_SELECTOR = 0x0000080a,
	VMCS_FIELD_GUEST_LDTR_SELECTOR = 0x0000080c,
	VMCS_FIELD_GUEST_TR_SELECTOR = 0x0000080e,
	VMCS_FIELD_GUEST_INTR_STATUS = 0x00000810,
	VMCS_FIELD_GUEST_PML_INDEX = 0x00000812,

	// Vol 3B, Table H-3. Encodings for 16-Bit Host-State Fields (0000_11xx_xxxx_xxx0B)
	VMCS_FIELD_HOST_ES_SELECTOR = 0x00000c00,
	VMCS_FIELD_HOST_CS_SELECTOR = 0x00000c02,
	VMCS_FIELD_HOST_SS_SELECTOR = 0x00000c04,
	VMCS_FIELD_HOST_DS_SELECTOR = 0x00000c06,
	VMCS_FIELD_HOST_FS_SELECTOR = 0x00000c08,
	VMCS_FIELD_HOST_GS_SELECTOR = 0x00000c0a,
	VMCS_FIELD_HOST_TR_SELECTOR = 0x00000c0c,

	// Vol 3B, Table H-3. Encodings for 16-Bit Host-State Fields (0000_11xx_xxxx_xxx0B)
	VMCS_FIELD_IO_BITMAP_A_FULL = 0x00002000,
	VMCS_FIELD_IO_BITMAP_A_HIGH = 0x00002001,
	VMCS_FIELD_IO_BITMAP_B_FULL = 0x00002002,
	VMCS_FIELD_IO_BITMAP_B_HIGH = 0x00002003,
	VMCS_FIELD_MSR_BITMAP_FULL = 0x00002004,
	VMCS_FIELD_MSR_BITMAP_HIGH = 0x00002005,
	VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR_FULL = 0x00002006,
	VMCS_FIELD_VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
	VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR_FULL = 0x00002008,
	VMCS_FIELD_VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
	VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR_FULL = 0x0000200a,
	VMCS_FIELD_VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
	VMCS_FIELD_EXECUTIVE_VMCS_PTR_FULL = 0x0000200c,
	VMCS_FIELD_EXECUTIVE_VMCS_PTR_HIGH = 0x0000200d,
	VMCS_FIELD_PML_ADDRESS_FULL = 0x0000200e,
	VMCS_FIELD_PML_ADDRESS_HIGH = 0x0000200f,
	VMCS_FIELD_TSC_OFFSET_FULL = 0x00002010,
	VMCS_FIELD_TSC_OFFSET_HIGH = 0x00002011,
	VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR_FULL = 0x00002012,
	VMCS_FIELD_VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	VMCS_FIELD_APIC_ACCESS_ADDR_FULL = 0x00002014,
	VMCS_FIELD_APIC_ACCESS_ADDR_HIGH = 0x00002015,
	VMCS_FIELD_PI_DESC_ADDR_FULL = 0x00002016,
	VMCS_FIELD_PI_DESC_ADDR_HIGH = 0x00002017,
	VMCS_FIELD_VM_FUNCTION_CONTROL_FULL = 0x00002018,
	VMCS_FIELD_VM_FUNCTION_CONTROL_HIGH = 0x00002019,
	VMCS_FIELD_EPT_POINTER_FULL = 0x0000201a,
	VMCS_FIELD_EPT_POINTER_HIGH = 0x0000201b,
	VMCS_FIELD_EOI_EXIT_BITMAP0_FULL = 0x0000201c,
	VMCS_FIELD_EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
	VMCS_FIELD_EPTP_LIST_ADDR_FULL = 0x00002024,
	VMCS_FIELD_EPTP_LIST_ADDR_HIGH = 0x00002025,
	VMCS_FIELD_VMREAD_BITMAP_FULL = 0x00002026,
	VMCS_FIELD_VMREAD_BITMAP_HIGH = 0x00002027,
	VMCS_FIELD_VMWRITE_BITMAP_FULL = 0x00002028,
	VMCS_FIELD_VMWRITE_BITMAP_HIGH = 0x00002029,
	VMCS_FIELD_VIRT_EXCEPTION_INFO_FULL = 0x0000202a,
	VMCS_FIELD_VIRT_EXCEPTION_INFO_HIGH = 0x0000202b,
	VMCS_FIELD_XSS_EXIT_BITMAP_FULL = 0x0000202c,
	VMCS_FIELD_XSS_EXIT_BITMAP_HIGH = 0x0000202d,
	VMCS_FIELD_TSC_MULTIPLIER_FULL = 0x00002032,
	VMCS_FIELD_TSC_MULTIPLIER_HIGH = 0x00002033,
	
	// Vol 3B, Table H-5. Encodings for 64-Bit Read-Only Data Field (0010_01xx_xxxx_xxxAb)
	VMCS_FIELD_GUEST_PHYSICAL_ADDRESS_FULL = 0x00002400,
	VMCS_FIELD_GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	
	// Vol 3B, Table H-6. Encodings for 64-Bit Guest-State Fields (0010_10xx_xxxx_xxxAb)
	VMCS_FIELD_VMCS_LINK_POINTER_FULL = 0x00002800,
	VMCS_FIELD_VMCS_LINK_POINTER_HIGH = 0x00002801,
	VMCS_FIELD_GUEST_IA32_DEBUGCTL_FULL = 0x00002802,
	VMCS_FIELD_GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
	VMCS_FIELD_GUEST_PAT_FULL = 0x00002804,
	VMCS_FIELD_GUEST_PAT_HIGH = 0x00002805,
	VMCS_FIELD_GUEST_EFER_FULL = 0x00002806,
	VMCS_FIELD_GUEST_EFER_HIGH = 0x00002807,
	VMCS_FIELD_GUEST_PERF_GLOBAL_CTRL_FULL = 0x00002808,
	VMCS_FIELD_GUEST_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
	VMCS_FIELD_GUEST_PDPTE0_FULL = 0x0000280a,
	VMCS_FIELD_GUEST_PDPTE0_HIGH = 0x0000280b,
	VMCS_FIELD_GUEST_PDPTE1_FULL = 0x0000280c,
	VMCS_FIELD_GUEST_PDPTE1_HIGH = 0x0000280d,
	VMCS_FIELD_GUEST_PDPTE2_FULL = 0x0000280e,
	VMCS_FIELD_GUEST_PDPTE2_HIGH = 0x0000280f,
	VMCS_FIELD_GUEST_PDPTE3_FULL = 0x00002810,
	VMCS_FIELD_GUEST_PDPTE3_HIGH = 0x00002811,
	VMCS_FIELD_GUEST_BNDCFGS_FULL = 0x00002812,
	VMCS_FIELD_GUEST_BNDCFGS_HIGH = 0x00002813,
	
	// Vol 3B, Table H-7. Encodings for 64-Bit Host-State Fields (0010_11xx_xxxx_xxxAb)
	VMCS_FIELD_HOST_PAT_FULL = 0x00002c00,
	VMCS_FIELD_HOST_PAT_HIGH = 0x00002c01,
	VMCS_FIELD_HOST_EFER_FULL = 0x00002c02,
	VMCS_FIELD_HOST_EFER_HIGH = 0x00002c03,
	VMCS_FIELD_HOST_PERF_GLOBAL_CTRL_FULL = 0x00002c04,
	VMCS_FIELD_HOST_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,

	// Table H-8. Encodings for 32-Bit Control Fields (0100_00xx_xxxx_xxx0B)
	VMCS_FIELD_PINBASED_CTLS = 0x00004000,
	VMCS_FIELD_PROCBASED_CTLS = 0x00004002,
	VMCS_FIELD_EXCEPTION_BITMAP = 0x00004004,
	VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	VMCS_FIELD_PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	VMCS_FIELD_CR3_TARGET_COUNT = 0x0000400a,
	VMCS_FIELD_VMEXIT_CTLS = 0x0000400c,
	VMCS_FIELD_VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VMCS_FIELD_VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VMCS_FIELD_VMENTRY_CTLS = 0x00004012,
	VMCS_FIELD_VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VMCS_FIELD_VM_ENTRY_INTR_INFO = 0x00004016,
	VMCS_FIELD_VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VMCS_FIELD_VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	VMCS_FIELD_TPR_THRESHOLD = 0x0000401c,
	VMCS_FIELD_PROCBASED_CTLS2 = 0x0000401e,
	VMCS_FIELD_PLE_GAP = 0x00004020,
	VMCS_FIELD_PLE_WINDOW = 0x00004022,

	// Vol 3B, Table H-9. Encodings for 32-Bit Read-Only Data Fields (0100_01xx_xxxx_xxx0B)
	VMCS_FIELD_VM_INSTRUCTION_ERROR = 0x00004400,
	VMCS_FIELD_VM_EXIT_REASON = 0x00004402,
	VMCS_FIELD_VM_EXIT_INTR_INFO = 0x00004404,
	VMCS_FIELD_VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	VMCS_FIELD_IDT_VECTORING_INFO = 0x00004408,
	VMCS_FIELD_IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VMCS_FIELD_VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMCS_FIELD_INSTRUCTION_INFO = 0x0000440e,

	// Vol 3B, Table H-10. Encodings for 32-Bit Guest-State Fields (0100_10xx_xxxx_xxx0B)
	VMCS_FIELD_GUEST_ES_LIMIT = 0x00004800,
	VMCS_FIELD_GUEST_CS_LIMIT = 0x00004802,
	VMCS_FIELD_GUEST_SS_LIMIT = 0x00004804,
	VMCS_FIELD_GUEST_DS_LIMIT = 0x00004806,
	VMCS_FIELD_GUEST_FS_LIMIT = 0x00004808,
	VMCS_FIELD_GUEST_GS_LIMIT = 0x0000480a,
	VMCS_FIELD_GUEST_LDTR_LIMIT = 0x0000480c,
	VMCS_FIELD_GUEST_TR_LIMIT = 0x0000480e,
	VMCS_FIELD_GUEST_GDTR_LIMIT = 0x00004810,
	VMCS_FIELD_GUEST_IDTR_LIMIT = 0x00004812,
	VMCS_FIELD_GUEST_ES_AR_BYTES = 0x00004814,
	VMCS_FIELD_GUEST_CS_AR_BYTES = 0x00004816,
	VMCS_FIELD_GUEST_SS_AR_BYTES = 0x00004818,
	VMCS_FIELD_GUEST_DS_AR_BYTES = 0x0000481a,
	VMCS_FIELD_GUEST_FS_AR_BYTES = 0x0000481c,
	VMCS_FIELD_GUEST_GS_AR_BYTES = 0x0000481e,
	VMCS_FIELD_GUEST_LDTR_AR_BYTES = 0x00004820,
	VMCS_FIELD_GUEST_TR_AR_BYTES = 0x00004822,
	VMCS_FIELD_GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	VMCS_FIELD_GUEST_ACTIVITY_STATE = 0x00004826,
	VMCS_FIELD_GUEST_SMBASE = 0x00004828,
	VMCS_FIELD_GUEST_SYSENTER_CS = 0x0000482a,
	VMCS_FIELD_GUEST_PREEMPTION_TIMER = 0x0000482e,

	// Vol 3B, Table H-11. Encoding for 32-Bit Host-State Field (0100_11xx_xxxx_xxx0B)
	VMCS_FIELD_HOST_SYSENTER_CS = 0x00004c00,

	// Vol 3B, Table H-12. Encodings for Natural-Width Control Fields (0110_00xx_xxxx_xxx0B)
	VMCS_FIELD_CR0_GUEST_HOST_MASK = 0x00006000,
	VMCS_FIELD_CR4_GUEST_HOST_MASK = 0x00006002,
	VMCS_FIELD_CR0_READ_SHADOW = 0x00006004,
	VMCS_FIELD_CR4_READ_SHADOW = 0x00006006,
	VMCS_FIELD_CR3_TARGET_VALUE0 = 0x00006008,
	VMCS_FIELD_CR3_TARGET_VALUE1 = 0x0000600a,
	VMCS_FIELD_CR3_TARGET_VALUE2 = 0x0000600c,
	VMCS_FIELD_CR3_TARGET_VALUE3 = 0x0000600e,

	// Vol 3B, Table H-13. Encodings for Natural-Width Read-Only Data Fields (0110_01xx_xxxx_xxx0B)
	VMCS_FIELD_EXIT_QUALIFICATION = 0x00006400,
	VMCS_FIELD_IO_RCX = 0x00006402,
	VMCS_FIELD_IO_RSI = 0x00006404,
	VMCS_FIELD_IO_RDI = 0x00006406,
	VMCS_FIELD_IO_RIP = 0x00006408,
	VMCS_FIELD_GUEST_LINEAR_ADDRESS = 0x0000640a,

	// Vol 3B, Table H-14. Encodings for Natural-Width Guest-State Fields (0110_10xx_xxxx_xxx0B)
	VMCS_FIELD_GUEST_CR0 = 0x00006800,
	VMCS_FIELD_GUEST_CR3 = 0x00006802,
	VMCS_FIELD_GUEST_CR4 = 0x00006804,
	VMCS_FIELD_GUEST_ES_BASE = 0x00006806,
	VMCS_FIELD_GUEST_CS_BASE = 0x00006808,
	VMCS_FIELD_GUEST_SS_BASE = 0x0000680a,
	VMCS_FIELD_GUEST_DS_BASE = 0x0000680c,
	VMCS_FIELD_GUEST_FS_BASE = 0x0000680e,
	VMCS_FIELD_GUEST_GS_BASE = 0x00006810,
	VMCS_FIELD_GUEST_LDTR_BASE = 0x00006812,
	VMCS_FIELD_GUEST_TR_BASE = 0x00006814,
	VMCS_FIELD_GUEST_GDTR_BASE = 0x00006816,
	VMCS_FIELD_GUEST_IDTR_BASE = 0x00006818,
	VMCS_FIELD_GUEST_DR7 = 0x0000681a,
	VMCS_FIELD_GUEST_RSP = 0x0000681c,
	VMCS_FIELD_GUEST_RIP = 0x0000681e,
	VMCS_FIELD_GUEST_RFLAGS = 0x00006820,
	VMCS_FIELD_GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	VMCS_FIELD_GUEST_SYSENTER_ESP = 0x00006824,
	VMCS_FIELD_GUEST_SYSENTER_EIP = 0x00006826,
	
	// Vol 3B, Table H-15. Encodings for Natural-Width Host-State Fields (0110_11xx_xxxx_xxx0B)
	VMCS_FIELD_HOST_CR0 = 0x00006c00,
	VMCS_FIELD_HOST_CR3 = 0x00006c02,
	VMCS_FIELD_HOST_CR4 = 0x00006c04,
	VMCS_FIELD_HOST_FS_BASE = 0x00006c06,
	VMCS_FIELD_HOST_GS_BASE = 0x00006c08,
	VMCS_FIELD_HOST_TR_BASE = 0x00006c0a,
	VMCS_FIELD_HOST_GDTR_BASE = 0x00006c0c,
	VMCS_FIELD_HOST_IDTR_BASE = 0x00006c0e,
	VMCS_FIELD_HOST_SYSENTER_ESP = 0x00006c10,
	VMCS_FIELD_HOST_SYSENTER_EIP = 0x00006c12,
	VMCS_FIELD_HOST_RSP = 0x00006c14,
	VMCS_FIELD_HOST_RIP = 0x00006c16,
} VMCS_FIELD_ENCODING, *PVMCS_FIELD_ENCODING;

// Vol 3B, Table I-1. Basic Exit Reasons
typedef enum _VMEXIT_REASON
{
	VMEXIT_REASON_EXCEPTION_NMI = 0,
	VMEXIT_REASON_EXTERNAL_INTERRUPT = 1,
	VMEXIT_REASON_TRIPLE_FAULT = 2,
	VMEXIT_REASON_INIT = 3,
	VMEXIT_REASON_SIPI = 4,
	VMEXIT_REASON_IO_SMI = 5,
	VMEXIT_REASON_OTHER_SMI = 6,
	VMEXIT_REASON_PENDING_VIRT_INTR = 7,
	VMEXIT_REASON_PENDING_VIRT_NMI = 8,
	VMEXIT_REASON_TASK_SWITCH = 9,
	VMEXIT_REASON_CPUID = 10,
	VMEXIT_REASON_GETSEC = 11,
	VMEXIT_REASON_HLT = 12,
	VMEXIT_REASON_INVD = 13,
	VMEXIT_REASON_INVLPG = 14,
	VMEXIT_REASON_RDPMC = 15,
	VMEXIT_REASON_RDTSC = 16,
	VMEXIT_REASON_RSM = 17,
	VMEXIT_REASON_VMCALL = 18,
	VMEXIT_REASON_VMCLEAR = 19,
	VMEXIT_REASON_VMLAUNCH = 20,
	VMEXIT_REASON_VMPTRLD = 21,
	VMEXIT_REASON_VMPTRST = 22,
	VMEXIT_REASON_VMREAD = 23,
	VMEXIT_REASON_VMRESUME = 24,
	VMEXIT_REASON_VMWRITE = 25,
	VMEXIT_REASON_VMXOFF = 26,
	VMEXIT_REASON_VMXON = 27,
	VMEXIT_REASON_CR_ACCESS = 28,
	VMEXIT_REASON_DR_ACCESS = 29,
	VMEXIT_REASON_IO_INSTRUCTION = 30,
	VMEXIT_REASON_MSR_READ = 31,
	VMEXIT_REASON_MSR_WRITE = 32,
	VMEXIT_REASON_INVALID_GUEST_STATE = 33,
	VMEXIT_REASON_MSR_LOADING = 34,
	VMEXIT_REASON_MWAIT_INSTRUCTION = 36,
	VMEXIT_REASON_MONITOR_TRAP_FLAG = 37,
	VMEXIT_REASON_MONITOR_INSTRUCTION = 39,
	VMEXIT_REASON_PAUSE_INSTRUCTION = 40,
	VMEXIT_REASON_MCE_DURING_VMENTRY = 41,
	VMEXIT_REASON_TPR_BELOW_THRESHOLD = 43,
	VMEXIT_REASON_APIC_ACCESS = 44,
	VMEXIT_REASON_ACCESS_GDTR_OR_IDTR = 46,
	VMEXIT_REASON_ACCESS_LDTR_OR_TR = 47,
	VMEXIT_REASON_EPT_VIOLATION = 48,
	VMEXIT_REASON_EPT_MISCONFIG = 49,
	VMEXIT_REASON_INVEPT = 50,
	VMEXIT_REASON_RDTSCP = 51,
	VMEXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED = 52,
	VMEXIT_REASON_INVVPID = 53,
	VMEXIT_REASON_WBINVD = 54,
	VMEXIT_REASON_XSETBV = 55,
	VMEXIT_REASON_APIC_WRITE = 56,
	VMEXIT_REASON_RDRAND = 57,
	VMEXIT_REASON_INVPCID = 58,
	VMEXIT_REASON_RDSEED = 61,
	VMEXIT_REASON_PML_FULL = 62,
	VMEXIT_REASON_XSAVES = 63,
	VMEXIT_REASON_XRSTORS = 64,
	VMEXIT_REASON_PCOMMIT = 65,
	VMEXIT_REASONS_MAX
} VMEXIT_REASON, *PVMEXIT_REASON;

//! Vol 3B, Table 21-5. Definitions of Pin-Based VM-Execution Controls
// (VMCS_FIELD_PINBASED_CTLS)
typedef union _VMX_PINBASED_CTLS
{
	UINT32 dwValue;
	struct {
		UINT32 ExternalIntExit : 1;		//!< 0	External interrupts cause VM exits
		UINT32 Reserved0 : 2;			//!< 1-2
		UINT32 NmiExit : 1;				//!< 3	Non-maskable interrupts (NMIs) cause VM exits
		UINT32 Reserved1 : 1;			//!< 4
		UINT32 VirtNmiExit : 1;			//!< 5	NMIs are never blocked and the "blocking by NMI"
										//		bit(bit 3) in the interruptibility - state field 
										//		indicates "virtual - NMI blocking"
		UINT32 PreemptionTimer : 1;		//!< 6	Use VMX-preemption timer counts down in VMX non-root operation
		UINT32 Reserved2 : 25;			//!< 7-31
	};
} VMX_PINBASED_CTLS, *PVMX_PINBASED_CTLS;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_PINBASED_CTLS));

//! Vol 3B, Table 21-6. Definitions of Primary Processor-Based VM-Execution Controls
// (VMCS_FIELD_PROCBASED_CTLS)
typedef union _VMX_PROCBASED_CTLS
{
	UINT32 dwValue;
	struct {
		UINT32 Reserved0 : 2;		//!< 0-1
		UINT32 IntWindowExit : 1;	//!< 2		A VM exit occurs at the beginning of any instruction 
									//			if RFLAGS.IF = 1
		UINT32 UseTscOffseting : 1; // 3		RDTSC, RDTSCP and IA32_TIME_STAMP_COUNTER MSR return 
									//			a value modified by the TSC offset field
		UINT32 Reserved1 : 3;		//!< 4-6
		UINT32 HltExit : 1;			//!< 7		HLT causes a VM exit
		UINT32 Reserved2 : 1;		//!< 8
		UINT32 InvlpgExit : 1;		//!< 9		INVLPG causes a VM exit
		UINT32 MwaitExit : 1;		//!< 10		MWAIT causes a VM exit
		UINT32 RdpmcExit : 1;		//!< 11		RDPMC causes a VM exit
		UINT32 RdtscExit : 1;		//!< 12		RDTSC causes a VM exit
		UINT32 Reserved3 : 2;		//!< 13-14
		UINT32 Cr3LoadExit : 1;		//!< 15		MOV to CR3 causes a VM exit
		UINT32 Cr3StoreExit : 1;	//!< 16		MOV from CR3 causes a VM exit
		UINT32 Reserved4 : 2;		//!< 17-18
		UINT32 Cr8LoadExit : 1;		//!< 19		MOV to CR8 causes a VM exit
		UINT32 Cr8StoreExit : 1;	//!< 20		MOV from CR8 causes a VM exit
		UINT32 UseTprShadow : 1;	//!< 21		Activates the TPR shadow
		UINT32 NmiWindowExit : 1;	//!< 22		VM exit occurs at the beginning of any instruction
									//			if there is no virtual - NMI blocking
		UINT32 MovDrExit : 1;		//!< 23		MOV to/from DR causes a VM exit
		UINT32 UncondIoExit : 1;	//!< 24		I/O instruction cause a VM exit, ignored if using I/O bitmaps
		UINT32 UseIoBitmaps : 1;	//!< 25		Use I/O bitmaps
		UINT32 Reserved5 : 1;		//!< 26
		UINT32 MonitorTrapFlag : 1; // 27		Monitor trap flag debugging feature is enabled
		UINT32 UseMsrBitmaps : 1;	//!< 28		Use MSR bitmaps
		UINT32 MonitorExit : 1;		//!< 29		MONITOR causes a VM exit
		UINT32 PauseExit : 1;		//!< 30		PAUSE causes a VM exit
		UINT32 UseProcbased2 : 1;	//!< 31		Determines whether to use VMX_PROCBASED_CTLS2 or not
	};
} VMX_PROCBASED_CTLS, *PVMX_PROCBASED_CTLS;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_PROCBASED_CTLS));

//! Vol 3B, Table 21-7. Definitions of Secondary Processor-Based VM-Execution Controls
// (VMCS_FIELD_PROCBASED_CTLS2)
typedef union _VMX_PROCBASED_CTLS2
{
	UINT32 dwValue;
	struct {
		UINT32 VirtApicAccess : 1;		//!< 0		a VM exit occurs on any attempt to access
										//			data on the page with the APIC - access address
		UINT32 EnableEpt : 1;			//!< 1		Enable Extended Page Tables
		UINT32 DescriptorTableExit : 1; // 2		LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, and STR cause VM exits
		UINT32 EnableRdtscp : 1;		//!< 3		When clear RTSCP causes an Invalid Opcode fault
		UINT32 VirtX2ApicAccess : 1;	//!< 4		Causes RDMSR and WRMSR to IA32_X2APIC_TPR to use the TPR shadow
		UINT32 EnableVpid : 1;			//!< 5		cached translations of linear addresses 
										//			are associated with a virtual - processor identifier
		UINT32 WbinvdExit : 1;			//!< 6		WBINVD causes a VM exit
		UINT32 UnrestrictedGuest : 1;	//!< 7		Guest software may run in unpaged protected mode or 
										//			in real - address mode
		UINT32 Reserved0 : 2;			//!< 8-9
		UINT32 PauseLoopExit : 1;		//!< 10		A series of executions of PAUSE can cause a VM exit
		UINT32 Reserved1 : 21;			//!< 11-31
	};
} VMX_PROCBASED_CTLS2, *PVMX_PROCBASED_CTLS2;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_PROCBASED_CTLS2));

//! Vol 3B, Table 21-9. Definitions of VM-Exit Controls (VMCS_FIELD_VMEXIT_CTLS)
typedef union _VMX_EXIT_CTLS
{
	UINT32 dwValue;
	struct {
		UINT32 Reserved0 : 2;				//!< 0-1
		UINT32 SaveDebugControls : 1;		//!< 2		DR7 and the IA32_DEBUGCTL MSR are saved on VM exit
		UINT32 Reserved1 : 6;				//!< 3-8
		UINT32 IsHost64bit : 1;				//!< 9		Is host in 64bit mode
		UINT32 Reserved2 : 2;				//!< 10-11
		UINT32 LoadIa32PerfGlobalCtrl : 1;	//!< 12		IA32_PERF_GLOBAL_CTRL MSR is loaded on VM exit
		UINT32 Reserved3 : 2;				//!< 13-14
		UINT32 AckIntOnExit : 1;			//!< 15		Acknowledge the interrupt, acquiring the vector data
		UINT32 Reserved4 : 2;				//!< 16-17
		UINT32 SaveIa32Pat : 1;				//!< 18		IA32_PAT MSR is saved on VM exit
		UINT32 LoadIa32Pat : 1;				//!< 19		IA32_PAT MSR is loaded on VM exit
		UINT32 SaveIa32Efer : 1;			//!< 20		IA32_EFER MSR is saved on VM exit
		UINT32 LoadIa32Efer : 1;			//!< 21		IA32_EFER MSR is loaded on VM exit
		UINT32 SavePreemtptionTimer : 1;	//!< 22		Save the current value of VMX preemption timer
		UINT32 Reserved5 : 9;				//!< 23-31
	};
} VMX_EXIT_CTLS, *PVMX_EXIT_CTLS;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_EXIT_CTLS));

//! Vol 3B, Table 21-11. Definitions of VM-Entry Controls (VMCS_FIELD_VMENTRY_CTLS)
typedef union _VMX_ENTRY_CTLS
{
	UINT32 dwValue;
	struct {
		UINT32 Reserved0 : 2;				//!< 0-1
		UINT32 LoadDebugControls : 1;		//!< 2	DR7 and the IA32_DEBUGCTL MSR are loaded on VM exit
		UINT32 Reserved1 : 6;				//!< 3-8
		UINT32 IsGuest64bit : 1;			//!< 9	Is guest in 64bit mode
		UINT32 EnterSmm : 1;				//!< 10	Is guest in SMM mode
		UINT32 DisableDualMonitor : 1;		//!< 11	Restore default behavior for SMM after VM entry
		UINT32 Reserved2 : 1;				//!< 12
		UINT32 LoadIa32PerfGlobalCtrl : 1;	//!< 13	IA32_PERF_GLOBAL_CTRL MSR is loaded on VM entry
		UINT32 LoadIa32Pat : 1;				//!< 14	IA32_PAT is loaded on VM entry
		UINT32 LoadIa32Efer : 1;			//!< 15	IA32_EFER is loaded on VM entry
		UINT32 Reserved3 : 16;				//!< 16-31
	};
} VMX_ENTRY_CTLS, *PVMX_ENTRY_CTLS;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_ENTRY_CTLS));

//! Vol 3B, 21.6.3 Exception Bitmap (VMCS_FIELD_EXCEPTION_BITMAP)
typedef union _VMX_EXCEPTION_BITMAP
{
	UINT32 dwValue;
	struct {
		UINT32 De : 1;			//!< 0	Divide - by - zero Error #DE
		UINT32 Db : 1;			//!< 1	Debug Fault/Trap #DB
		UINT32 Nmi : 1;			//!< 2	Non Maskable Interrupt
		UINT32 Bp : 1;			//!< 3	Breakpoint #BP
		UINT32 Of : 1;			//!< 4	Overflow #OF
		UINT32 Br : 1;			//!< 5	Bound Range Exceeded #BR
		UINT32 Ud : 1;			//!< 6	Invalid Opcode #UD
		UINT32 Nm : 1;			//!< 7	Device Not Available #NM
		UINT32 Df : 1;			//!< 8	Double Fault #DF
		UINT32 So : 1;			//!< 9	Coprocessor Segment Overrun Fault
		UINT32 Ts : 1;			//!< 10	Invalid TSS #TS
		UINT32 Np : 1;			//!< 11	Segment Not Present #NP
		UINT32 Ss : 1;			//!< 12	Stack - Segment Fault #SS
		UINT32 Gp : 1;			//!< 13	General Protection Fault #GP
		UINT32 Pf : 1;			//!< 14	Page Fault #PF
		UINT32 Reserved0 : 1;	//!< 15
		UINT32 Mf : 1;			//!< 16	x87 Floating - Point Exception
		UINT32 Ac : 1;			//!< 17	Alignment Check Fault #AC
		UINT32 Mc : 1;			//!< 18	Machine Check #MC
		UINT32 Xm : 1;			//!< 19	SIMD Floating - Point Exception #XM / #XF
		UINT32 Ve : 1;			//!< 20	Virtualization Exception #VE
		UINT32 Reserved1 : 9;	//!< 21-29
		UINT32 Sx : 1;			//!< 30	Security Exception #SX
		UINT32 Reserved2 : 1;	//!< 31
	};
} VMX_EXCEPTION_BITMAP, *PVMX_EXCEPTION_BITMAP;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_EXCEPTION_BITMAP));

//! Vol 3B, 21.6.4 I/O-Bitmap Addresses (VMCS_FIELD_IO_BITMAP_A_FULL)
typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VMX_IO_BITMAPS
{
	UINT8 tIoBitmapA[PAGE_SIZE]; //!< 0 - 0x7FFF
	UINT8 tIoBitmapB[PAGE_SIZE]; //!< 0x8000 - 0xFFFF
} VMX_IO_BITMAPS, *PVMX_IO_BITMAPS;
C_ASSERT((2 * PAGE_SIZE) == sizeof(VMX_IO_BITMAPS));

//! Vol 3B, 21.6.9 MSR-Bitmap Address (VMCS_FIELD_MSR_BITMAP_FULL)
typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VMX_MSR_BITMAPS
{
	UINT8 tRdmsrL[PAGE_SIZE / 4]; //!< RDMSR 0 - 0x1FFF
	UINT8 tRdmsrH[PAGE_SIZE / 4]; //!< RDMSR 0xC0000000 - 0xC0001FFF
	UINT8 tWrmsrL[PAGE_SIZE / 4]; //!< WRMSR 0 - 0x1FFF
	UINT8 tWrmsrH[PAGE_SIZE / 4]; //!< WRMSR 0xC0000000 - 0xC0001FFF
} VMX_MSR_BITMAPS, *PVMX_MSR_BITMAPS;
C_ASSERT(PAGE_SIZE == sizeof(VMX_MSR_BITMAPS));

typedef enum _VMX_ADDRESS_SIZE
{
	VMX_ADDRESS_SIZE_16BIT = 0,
	VMX_ADDRESS_SIZE_32BIT = 1,
	VMX_ADDRESS_SIZE_64BIT = 2
} VMX_ADDRESS_SIZE, *PVMX_ADDRESS_SIZE;

typedef enum _VMX_OPERAND_SIZE
{
	VMX_OPERAND_SIZE_16BIT = 0,
	VMX_OPERAND_SIZE_32BIT = 1
} VMX_OPERAND_SIZE, *PVMX_OPERAND_SIZE;

typedef enum _VMX_SEGMENT_REGISTER_INDEX
{
	VMX_ES_SELECTOR_INDEX = 0,
	VMX_CS_SELECTOR_INDEX = 1,
	VMX_SS_SELECTOR_INDEX = 2,
	VMX_DS_SELECTOR_INDEX = 3,
	VMX_FS_SELECTOR_INDEX = 4,
	VMX_GS_SELECTOR_INDEX = 5
} VMX_SEGMENT_REGISTER_INDEX, *PVMX_SEGMENT_REGISTER_INDEX;

typedef enum _VMX_GP_REGISTER_INDEX
{
	VMX_RAX_INDEX = 0,
	VMX_RCX_INDEX = 1,
	VMX_RDX_INDEX = 2,
	VMX_RBX_INDEX = 3,
	VMX_RSP_INDEX = 4,
	VMX_RBP_INDEX = 5,
	VMX_RSI_INDEX = 6,
	VMX_RDI_INDEX = 7,
	VMX_R8_INDEX = 8,
	VMX_R9_INDEX = 9,
	VMX_R10_INDEX = 10,
	VMX_R11_INDEX = 11,
	VMX_R12_INDEX = 12,
	VMX_R13_INDEX = 13,
	VMX_R14_INDEX = 14,
	VMX_R15_INDEX = 15,
} VMX_GP_REGISTER_INDEX, *PVMX_GP_REGISTER_INDEX;

typedef enum _VMX_SCALING
{
	VMX_NO_SCALING = 0,
	VMX_SCALE_BY_2 = 1,
	VMX_SCALE_BY_4 = 2,
	VMX_SCALE_BY_8 = 3
} VMX_SCALING, *PVMX_SCALING;

//! Vol 3B, 23.5 EVENT INJECTION
typedef enum _VMX_INTERRUPTION_TYPE
{
	VMX_INT_TYPE_EXTERNAL = 0,
	VMX_INT_TYPE_NMI = 2,
	VMX_INT_TYPE_HW_EXCEPTION = 3,
	VMX_INT_TYPE_SW_INTERRUPT = 4,
	VMX_INT_TYPE_PRIVILEGED_SW = 5,
	VMX_INT_TYPE_SW_EXCEPTION = 6,
} VMX_INTERRUPTION_TYPE, *PVMX_INTERRUPTION_TYPE;

//! Table 21-12. Format of the VM-Entry Interruption-Information Field
// (VMCS_FIELD_VM_ENTRY_INTR_INFO)
typedef union _VMX_VM_ENTRY_INTR_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Vector : 8;				//!< 0-7	Vector of interrupt or exception
		UINT32 InterruptionType : 3;	//!< 8-10	See VMX_INTERRUPTION_TYPE
		UINT32 ErrorCodeValid : 1;		//!< 11		0=invalid, 1=valid
		UINT32 Reserved0 : 18;			//!< 12-30	0
		UINT32 Valid : 1;				//!< 31		Is structure valid
	};
} VMX_VM_ENTRY_INTR_INFO, *PVMX_VM_ENTRY_INTR_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_VM_ENTRY_INTR_INFO));

//! Table 21-13. Format of Exit Reason (VMCS_FIELD_VM_EXIT_REASON)
typedef union _VMX_VMEXIT_REASON
{
	UINT32 dwValue;
	struct {
		UINT32 ExitReason : 16;		//!< 0-15	Exit reason, see VMEXIT_REASON
		UINT32 Reserved0 : 12;		//!< 16-27	0
		UINT32 PendingMtf : 1;		//!< 28		Pending MTF VM-Exit
		UINT32 ExitFromRoot : 1;	//!< 29		VM-Exit from root operation
		UINT32 Reserved1 : 1;		//!< 30		0
		UINT32 EntryFailed : 1;		//!< 31		VM-Entry failed
	};
} VMX_VMEXIT_REASON, *PVMX_VMEXIT_REASON;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_VMEXIT_REASON));

//! Vol 3B, Table 21-14. Format of the VM-Exit Interruption-Information Field
// (VMCS_FIELD_VM_EXIT_INTR_INFO)
typedef union _VMX_VM_EXIT_INTR_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Vector : 8;				//!< 0-7	Vector of interrupt or exception
		UINT32 InterruptionType : 3;	//!< 8-10	See VMX_INTERRUPTION_TYPE
		UINT32 ErrorCodeValid : 1;		//!< 11		0=invalid, 1=valid
		UINT32 NmiUnblocking : 1;		//!< 12		NMI unblocking due to IRET
		UINT32 Reserved0 : 18;			//!< 13-30	0
		UINT32 Valid : 1;				//!< 31		Is structure valid
	};
} VMX_VM_EXIT_INTR_INFO, *PVMX_VM_EXIT_INTR_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_VM_EXIT_INTR_INFO));

//! Table 21-15. Format of the IDT-Vectoring Information Field (VMCS_FIELD_IDT_VECTORING_INFO)
typedef union _VMX_IDT_VECTORING_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Vector : 8;				//!< 0-7	Vector of interrupt or exception
		UINT32 InterruptionType : 3;	//!< 8-10	See VMX_INTERRUPTION_TYPE
		UINT32 ErrorCodeValid : 1;		//!< 11		0=invalid, 1=valid
		UINT32 Undefined0 : 1;			//!< 12
		UINT32 Reserved0 : 18;			//!< 13-30	0
		UINT32 Valid : 1;				//!< 31		Is structure valid
	};
} VMX_IDT_VECTORING_INFO, *PVMX_IDT_VECTORING_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_IDT_VECTORING_INFO));

//! Table 24-1. Exit Qualification for Debug Exceptions (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_DEBUG_EXCEPTION_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 Breakpoint : 4;	//!< 0-3	B0-B3. Indicates which breakpoint condition was met
		UINT64 Reserved0 : 9;   //!< 4-12
		UINT64 Bd : 1;			//!< 13		Debug exception due to debug register access
		UINT64 Bs : 1;			//!< 14		Debug exception due to opcode/branch
		UINT64 Reserved1 : 49;  //!< 15-63
	};
} VMX_DEBUG_EXCEPTION_EXIT_QUALIFICATION, *PVMX_DEBUG_EXCEPTION_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_DEBUG_EXCEPTION_EXIT_QUALIFICATION));

typedef enum _VMX_TASK_SWITCH_CAUSE
{
	VMX_TASK_SWITCH_CAUSE_CALL = 0,
	VMX_TASK_SWITCH_CAUSE_IRET = 1,
	VMX_TASK_SWITCH_CAUSE_JMP = 2,
	VMX_TASK_SWITCH_CAUSE_TASK_GATE = 3
} VMX_TASK_SWITCH_CAUSE, *PVMX_TASK_SWITCH_CAUSE;

//! Table 24-2. Exit Qualification for Task Switch (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_TASK_SWITCH_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 TssSelector : 16;	//!< 0-15	TSS to which the guest attempted to switch
		UINT64 Reserved0 : 14;		//!< 16-29
		UINT64 TaskSwitchCause : 2; //!< 30-31	See VMX_TASK_SWITCH_CAUSE
		UINT64 Reserved1 : 32;		//!< 32-63
	};
} VMX_TASK_SWITCH_EXIT_QUALIFICATION, *PVMX_TASK_SWITCH_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_TASK_SWITCH_EXIT_QUALIFICATION));

//! Table 24-3. Exit Qualification for Control-Register Accesses
typedef enum _VMX_MOV_CR_ACCESS_TYPE
{
	VMX_MOV_CR_ACCESS_TYPE_TO_CR = 0,
	VMX_MOV_CR_ACCESS_TYPE_FROM_CR,
	VMX_MOV_CR_ACCESS_TYPE_CLTS,
	VMX_MOV_CR_ACCESS_TYPE_LMSW,
} VMX_MOV_CR_ACCESS_TYPE, *PVMX_MOV_CR_ACCESS_TYPE;

//! Table 24-3. Exit Qualification for Control-Register Accesses (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_MOV_CR_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 ControlRegister : 4; //!< 0-3	Number of control register (0 for CLTS and LMSW)
		UINT64 AccessType : 2;      //!< 4-5	See VMX_MOV_CR_ACCESS_TYPE
		UINT64 LmswOperandType : 1; //!< 6		MSW operand type: 0=register, 1=memory
		UINT64 Reserved0 : 1;       //!< 7
		UINT64 GpRegister : 4;      //!< 8-11	See VMX_GP_REGISTER_INDEX
		UINT64 Reserved1 : 4;       //!< 12-15
		UINT64 LmswSourceData : 16; //!< 16-31	LMSW source data, or 0 for CTLS and MOV CRx
		UINT64 Reserved2 : 32;		//!< 32-63
	};
} VMX_MOV_CR_EXIT_QUALIFICATION, *PVMX_MOV_CR_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_MOV_CR_EXIT_QUALIFICATION));

// 24-4. Exit Qualification for MOV DR (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_MOV_DR_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 DebugRegister : 3;	//!< 0-2	Number of debug register
		UINT64 Reserved0 : 1;		//!< 3
		UINT64 Direction : 1;		//!< 4		0=MOV to DR, 1=MOV from DR
		UINT64 Reserved1 : 3;		//!< 5-7
		UINT64 GpRegister : 4;		//!< 8-11	See VMX_GP_REGISTER_INDEX
		UINT64 Reserved2 : 52;		//!< 12-63
	};
} VMX_MOV_DR_EXIT_QUALIFICATION, *PVMX_MOV_DR_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_MOV_DR_EXIT_QUALIFICATION));

typedef enum _VMX_IO_ACCESS_SIZE
{
	VMX_IO_ACCESS_SIZE_1 = 0,
	VMX_IO_ACCESS_SIZE_2 = 1,
	VMX_IO_ACCESS_SIZE_4 = 3
} VMX_IO_ACCESS_SIZE, *PVMX_IO_ACCESS_SIZE;

//! Table 24-5. Exit Qualification for I/O Instructions (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_IO_OPCODE_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 AccessSize : 3;		//!< 0-2	See VMX_IO_ACCESS_SIZE
		UINT64 Direction : 1;		//!< 3		0=OUT, 1=IN
		UINT64 IsString : 1;		//!< 4		0=Not a string, 1=String
		UINT64 RepPrefixed : 1;		//!< 5		0=not REP, 1=REP		
		UINT64 Reserved0 : 9;		//!< 7-15
		UINT64 PortNumber : 8;		//!< 16-31	Port number (DX)
		UINT64 Reserved1 : 32;		//!< 32-63
	};
} VMX_IO_OPCODE_EXIT_QUALIFICATION, *PVMX_IO_OPCODE_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_IO_OPCODE_EXIT_QUALIFICATION));

typedef enum _VMX_APIC_ACCESS_TYPE
{
	VMX_APIC_ACCESS_TYPE_LINEAR_READ = 0,			//!< linear access for a data read during instruction execution
	VMX_APIC_ACCESS_TYPE_LINEAR_WRITE = 1,			//!< linear access for a data write during instruction execution
	VMX_APIC_ACCESS_TYPE_LINEAR_FETCH = 2,			//!< linear access for an instruction fetch
	VMX_APIC_ACCESS_TYPE_LINEAR_RW_EVENT = 3,		//!< linear access (read or write) during event delivery
	VMX_APIC_ACCESS_TYPE_GUEST_PHYSICAL = 10,		//!< guest-physical access during event delivery
	VMX_APIC_ACCESS_TYPE_GUEST_PHYSICAL_FETCH = 15,	//!< guest-physical access for an instruction fetch or during instruction execution
} VMX_APIC_ACCESS_TYPE, *PVMX_APIC_ACCESS_TYPE;

//!	Table 24-6. Exit Qualification for APIC-Access VM Exits from Linear Accesses 
//	and Guest - Physical Accesses (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_APIC_ACCESS_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 Offset : 12;		//!< 0-11	Offset within APIC page
		UINT64 AccessType : 4;	//!< 12-15	See VMX_APIC_ACCESS_TYPE
		UINT64 Reserved0 : 48;	//!< 16-63
	};
} VMX_APIC_ACCESS_EXIT_QUALIFICATION, *PVMX_APIC_ACCESS_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_APIC_ACCESS_EXIT_QUALIFICATION));

//! Table 24-7. Exit Qualification for EPT Violations (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_EPT_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 ReadAccess : 1;			//!< 0		EPT violation was a data read
		UINT64 WriteAccess : 1;			//!< 1		EPT violation was a data write
		UINT64 ExecuteAccess : 1;		//!< 2		EPT violation was an instruction fetch
		UINT64 GuestAllowRead : 1;		//!< 3		Guest page table allows read
		UINT64 GuestAllowWrite : 1;		//!< 4		Guest page table allows write
		UINT64 GuestAllowExecute : 1;	//!< 5		Guest page table allows execute
		UINT64 Reserved0 : 1;			//!< 6
		UINT64 AddressValid : 1;		//!< 7		Valid for all EPT-violations, except those resulting from 
										//			an attempt to load the guest PDPTEs as part of the execution of
										//			the MOV CR instruction
		UINT64 IsMemoryAccess : 1;		//!< 8		0=Change to PTE access/dirty bit, 1=access to memory
		UINT64 Reserved1 : 3;			//!< 9-11
		UINT64 NmiUnblocking : 1;		//!< 12		NMI unblocking due to IRET
		UINT64 Reserved2 : 51;			//!< 13-63
	};
} VMX_EPT_EXIT_QUALIFICATION, *PVMX_EPT_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_EPT_EXIT_QUALIFICATION));

//! Table 24-8. Format of the VM-Exit Instruction-Information Field 
// as Used for INS and OUTS (VMCS_FIELD_INSTRUCTION_INFO)
typedef union _VMX_IO_INSTRUCTION_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Undefined0 : 7;		//!< 0-6	
		UINT32 AddressSize : 3;		//!< 7-9	See VMX_ADDRESS_SIZE
		UINT32 Undefined1 : 5;		//!< 10-14
		UINT32 SegmentRegister : 3;	//!< 15-17	See VMX_SEGMENT_REGISTER_INDEX
		UINT32 Undefined2 : 14;		//!< 18-31
	};
} VMX_IO_INSTRUCTION_INFO, *PVMX_IO_INSTRUCTION_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_IO_INSTRUCTION_INFO));

typedef enum _VMX_IDT_OR_GDT_INSTRUCTION_ID
{
	VMX_SGDT_ID = 0,
	VMX_SIDT_ID = 1,
	VMX_LGDT_ID = 2,
	VMX_LIDT_ID = 3
} VMX_IDT_OR_GDT_INSTRUCTION_ID, *PVMX_IDT_OR_GDT_INSTRUCTION_ID;

//! Table 24-9. Format of the VM-Exit Instruction-Information Field as Used for 
//	LIDT, LGDT, SIDT, or SGDT (VMCS_FIELD_INSTRUCTION_INFO)
typedef union _VMX_IDT_OR_GDT_ACCESS_INSTRUCTION_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Scalling : 2;				//!<  0-1	See VMX_SCALING
		UINT32 Reserved1 : 5;				//!<  2-6
		UINT32 AddressSize : 3;				//!<  7-9	See VMX_ADDRESS_SIZE
		UINT32 Reserved2 : 1;				//!<  10
		UINT32 OperandSize : 1;				//!<  11	See VMX_OPERAND_SIZE
		UINT32 Reserved3 : 3;				//!<  12-14
		UINT32 SegmentRegister : 3;			//!<  15-17 See VMX_SEGMENT_REGISTER_INDEX
		UINT32 IndexRegister : 4;			//!<  18-21 See VMX_GP_REGISTER_INDEX
		UINT32 IndexRegisterInvalid : 1;	//!<  22	0=valid, 1=invalid
		UINT32 BaseRegister : 4;			//!<  23-26 BaseReg (encoded as IndexRegister above)
		UINT32 BaseRegisterInvalid : 1;		//!<  27	0=valid, 1=invalid
		UINT32 InstructionIdentity : 2;		//!<  28-29 See VMX_IDT_OR_GDT_INSTRUCTION_ID
		UINT32 Reserved4 : 2;				//!<  30-31
	};
} VMX_IDT_OR_GDT_ACCESS_INSTRUCTION_INFO, *PVMX_IDT_OR_GDT_ACCESS_INSTRUCTION_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_IDT_OR_GDT_ACCESS_INSTRUCTION_INFO));

typedef enum _VMX_LDT_OR_TR_INSTRUCTION_ID
{
	VMX_SLDT_ID = 0,
	VMX_STR_ID = 1,
	VMX_LLDT_ID = 2,
	VMX_LTR_ID = 3
} VMX_LDT_OR_TR_INSTRUCTION_ID, *PVMX_LDT_OR_TR_INSTRUCTION_ID;

//! Table 24-10. Format of the VM-Exit Instruction-Information Field 
// as Used for LLDT, LTR, SLDT, and STR (VMCS_FIELD_INSTRUCTION_INFO)
typedef union _VMX_LDT_OR_TR_ACCESS_INSTRUCTION_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Scalling : 2;				//!<  0-1	See VMX_SCALING
		UINT32 Undefined0 : 1;				//!<  2
		UINT32 GpRegister : 4;				//!<  3-6	See VMX_GP_REGISTER_INDEX
		UINT32 AddressSize : 3;				//!<  7-9	See VMX_ADDRESS_SIZE
		UINT32 IsRegister : 1;				//!<  10	0=memory, 1=register
		UINT32 Undefined1 : 4;				//!<  11-14
		UINT32 SegmentRegister : 3;			//!<  15-17 See VMX_SEGMENT_REGISTER_INDEX
		UINT32 IndexRegister : 4;			//!<  18-21 See VMX_GP_REGISTER_INDEX
		UINT32 IndexRegisterInvalid : 1;	//!<  22	0=valid, 1=invalid
		UINT32 BaseRegister : 4;			//!<  23-26 BaseReg (encoded as IndexRegister above)
		UINT32 BaseRegisterInvalid : 1;		//!<  27	0=valid, 1=invalid
		UINT32 InstructionIdentity : 2;		//!<  28-29 See VMX_LDT_OR_TR_INSTRUCTION_ID
		UINT32 Undefined2 : 2;				//!<  30-31
	};
} VMX_LDT_OR_TR_ACCESS_INSTRUCTION_INFO, *PVMX_LDT_OR_TR_ACCESS_INSTRUCTION_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_LDT_OR_TR_ACCESS_INSTRUCTION_INFO));

//! Table 24-11. Format of the VM-Exit Instruction-Information Field
// as Used for VMCLEAR, VMPTRLD, VMPTRST, and VMXON (VMCS_FIELD_INSTRUCTION_INFO)
typedef union _VMX_VMCS_PTR_OPCODES_INSTRUCTION_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Scalling : 2;				//!<  0-1	See VMX_SCALING
		UINT32 Undefined0 : 5;				//!<  2-6
		UINT32 AddressSize : 3;				//!<  7-9	See VMX_ADDRESS_SIZE
		UINT32 Zero0 : 1;					//!<  10	0
		UINT32 Undefined1 : 4;				//!<  11-14
		UINT32 SegmentRegister : 3;			//!<  15-17 See VMX_SEGMENT_REGISTER_INDEX
		UINT32 IndexRegister : 4;			//!<  18-21 See VMX_GP_REGISTER_INDEX
		UINT32 IndexRegisterInvalid : 1;	//!<  22	0=valid, 1=invalid
		UINT32 BaseRegister : 4;			//!<  23-26 BaseReg (encoded as IndexRegister above)
		UINT32 BaseRegisterInvalid : 1;		//!<  27	0=valid, 1=invalid
		UINT32 Undefined2 : 4;				//!<  28-31
	};
} VMX_VMCS_OPCODES_INSTRUCTION_INFO, *PVMX_VMCS_OPCODES_INSTRUCTION_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_VMCS_OPCODES_INSTRUCTION_INFO));

//! Table 24-12. Format of the VM-Exit Instruction-Information Field
// as Used for VMREAD and VMWRITE (VMCS_FIELD_INSTRUCTION_INFO)
typedef union _VMX_VMCS_RW_OPCODES_INSTRUCTION_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Scalling : 2;				//!<  0-1	See VMX_SCALING
		UINT32 Undefined0 : 1;				//!<  2
		UINT32 GpRegister1 : 4;				//!<  3-6	See VMX_GP_REGISTER_INDEX
		UINT32 AddressSize : 3;				//!<  7-9	See VMX_ADDRESS_SIZE
		UINT32 IsRegister : 1;				//!<  10	0=memory, 1=register
		UINT32 Undefined1 : 4;				//!<  11-14
		UINT32 SegmentRegister : 3;			//!<  15-17 See VMX_SEGMENT_REGISTER_INDEX
		UINT32 IndexRegister : 4;			//!<  18-21 See VMX_GP_REGISTER_INDEX
		UINT32 IndexRegisterInvalid : 1;	//!<  22	0=valid, 1=invalid
		UINT32 BaseRegister : 4;			//!<  23-26 BaseReg (encoded as IndexRegister above)
		UINT32 BaseRegisterInvalid : 1;		//!<  27	0=valid, 1=invalid
		UINT32 GpRegister2 : 4;				//!<  28-31 See VMX_GP_REGISTER_INDEX
	};
} VMX_VMCS_RW_OPCODES_INSTRUCTION_INFO, *PVMX_VMCS_RW_OPCODES_INSTRUCTION_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_VMCS_RW_OPCODES_INSTRUCTION_INFO));

//! Table 24-13. Format of the VM-Exit Instruction-Information Field
// as Used for INVEPT and INVVPID (VMCS_FIELD_INSTRUCTION_INFO)
typedef union _VMX_INVEPT_OR_INVVPID_INSTRUCTION_INFO
{
	UINT32 dwValue;
	struct {
		UINT32 Scalling : 2;				//!<  0-1	See VMX_SCALING
		UINT32 Undefined0 : 5;				//!<  2-6
		UINT32 AddressSize : 3;				//!<  7-9	See VMX_ADDRESS_SIZE
		UINT32 Zero0 : 1;					//!<  10	0
		UINT32 Undefined1 : 4;				//!<  11-14
		UINT32 SegmentRegister : 3;			//!<  15-17 See VMX_SEGMENT_REGISTER_INDEX
		UINT32 IndexRegister : 4;			//!<  18-21 See VMX_GP_REGISTER_INDEX
		UINT32 IndexRegisterInvalid : 1;	//!<  22	0=valid, 1=invalid
		UINT32 BaseRegister : 4;			//!<  23-26 BaseReg (encoded as IndexRegister above)
		UINT32 BaseRegisterInvalid : 1;		//!<  27	0=valid, 1=invalid
		UINT32 GpRegister2 : 4;				//!<  28-31 See VMX_GP_REGISTER_INDEX
	};
} VMX_INVEPT_OR_INVVPID_INSTRUCTION_INFO, *PVMX_INVEPT_OR_INVVPID_INSTRUCTION_INFO;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_INVEPT_OR_INVVPID_INSTRUCTION_INFO));

#define VMX_EPT_PML4E_ENTRY_COUNT   512
#define VMX_EPT_PDPTE_ENTRY_COUNT   512
#define VMX_EPT_PDE_ENTRY_COUNT     512
#define VMX_EPT_PTE_ENTRY_COUNT     512

typedef enum _VMX_EPT_MEMORY_TYPE
{
	VMX_EPT_MEMORY_TYPE_UC = 0,	// Uncachable
	VMX_EPT_MEMORY_TYPE_WC = 1,	// Write-combined
	VMX_EPT_MEMORY_TYPE_WT = 4,	// Write-through
	VMX_EPT_MEMORY_TYPE_WP = 5,	// Write-Protected
	VMX_EPT_MEMORY_TYPE_WB = 6	// Write-back
} VMX_EPT_MEMORY_TYPE, *PVMX_EPT_MEMORY_TYPE;

//! Table 25-1. Format of an EPT PML4 Entry (PML4E)
typedef union _VMX_EPT_PML4E
{
	UINT64 qwValue;
	struct {
		UINT64 Read : 1;		//!< 0		Allow read
		UINT64 Write : 1;		//!< 1		Allow write
		UINT64 Execute : 1;		//!< 2		Allow execute
		UINT64 Reserved0 : 5;	//!< 3-7	0
		UINT64 Ignored0 : 4;	//!< 8-11
		UINT64 Address : 36;	//!< 12-47	Address of VMX_EPT_PDPTE
		UINT64 Reserved1 : 4;	//!< 48-51	0
		UINT64 Ignored1 : 12;	//!< 52-63
	};
} VMX_EPT_PML4E, *PVMX_EPT_PML4E;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_EPT_PML4E));

//! Table 25-2. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE)
// that Maps a 1 - GByte Page
typedef union _VMX_EPT_PDPTE1GB
{
	UINT64 qwValue;
	struct {
		UINT64 Read : 1;		//!< 0		Allow read
		UINT64 Write : 1;		//!< 1		Allow write
		UINT64 Execute : 1;		//!< 2		Allow execute
		UINT64 MemoryType : 3;	//!< 3-5	See VMX_EPT_MEMORY_TYPE
		UINT64 IgnorePat : 1;	//!< 6		Ignore PAT memory type
		UINT64 Large : 1;		//!< 7		Must be 1 for 1GB pages
		UINT64 Ignored0 : 4;	//!< 8-11
		UINT64 Reserved0 : 18;	//!< 12-29	0
		UINT64 Address : 18;	//!< 30-47	Address of 1GB page
		UINT64 Reserved1 : 4;	//!< 48-51	0
		UINT64 Ignored1 : 12;	//!< 52-63
	};
} VMX_EPT_PDPTE1GB, *PVMX_EPT_PDPTE1GB;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_EPT_PDPTE1GB));

//! Table 25-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE)
// that References an EPT Page Directory
typedef union _VMX_EPT_PDPTE
{
	UINT64 qwValue;
	struct 	{
		UINT64 Read : 1;		//!< 0		Allow read
		UINT64 Write : 1;		//!< 1		Allow write
		UINT64 Execute : 1;		//!< 2		Allow execute
		UINT64 Reserved0 : 5;	//!< 3-7	0
		UINT64 Ignored0 : 4;	//!< 8-11
		UINT64 Address : 36;	//!< 12-47	Address of VMX_EPT_PDE
		UINT64 Reserved1 : 4;	//!< 48-51	0
		UINT64 Ignored2 : 12;	//!< 52-63
	};
} VMX_EPT_PDPTE, *PVMX_EPT_PDPTE;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_EPT_PDPTE));

//! Table 25-4. Format of an EPT Page-Directory Entry (PDE)
// that Maps a 2-MByte Page
typedef union _VMX_EPT_PDE2MB
{
	UINT64 qwValue;
	struct {
		UINT64 Read : 1;		//!< 0		Allow read
		UINT64 Write : 1;		//!< 1		Allow write
		UINT64 Execute : 1;		//!< 2		Allow execute
		UINT64 MemoryType : 3;	//!< 3-5	See VMX_EPT_MEMORY_TYPE
		UINT64 IgnorePat : 1;	//!< 6		Ignore PAT memory type
		UINT64 Large : 1;		//!< 7		Must be 1 for 2MB pages
		UINT64 Ignored0 : 1;	//!< 8-11
		UINT64 Reserved0 : 9;	//!< 12-20	0
		UINT64 Address : 27;	//!< 21-47	Address of 2MB page
		UINT64 Reserved1 : 4;	//!< 48-51	0
		UINT64 Ignored1 : 12;	//!< 52-63
	};
} VMX_EPT_PDE2MB, *PVMX_EPT_PDE2MB;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_EPT_PDE2MB));

//! Table 25-5. Format of an EPT Page-Directory Entry (PDE)
// that References an EPT Page Table
typedef union _VMX_EPT_PDE
{
	UINT64 qwValue;
	struct {
		UINT64 Read : 1;		//!< 0		Allow read
		UINT64 Write : 1;		//!< 1		Allow write
		UINT64 Execute : 1;		//!< 2		Allow execute
		UINT64 Reserved0 : 5;	//!< 3-7	0
		UINT64 Ignored0 : 4;	//!< 8-11
		UINT64 Address : 36;	//!< 12-47	Address of PTE
		UINT64 Reserved1 : 4;	//!< 48-51	0
		UINT64 Ignored1 : 12;	//!< 52-63
	};
} VMX_EPT_PDE, *PVMX_EPT_PDE;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_EPT_PDE));

//! Table 25-6. Format of an EPT Page-Table Entry
typedef union _VMX_EPT_PTE
{
	UINT64 qwValue;
	struct {
		UINT64 Read : 1;			//!< 0		Allow read
		UINT64 Write : 1;			//!< 1		Allow write
		UINT64 Execute : 1;			//!< 2		Allow execute
		UINT64 MemoryType : 3;		//!< 3-5	See VMX_EPT_MEMORY_TYPE
		UINT64 IgnorePat : 1;		//!< 6		Ignore PAT memory type
		UINT64 Ignored0 : 5;		//!< 7-11
		UINT64 Address : 36;		//!< 12-47	Address of page
		UINT64 Reserved0 : 4;		//!< 48-51	0
		UINT64 Ignored1 : 12;		//!< 52-63
	};
} VMX_EPT_PTE, *PVMX_EPT_PTE;

// An example of a VMX EPT table
typedef struct _VMX_EPT_TABLE
{
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPT_PML4E atPml4[VMX_EPT_PML4E_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPT_PDPTE atPdpte[VMX_EPT_PDPTE_ENTRY_COUNT];
	DECLSPEC_ALIGN(PAGE_SIZE) VMX_EPT_PDE2MB atPde[VMX_EPT_PDE_ENTRY_COUNT][VMX_EPT_PTE_ENTRY_COUNT];
} VMX_EPT_TABLE, *PVMX_EPT_TABLE;

//! Table 26-9. Exit Qualification for SMIs That Arrive Immediately
// After the Retirement of an I/O Instruction (VMCS_FIELD_EXIT_QUALIFICATION)
typedef union _VMX_SMI_AFTER_IO_EXIT_QUALIFICATION
{
	UINT64 qwValue;
	struct {
		UINT64 AccessSize : 3;	//!< 0-2	See VMX_IO_ACCESS_SIZE
		UINT64 Direction : 1;	//!< 3		0=OUT, 1=IN
		UINT64 IsString : 1;	//!< 4		0=Not string, 1=String
		UINT64 RepPrefixed : 1;	//!< 5		0=Not REP, 1=REP
		UINT64 Operand : 1;		//!< 6		0=DX, 1=Immediate
		UINT64 Reserved0 : 8;	//!< 7-15	0
		UINT64 PortNumber : 16;	//!< 16-31	IO Port number
		UINT64 Reserved1 : 32;	//!< 32-63	0
	};
} VMX_SMI_AFTER_IO_EXIT_QUALIFICATION, *PVMX_SMI_AFTER_IO_EXIT_QUALIFICATION;
C_ASSERT(sizeof(UINT64) == sizeof(VMX_SMI_AFTER_IO_EXIT_QUALIFICATION));

//! 26.15.5 Enabling the Dual-Monitor Treatment
typedef union _VMX_SMM_MONITOR_FEATURES
{
	UINT32 dwValue;
	struct {
		UINT32 Is64bit : 1;		//!< 0		Will SMM monitor run in 64bit
		UINT32 Reserved0 : 31;	//!< 1-31	0
	};
} VMX_SMM_MONITOR_FEATURES, *PVMX_SMM_MONITOR_FEATURES;
C_ASSERT(sizeof(UINT32) == sizeof(VMX_SMM_MONITOR_FEATURES));

//! Table 26-10. Format of MSEG Header (Monitor SEGment)
typedef struct _VMX_MSEG_HEADER
{
	UINT32						dwRevision;
	VMX_SMM_MONITOR_FEATURES	tMonitorFeatures;
	UINT32						dwGdtrLimit;
	UINT32						dwGdtrBaseOffset;
	UINT32						dwCsSelector;
	UINT32						dwEipOffset;
	UINT32						dwEspOffset;
	UINT32						dwCr3Offset;
} VMX_MSEG_HEADER, *PVMX_MSEG_HEADER;

typedef enum _VMX_OPCODE_RC
{
	VMX_SUCCESS = 0,	//!< Opcode succeeded
	VMX_ERROR,			//!< Opcode failed - read VMCS_FIELD_VM_INSTRUCTION_ERROR for info
	VMX_ERROR_NO_INFO	//!< Opcode failed - no information available on error
} VMX_OPCODE_RC, *PVMX_OPCODE_RC;

// Vol 3B, Table 30-1. VM-Instruction Error Numbers
// Define VM_INSTRUCTION_ERROR enum and error message array using X-Macros
#define VM_INSTRUCTION_ERRORS \
		X(VMERROR_VMCALL_IN_ROOT, 1, "VMCALL executed in VMX root operation") \
		X(VMERROR_VMCLEAR_INVALID_ADDR, 2, "VMCLEAR with invalid physical address") \
		X(VMERROR_VMCLEAR_WITH_VMXON, 3, "VMCLEAR with VMXON pointer") \
		X(VMERROR_VMLAUNCH_VMCS_UNCLEAR, 4, "VMLAUNCH with non - clear VMCS") \
		X(VMERROR_VMRESUME_VMCS_NOT_LAUNCHED, 5, "VMRESUME with non - launched VMCS") \
		X(VMERROR_VMRESUME_AFTER_VMXOFF, 6, "VMRESUME after VMXOFF(VMXOFF and VMXON between VMLAUNCH and VMRESUME)") \
		X(VMERROR_VMENTRY_INVALID_CONTROLS, 7, "VM entry with invalid control field(s)") \
		X(VMERROR_VMENTRY_INVALID_STATE, 8, "VM entry with invalid host - state field(s)") \
		X(VMERROR_VMPTRLD_INVALID_ADDR, 9, "VMPTRLD with invalid physical address") \
		X(VMERROR_VMPTRLD_WITH_VMXON, 10, "VMPTRLD with VMXON pointer") \
		X(VMERROR_VMPTRLD_BAD_REVISION, 11, "VMPTRLD with incorrect VMCS revision identifier") \
		X(VMERROR_VM_RW_BAD_FIELD, 12, "VMREAD / VMWRITE from / to unsupported VMCS component") \
		X(VMERROR_VMWRITE_TO_READONLY_FIELD, 13, "VMWRITE to read - only VMCS component") \
		X(VMERROR_VMXON_IN_ROOT, 15, "VMXON executed in VMX root operation") \
		X(VMERROR_VMENTRY_BAD_VMCS_PTR, 16, "VM entry with invalid executive - VMCS pointer") \
		X(VMERROR_VMENTRY_VMCS_PTR_NOT_LAUNCHED, 17, "VM entry with non - launched executive VMCS") \
		X(VMERROR_VMENTRY_DURING_DUAL_MONITOR_SHUTDOWN, 18, "VM entry with executive - VMCS pointer not VMXON pointer(when attempting to deactivate the dual - monitor treatment of, SMIs and SMM)") \
		X(VMERROR_VMCALL_VMCS_UNCLEAR, 19, "VMCALL with non - clear VMCS(when attempting to activate the dual - monitor treatment of SMIs and SMM)") \
		X(VMERROR_VMCALL_INVALID_CONTROLS, 20, "VMCALL with invalid VM - exit control fields") \
		X(VMERROR_VMCALL_BAD_REVISION, 22, "VMCALL with incorrect MSEG revision identifier(when attempting to activate the dual - monitor treatment of SMIs and SMM)") \
		X(VMERROR_VMXOFF_IN_DUAL_MONITOR, 23, "VMXOFF under dual - monitor treatment of SMIs and SMM") \
		X(VMERROR_VMCALL_INVALID_FEATURE, 24, "VMCALL with invalid SMM - monitor features(when attempting to activate the dual - monitor treatment of SMIs and SMM)") \
		X(VMERROR_VMENTRY_INVALID_CONTROLS_SMM, 25, "VM entry with invalid VM-execution control fields in executive VMCS (when attempting to return from SMM)") \
		X(VMERROR_VMENTRY_EVENTS_BLOCKED, 26, "VM entry with events blocked by MOV SS.") \
		X(VMERROR_INV_BAD_OPERAND, 28, "Invalid operand to INVEPT / INVVPID.")

typedef enum _VM_INSTRUCTION_ERROR
{
#define X(EnumName,EnumValue,ErrorMsg) EnumName = EnumValue,
	VM_INSTRUCTION_ERRORS
#undef X
	VM_INSTRUCTION_ERROR_MAX
} VM_INSTRUCTION_ERROR, *PVM_INSTRUCTION_ERROR;

/**
* Get the error messages string for the VM instruction error
* @param eVmError - value of VMCS_FIELD_VM_INSTRUCTION_ERROR after a VMX_ERROR
* @return Error message string
*/
LPCSTR
VTX_GetVmInstructionErrorMsg(
	IN const VM_INSTRUCTION_ERROR eVmError
);

// Vol 3B, 27.5 VMM SETUP & TEAR DOWN
/**
* Adjust the value of CR0 according to the FIXED MSRs
* to clear/set bits that the CPU doesn't/must support
* @param ptCr0 - value to edit
*/
VOID
VTX_AdjustCr0(
	OUT PCR0_REG ptCr0
);

/**
* Adjust the value of CR4 according to the FIXED MSRs
* to clear/set bits that the CPU doesn't/must support
* @param ptCr4 - value to edit
*/
VOID
VTX_AdjustCr4(
	OUT PCR4_REG ptCr4
);

/**
* Adjust the value of the VMX execution control according to the MSR
* to clear/set bits that the CPU doesn't/must support.
* @param dwAdjustMsrCode - MSR code of MSR used to adjust the VMX control
* @param pdwCtlValue - VMX execution control to adjust
*/
VOID
VTX_AdjustCtl(
	IN	const UINT32	dwAdjustMsrCode,
	OUT	PUINT32			pdwCtlValue
);

// Vol 3B, 21.6 VM-EXECUTION CONTROL FIELDS
#define VMX_ADJUST_PINBASED_CTLS(pdwCtlValue) \
	VTX_AdjustCtl(MSR_CODE_IA32_VMX_PINBASED_CTLS, (pdwCtlValue))
#define VMX_ADJUST_PROCBASED_CTLS(pdwCtlValue) \
	VTX_AdjustCtl(MSR_CODE_IA32_VMX_PROCBASED_CTLS, (pdwCtlValue))
#define VMX_ADJUST_PROCBASED_CTLS2(pdwCtlValue) \
	VTX_AdjustCtl(MSR_CODE_IA32_VMX_PROCBASED_CTLS2, (pdwCtlValue))
#define VMX_ADJUST_EXIT_CTLS(pdwCtlValue) \
	VTX_AdjustCtl(MSR_CODE_IA32_VMX_EXIT_CTLS, (pdwCtlValue))
#define VMX_ADJUST_ENTRY_CTLS(pdwCtlValue) \
	VTX_AdjustCtl(MSR_CODE_IA32_VMX_ENTRY_CTLS, (pdwCtlValue))

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_VT_X_H__ */
