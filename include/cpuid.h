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
* @file		cpuid.h
* @section	CPUID structures and functions (https://en.wikipedia.org/wiki/CPUID)
*/

#ifndef __INTEL_CPUID_H__
#define __INTEL_CPUID_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
typedef enum _CPUID_FUNCTION
{
	// Basic CPUID Information
	CPUID_FUNCTION_BASIC_VENDOR_ = 0,
	CPUID_FUNCTION_BASIC_FEATURES = 1,
	CPUID_FUNCTION_BASIC_TLB = 2,
	CPUID_FUNCTION_BASIC_SERIAL = 3,

	// Deterministic Cache Parameters Leaf
	CPUID_FUNCTION_CACHE = 4,

	// MONITOR/MWAIT Leaf
	CPUID_FUNCTION_MONITOR = 5,

	// Thermal and Power Management Leaf
	CPUID_FUNCTION_POWERMGMT = 6,

	// Structured Extended Feature Flags Enumeration Leaf
	CPUID_FUNCTION_FEATURES_EX = 7,

	// Direct Cache Access Information Leaf
	CPUID_FUNCTION_DCA_CAP = 9,

	// Architectural Performance Monitoring Leaf
	CPUID_FUNCTION_PERFORMANCE = 0xA,

	// Extended Topology Enumeration Leaf
	CPUID_FUNCTION_TOPOLOGY_EX = 0xB,

	// Processor Extended State Enumeration Main Leaf (EAX = 0DH, ECX = 0)
	// Processor Extended State Enumeration Sub-leaf (EAX = 0DH, ECX = 1)
	// Processor Extended State Enumeration Sub-leaves (EAX = 0DH, ECX = n, n > 1)
	CPUID_FUNCTION_PROC_STATE_EX = 0xD,

	// Platform QoS Monitoring Enumeration Sub-leaf (EAX = 0FH, ECX = 0)
	// L3 Cache QoS Monitoring Capability Enumeration Sub-leaf (EAX = 0FH, ECX = 1)
	CPUID_FUNCTION_QOS0 = 0xF,

	// Platform QoS Enforcement Enumeration Sub-leaf (EAX = 10H, ECX = 0)
	// L3 Cache QoS Enforcement Enumeration Sub-leaf (EAX = 10H, ECX = ResID =1)
	CPUID_FUNCTION_QOS1 = 0x10,

	// Intel Processor Trace Enumeration Main Leaf (EAX = 14H, ECX = 0)
	// Intel Processor Trace Enumeration Sub-leaf (EAX = 14H, ECX = 1)
	CPUID_FUNCTION_TRACE = 0x14,

	// Time Stamp Counter/Core Crystal Clock Information-leaf
	CPUID_FUNCTION_TSC = 0x15,

	// Processor Frequency Information Leaf
	CPUID_FUNCTION_FREQUENCY = 0x16,

	// System-On-Chip Vendor Attribute Enumeration Main Leaf (EAX = 17H, ECX = 0)
	// System-On-Chip Vendor Attribute Enumeration Sub-leaf (EAX = 17H, ECX = 1..3)
	// System-On-Chip Vendor Attribute Enumeration Sub-leaves (EAX = 17H, ECX > MaxSOCID_Index)
	CPUID_FUNCTION_SOC = 0x17,

	// Reserved 0x40000000 - 0x4FFFFFFF

	// Extended Function CPUID Information
	CPUID_FUNCTION_EX_MAXFUNC = 0x80000000,
	CPUID_FUNCTION_EX_FEATURES = 0x80000001,
	CPUID_FUNCTION_EX_BRAND_STRING0 = 0x80000002,
	CPUID_FUNCTION_EX_BRAND_STRING1 = 0x80000003,
	CPUID_FUNCTION_EX_BRAND_STRING2 = 0x80000004,
	// Reserved 0x80000005
	CPUID_FUNCTION_EX_CACHE = 0x80000006,
	CPUID_FUNCTION_EX_TSC = 0x80000007,
	CPUID_FUNCTION_EX_MAXADDR = 0x80000008,
} CPUID_FUNCTION, *PCPUID_FUNCTION;

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
typedef struct _CPUID_REGISTERS
{
	UINT32 dwEax;
	UINT32 dwEbx;
	UINT32 dwEcx;
	UINT32 dwEdx;
} CPUID_REGISTERS, *PCPUID_REGISTERS;

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
typedef struct _CPUID_BASIC_VENDOR
{
	UINT32 dwMaxBasicInfo;
	CHAR szVendor[12];
} CPUID_BASIC_VENDOR, *PCPUID_BASIC_VENDOR;
C_ASSERT(sizeof(CPUID_REGISTERS) == sizeof(CPUID_BASIC_VENDOR));

//! Vol 2A, Table 3-18. Processor Type Field
typedef enum _CPUID_PROCESSOR_TYPE
{
	CPUID_PROCESSOR_TYPE_ORIG_OEM = 0,
	CPUID_PROCESSOR_TYPE_OVERDRIVE = 1,
	CPUID_PROCESSOR_TYPE_DUAL = 2,
	CPUID_PROCESSOR_TYPE_INTEL_RESERVED = 3,
} CPUID_PROCESSOR_TYPE, *PCPUID_PROCESSOR_TYPE;

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
//! Vol 2A, Figure 3-6. Version Information Returned by CPUID in EAX
//! Vol 2A, Table 3-19. Feature Information Returned in the ECX Register
//! Vol 2A, Table 3-20. More on Feature Information Returned in the EDX Register
// https://en.wikipedia.org/wiki/CPUID#EAX=1:_Processor_Info_and_Feature_Bits
typedef struct _CPUID_BASIC_FEATURES
{
	UINT32 SteppingId : 4;		//!< EAX 0-3	Stepping ID
	UINT32 Model : 4;			//!< EAX 4-7	Model
	UINT32 FamilyId : 4;		//!< EAX 8-11	Family (0FH for the Pentium 4 Processor Family)
	UINT32 ProcessorType : 2;	//!< EAX 12-13	See CPUID_PROCESSOR_TYPE
	UINT32 Reserved0 : 2;		//!< EAX 14-15	0
	UINT32 ExModelId : 4;		//!< EAX 16-19	Extended Model ID (0)
	UINT32 ExFamilyId : 8;		//!< EAX 20-27	Extended Family ID (0)
	UINT32 Reserved1 : 4;		//!< EAX 28-31	0
	UINT32 BrandIndex : 8;		//!< EBX 0-7	Brand index
	UINT32 ClflushLineSize : 8;	//!< EBX 8-15	CLFLUSH line size (Value ? 8 = cache line size 
								//				in bytes; used also by CLFLUSHOPT).
	UINT32 MaxApicId : 8;		//!< EBX 16-23	Maximum number of addressable IDs for logical processors in this physical package
	UINT32 InitialApicId : 8;	//!< EBX 24-31	Initial APIC ID
	UINT32 Sse3 : 1;			//!< ECX 0		Prescott New Instructions-SSE3 (PNI)
	UINT32 Pclmulqdq : 1;		//!< ECX 1		PCLMULQDQ support
	UINT32 Dtes64 : 1;			//!< ECX 2		64-bit debug store (edx bit 21)
	UINT32 Monitor : 1;			//!< ECX 3		MONITOR and MWAIT instructions (SSE3)
	UINT32 Dscpl : 1;			//!< ECX 4		CPL qualified debug store
	UINT32 Vmx : 1;				//!< ECX 5		Virtual Machine eXtensions
	UINT32 Smx : 1;				//!< ECX 6		Safer Mode Extensions (LaGrande)
	UINT32 Est : 1;				//!< ECX 7		Enhanced SpeedStep
	UINT32 Tm2 : 1;				//!< ECX 8		Thermal Monitor 2
	UINT32 Ssse3 : 1;			//!< ECX 9		Supplemental SSE3 instructions
	UINT32 Cnxtid : 1;			//!< ECX 10		L1 Context ID
	UINT32 Sdbg : 1;			//!< ECX 11		Silicon Debug interface
	UINT32 Fma : 1;				//!< ECX 12		Fused multiply-add (FMA3)
	UINT32 Cx16 : 1;			//!< ECX 13		CMPXCHG16B instruction
	UINT32 Xtpr : 1;			//!< ECX 14		Can disable sending task priority messages
	UINT32 Pdcm : 1;			//!< ECX 15		Perfmon & debug capability
	UINT32 Reserved2 : 1;		//!< ECX 16		0
	UINT32 Pcid : 1;			//!< ECX 17		Process context identifiers (CR4 bit 17)
	UINT32 Dca : 1;				//!< ECX 18		Direct cache access for DMA writes
	UINT32 Sse41 : 1;			//!< ECX 19		SSE4.1 instructions
	UINT32 Sse42 : 1;			//!< ECX 20		SSE4.2 instructions
	UINT32 X2apic : 1;			//!< ECX 21		x2APIC support
	UINT32 Movbe : 1;			//!< ECX 22		MOVBE instruction (big-endian)
	UINT32 Popcnt : 1;			//!< ECX 23		POPCNT instruction
	UINT32 Tscdeadline : 1;		//!< ECX 24		APIC supports one-shot operation using a TSC deadline value
	UINT32 Aes : 1;				//!< ECX 25		AES instruction set
	UINT32 Xsave : 1;			//!< ECX 26		XSAVE, XRESTOR, XSETBV, XGETBV
	UINT32 Osxsave : 1;			//!< ECX 27		XSAVE enabled by OS
	UINT32 Avx : 1;				//!< ECX 28		Advanced Vector Extensions
	UINT32 F16c : 1;			//!< ECX 29		F16C (half-precision) FP support
	UINT32 Rdrnd : 1;			//!< ECX 30		RDRAND (on-chip random number generator) support
	UINT32 Hypervisor : 1;		//!< ECX 31		Running on a hypervisor
	UINT32 Fpu : 1;				//!< EDX 0		Onboard x87 FPU
	UINT32 Vme : 1;				//!< EDX 1		Virtual 8086 mode extensions (such as VIF, VIP, PIV)
	UINT32 De : 1;				//!< EDX 2		Debugging extensions (CR4 bit 3)
	UINT32 Pse : 1;				//!< EDX 3		Page Size Extension
	UINT32 Tsc : 1;				//!< EDX 4		Time Stamp Counter
	UINT32 Msr : 1;				//!< EDX 5		Model-specific registers
	UINT32 Pae : 1;				//!< EDX 6		Physical Address Extension
	UINT32 Mce : 1;				//!< EDX 7		Machine Check Exception
	UINT32 Cx8 : 1;				//!< EDX 8		CMPXCHG8 (compare-and-swap) instruction
	UINT32 Apic : 1;			//!< EDX 9		Onboard Advanced Programmable Interrupt Controller
	UINT32 Reserved3 : 1;		//!< EDX 10		0
	UINT32 Sep : 1;				//!< EDX 11		SYSENTER and SYSEXIT instructions
	UINT32 Mtrr : 1;			//!< EDX 12		Memory Type Range Registers
	UINT32 Pge : 1;				//!< EDX 13		Page Global Enable bit in CR4
	UINT32 Mca : 1;				//!< EDX 14		Machine check architecture
	UINT32 Cmov : 1;			//!< EDX 15		Conditional move and FCMOV instructions
	UINT32 Pat : 1;				//!< EDX 16		Page Attribute Table
	UINT32 Pse36 : 1;			//!< EDX 17		36-bit page size extension
	UINT32 Psn : 1;				//!< EDX 18		Processor Serial Number
	UINT32 Clfsh : 1;			//!< EDX 19		CLFLUSH instruction (SSE2)
	UINT32 Reserved4 : 1;		//!< EDX 20		0
	UINT32 Ds : 1;				//!< EDX 21		Debug store: save trace of executed jumps
	UINT32 Acpi : 1;			//!< EDX 22		Onboard thermal control MSRs for ACPI
	UINT32 Mmx : 1;				//!< EDX 23		MMX instructions
	UINT32 Fxsr : 1;			//!< EDX 24		FXSAVE, FXRESTOR instructions, CR4 bit 9
	UINT32 Sse : 1;				//!< EDX 25		SSE instructions (a.k.a. Katmai New Instructions)
	UINT32 Sse2 : 1;			//!< EDX 26		SSE2 instructions
	UINT32 Ss : 1;				//!< EDX 27		CPU cache supports self-snoop
	UINT32 Htt : 1;				//!< EDX 28		Hyper-threading
	UINT32 Tm : 1;				//!< EDX 29		Thermal monitor automatically limits temperature
	UINT32 Ia64 : 1;			//!< EDX 30		IA64 processor emulating x86
	UINT32 Pbe : 1;				//!< EDX 31		Pending Break Enable (PBE# pin) wakeup support
} CPUID_BASIC_FEATURES, *PCPUID_BASIC_FEATURES;
C_ASSERT(sizeof(CPUID_REGISTERS) == sizeof(CPUID_BASIC_FEATURES));

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
// https://en.wikipedia.org/wiki/CPUID#EAX=7,_ECX=0:_Extended_Features
typedef struct _CPUID_FEATURES_EX
{
	UINT32 dwMaxExSubFunc;		//!< EAX 0-31	Reports the maximum input value for supported leaf 7 sub-leaves
	UINT32 Fsgbase : 1;			//!< EBX 0		Supports RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE if 1
	UINT32 Ia32TscAdjust : 1;	//!< EBX 1		IA32_TSC_ADJUST MSR is supported if 1
	UINT32 Sgx : 1;				//!< EBX 2		Software Guard Extensions
	UINT32 Bm1 : 1;				//!< EBX 3		Bit Manipulation Instruction Set 1
	UINT32 Hle : 1;				//!< EBX 4		Transactional Synchronization Extensions
	UINT32 Avx2 : 1;			//!< EBX 5		Advanced Vector Extensions 2
	UINT32 FdpExcptnOnly : 1;	//!< EBX 6		FDP_EXCPTN_ONLY. x87 FPU Data Pointer updated
								//				only on x87 exceptions if 1
	UINT32 Smep : 1;			//!< EBX 7		Supervisor-Mode Execution Prevention
	UINT32 Bmi2 : 1;			//!< EBX 8		Bit Manipulation Instruction Set 2
	UINT32 Erms : 1;			//!< EBX 9		Enhanced REP MOVSB/STOSB
	UINT32 Invcpid : 1;			//!< EBX 10		INVPCID instruction
	UINT32 Rtm : 1;				//!< EBX 11		Transactional Synchronization Extensions
	UINT32 Pqm : 1;				//!< EBX 12		Platform Quality of Service Monitoring
	UINT32 DepFpuCsDs : 1;		//!< EBX 13		FPU CS and FPU DS deprecated
	UINT32 Mpx : 1;				//!< EBX 14		Intel MPX (Memory Protection Extensions)
	UINT32 Pqe : 1;				//!< EBX 15		Platform Quality of Service Enforcement
	UINT32 Avx512f : 1;			//!< EBX 16		AVX-512 Foundation
	UINT32 Avx512fdq : 1;		//!< EBX 17		AVX-512 DWORD and QWORD Instructions
	UINT32 Rdseed : 1;			//!< EBX 18		RDSEED instruction
	UINT32 Adx : 1;				//!< EBX 19		Intel ADX (Multi-Precision Add-Carry Instruction Extensions)
	UINT32 Smap : 1;			//!< EBX 20		Supervisor Mode Access Prevention
	UINT32 Avx512ifma : 1;		//!< EBX 21		AVX-512 Integer Fused Multiply-Add Instructions
	UINT32 Pcommit : 1;			//!< EBX 22		PCOMMIT instruction
	UINT32 Clflushopt : 1;		//!< EBX 23		CLFLUSHOPT instruction
	UINT32 Clwb : 1;			//!< EBX 24		CLWB instruction
	UINT32 IntelPt : 1;			//!< EBX 25		Intel Processor Trace
	UINT32 Avx512pf : 1;		//!< EBX 26		AVX-512 Prefetch Instructions
	UINT32 Avx512er : 1;		//!< EBX 27		AVX-512 Exponential and Reciprocal Instructions
	UINT32 Avx512cd : 1;		//!< EBX 28		AVX-512 Conflict Detection Instructions
	UINT32 Sha : 1;				//!< EBX 29		Intel SHA extensions
	UINT32 Avx512bw : 1;		//!< EBX 30		AVX-512 Byte and Word Instructions
	UINT32 Avx512vl : 1;		//!< EBX 31		AVX-512 Vector Length Extensions
	UINT32 Prefetchwt1 : 1;		//!< ECX 0		PREFETCHWT1
	UINT32 Avx512vbmi : 1;		//!< ECX 1		AVX-512 Vector Bit Manipulation Instructions
	UINT32 Umip : 1;			//!< ECX 2		User-mode Instruction Prevention
	UINT32 Pku : 1;				//!< ECX 3		Memory Protection Keys for User-mode pages
	UINT32 Ospke : 1;			//!< ECX 4		PKU enabled by OS
	UINT32 Reserved0 : 1;		//!< ECX 5		0
	UINT32 Avx512vbmi2 : 1;		//!< ECX 6		AVX-512 Vector Bit Manipulation Instructions 2
	UINT32 Reserved1 : 1;		//!< ECX 7		0
	UINT32 Gfni : 1;			//!< ECX 8		Galois Field instructions
	UINT32 Vaes : 1;			//!< ECX 9		AES instruction set (VEX-256/EVEX)
	UINT32 Vpclmulqdq : 1;		//!< ECX 10		CLMUL instruction set (VEX-256/EVEX)
	UINT32 Avx512vnni : 1;		//!< ECX 11		AVX-512 Vector Neural Network Instructions
	UINT32 Avx512bitalg : 1;	//!< ECX 12		AVX-512 BITALG instructions
	UINT32 Reserved2 : 1;		//!< ECX 13		0
	UINT32 Mawau : 8;			//!< ECX 14-21	The value of userspace MPX Address-Width
								//				Adjust used by the BNDLDX and BNDSTX 
								//				Intel MPX instructions in 64 - bit mode
	UINT32 Rdpid : 1;			//!< ECX 22		Read Processor ID
	UINT32 Reserved3 : 7;		//!< ECX 23-29	0
	UINT32 SgxLc : 1;			//!< ECX 30		SGX Launch Configuration
	UINT32 Reserved4 : 1;		//!< ECX 31		0
	UINT32 Reserved5 : 2;		//!< EDX 0-1	0
	UINT32 Avx512vnniw : 1;		//!< EDX 2		AVX-512 4-register Neural Network Instructions
	UINT32 Avx512maps : 1;		//!< EDX 2		AVX-512 4-register Multiply Accumulation Single precision
	UINT32 Reserved6 : 22;		//!< EDX 4-25	0
	UINT32 SpecCtrl : 1;		//!< EDX 26		Speculation Control:
								//				Indirect Branch Restricted Speculation(IBRS) and
								//				Indirect Branch Prediction Barrier(IBPB)
	UINT32 Reserved7 : 5;		//!< EDX 27-31	0
} CPUID_FEATURES_EX, *PCPUID_FEATURES_EX;
C_ASSERT(sizeof(CPUID_REGISTERS) == sizeof(CPUID_FEATURES_EX));

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
// https://en.wikipedia.org/wiki/CPUID#EAX=80000001h:_Extended_Processor_Info_and_Feature_Bits
typedef struct _CPUID_EX_FEATURES
{
	UINT32 Reserved0;			//!< EAX 0-31
	UINT32 Reserved1;			//!< EBX 0-31
	UINT32 LahfLm : 1;			//!< ECX 0		LAHF/SAHF in long mode
	UINT32 CmpLegacy : 1;		//!< ECX 1		Hyper-threading not valid
	UINT32 Svm : 1;				//!< ECX 2		Secure Virtual Machine
	UINT32 ExtApic : 1;			//!< ECX 3		Extended APIC space
	UINT32 Cr8Legacy : 1;		//!< ECX 4		CR8 in 32-bit mode
	UINT32 Abm : 1;				//!< ECX 5		Advanced bit manipulation (LZCNT and POPCNT)
	UINT32 Sse4a : 1;			//!< ECX 6		SSE4a
	UINT32 MisAlignSse : 1;		//!< ECX 7		Misaligned SSE mode
	UINT32 PrefetchNow : 1;		//!< ECX 8		PREFETCH and PREFETCHW instructions
	UINT32 Osvw : 1;			//!< ECX 9		OS Visible Workaround
	UINT32 Ibs : 1;				//!< ECX 10		Instruction Based Sampling
	UINT32 Xop : 1;				//!< ECX 11		XOP instruction set
	UINT32 Skinit : 1;			//!< ECX 12		SKINIT/STGI instructions
	UINT32 Wdt : 1;				//!< ECX 13		Watchdog timer
	UINT32 Reserved2 : 1;		//!< ECX 14		0
	UINT32 Lwp : 1;				//!< ECX 15		Light Weight Profiling
	UINT32 Fma4 : 1;			//!< ECX 16		4 operands fused multiply-add
	UINT32 Tce : 1;				//!< ECX 17		Translation Cache Extension
	UINT32 Reserved3 : 1;		//!< ECX 18		0
	UINT32 NodeIdMsr : 1;		//!< ECX 19		NodeID MSR
	UINT32 Reserved4 : 1;		//!< ECX 20		0
	UINT32 Tbm : 1;				//!< ECX 21		Trailing Bit Manipulation
	UINT32 Topoext : 1;			//!< ECX 22		Topology Extensions
	UINT32 PerfctrCore : 1;		//!< ECX 23		Core performance counter extensions
	UINT32 PerfctrNb : 1;		//!< ECX 24		NB performance counter extensions
	UINT32 Reserved5 : 1;		//!< ECX 25		0
	UINT32 Dbx : 1;				//!< ECX 26		Data breakpoint extensions
	UINT32 Perftsc : 1;			//!< ECX 27		Performance TSC
	UINT32 Pcxi2i : 1;			//!< ECX 28		L2I perf counter extensions
	UINT32 Reserved6 : 3;		//!< ECX 29-31
	UINT32 Fpu : 1;				//!< EDX 0		Onboard x87 FPU
	UINT32 Vme : 1;				//!< EDX 1		Virtual mode extensions (VIF)
	UINT32 De : 1;				//!< EDX 2		Debugging extensions (CR4 bit 3)
	UINT32 Pse : 1;				//!< EDX 3		Page Size Extension
	UINT32 Tsc : 1;				//!< EDX 4		Time Stamp Counter
	UINT32 Msr : 1;				//!< EDX 5		Model-specific registers
	UINT32 Pae : 1;				//!< EDX 6		Physical Address Extension
	UINT32 Mce : 1;				//!< EDX 7		Machine Check Exception
	UINT32 Cx8 : 1;				//!< EDX 8		CMPXCHG8 (compare-and-swap) instruction
	UINT32 Apic : 1;			//!< EDX 9		Onboard Advanced Programmable Interrupt Controller
	UINT32 Reserved7 : 1;		//!< EDX 10		0
	UINT32 Syscall : 1;			//!< EDX 11		SYSCALL and SYSRET instructions
	UINT32 Mtrr : 1;			//!< EDX 12		Memory Type Range Registers
	UINT32 Pge : 1;				//!< EDX 13		Page Global Enable bit in CR4
	UINT32 Mca : 1;				//!< EDX 14		Machine check architecture
	UINT32 Cmov : 1;			//!< EDX 15		Conditional move and FCMOV instructions
	UINT32 Pat : 1;				//!< EDX 16		Page Attribute Table
	UINT32 Pse36 : 1;			//!< EDX 17		36-bit page size extension
	UINT32 Reserved8 : 1;		//!< EDX 18		0
	UINT32 Mp : 1;				//!< EDX 19		Multiprocessor Capable
	UINT32 Nx : 1;				//!< EDX 20		NX bit
	UINT32 Reserved9 : 1;		//!< EDX 21		0
	UINT32 Mmxext : 1;			//!< EDX 22		Extended MMX
	UINT32 Mmx : 1;				//!< EDX 23		MMX instructions
	UINT32 Fxsr : 1;			//!< EDX 24		FXSAVE, FXRSTOR instructions, CR4 bit 9
	UINT32 Fxsropt : 1;			//!< EDX 25		FXSAVE/FXRSTOR optimizations
	UINT32 Pdpe1gb : 1;			//!< EDX 26		1GB pages
	UINT32 Rdtscp : 1;			//!< EDX 27		RDTSCP instruction
	UINT32 ReservedA : 1;		//!< EDX 28		0
	UINT32 Lm : 1;				//!< EDX 29		Long mode
	UINT32 ThreeDNowExt : 1;	//!< EDX 30		Extended 3DNow!
	UINT32 ThreeDNow : 1;		//!< EDX 31		3DNow!
} CPUID_EX_FEATURES, *PCPUID_EX_FEATURES;
C_ASSERT(sizeof(CPUID_REGISTERS) == sizeof(CPUID_EX_FEATURES));

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
typedef struct _CPUID_EX_MAXFUNC
{
	UINT32 dwMaxExFunc; //!< EAX
	UINT32 dwReserved0; //!< EBX
	UINT32 dwReserved1; //!< ECX
	UINT32 dwReserved2; //!< EDX
} CPUID_EX_MAXFUNC, *PCPUID_EX_MAXFUNC;
C_ASSERT(sizeof(CPUID_REGISTERS) == sizeof(CPUID_EX_MAXFUNC));

//! Vol 2A, Table 3-17. Information Returned by CPUID Instruction
typedef struct _CPUID_EX_MAXADDR
{
	UINT32 MaxPhysAddr : 8;		//!< EAX 0-7
	UINT32 MaxLinearAddr : 8;	//!< EAX 8-15
	UINT32 Reserved0 : 16;		//!< EAX 16-31
	UINT32 Reserved1;			//!< EBX
	UINT32 Reserved2;			//!< ECX
	UINT32 Reserved3;			//!< EDX
} CPUID_EX_MAXADDR, *PCPUID_EX_MAXADDR;
C_ASSERT(sizeof(CPUID_REGISTERS) == sizeof(CPUID_EX_MAXADDR));

/**
* Query CPUID for MAXPHYADDR value, which is the maximum number 
* of bits in a physical address
* @return MAXPHYADDR value
*/
UINT8
CPUID_GetMaxPhyAddrBits(
	VOID
);

// Calculate the Max Physical Address mask
#define MAXPHYADDR ((1 << CPUID_GetMaxPhyAddr()) - 1)

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_CPUID_H__ */
