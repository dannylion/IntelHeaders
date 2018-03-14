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
* @file		intrinsics.h
* @section	Define functions that perform specific opcodes in assembly
*/

#ifndef __INTRINSICS_H__
#define __INTRINSICS_H__

#include "ntdatatypes.h"

/**
 * Perform RDMSR opcode
 * @param dwMsrCode - MSR code to read from
 * @return MSR value
 */
extern
__forceinline
UINT64
__stdcall
ASM64_Rdmsr(
	IN const UINT32 dwMsrCode
);

/**
* Perform WRMSR opcode
* @param dwMsrCode - MSR code to write to
* @param qwValue - MSR value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_Wrmsr(
	IN const UINT32 dwMsrCode,
	IN const UINT64 qwValue
);

/**
* Perform CPUID opcode
* @param adwRegs - values of EAX, EBX, ECX, EDX after CPUID
* @param dwFunction - CPUID function id
* @param dwSubFunction - CPUID sub-function/leaf id
*/
extern
__forceinline
VOID
__stdcall
ASM64_Cpuid(
	OUT UINT32 adwRegs[4],
	IN const UINT32 dwFunction,
	IN const UINT32 dwSubFunction
);

/**
* Read CR0 value
* @return CR0 value
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadCr0(
	VOID
);

/**
* Read CR2 value
* @return CR2 value
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadCr2(
	VOID
);

/**
* Read CR3 value
* @return CR3 value
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadCr3(
	VOID
);

/**
* Read CR4 value
* @return CR4 value
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadCr4(
	VOID
);

/**
* Read CR8 value
* @return CR8 value
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadCr8(
	VOID
);

/*
 * Read RFLAGS register
 * @return RFLAGS value
 */
extern
__forceinline
UINT64
__stdcall
ASM64_ReadRflags(
	VOID
);

/*
* Write RFLAGS register
* @param qwValue - RFLAGS value
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteRflags(
	IN const UINT64 qwValue
);

/**
* Perform LGDT opcode (write to GDTR)
* @param pqwValue - GDTR value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_Lgdt(
	IN const PUINT64 pqwValue
);

/**
* Perform SGDT opcode (read from GDTR)
* @param pqwValue - GDTR value read
*/
extern
__forceinline
VOID
__stdcall
ASM64_Sgdt(
	OUT PUINT64 pqwValue
);

/**
* Perform LIDT opcode (write to IDTR)
* @param pqwValue - IDTR value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_Lidt(
	IN const PUINT64 pqwValue
);

/**
* Perform SIDT opcode (read from IDTR)
* @param pqwValue - IDTR value read
*/
extern
__forceinline
VOID
__stdcall
ASM64_Sidt(
	OUT PUINT64 pqwValue
);

/**
* Perform LLDT opcode (write LDTR)
* @param pwValue - LDTR value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_Lldt(
	IN const PUINT16 pwValue
);

/**
* Perform SLDT opcode (read LDTR)
* @return LDTR value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_Sldt(
	VOID
);

/**
* Perform LTR opcode (write TR)
* @param wValue - TR value to write
*/
extern
__forceinline
UINT16
__stdcall
ASM64_Ltr(
	IN const UINT16 wValue
);

/**
* Perform STR opcode (read TR)
* @return TR value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_Str(
	VOID
);

/**
* Write to CR0
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteCr0(
	IN const UINT64 qwValue
);

/**
* Write to CR2
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteCr2(
	IN const UINT64 qwValue
);

/**
* Write to CR3
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteCr3(
	IN const UINT64 qwValue
);

/**
* Write to CR4
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteCr4(
	IN const UINT64 qwValue
);

/**
* Write to CR8
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteCr8(
	IN const UINT64 qwValue
);

/**
* Write to CS selector
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteCS(
	IN const UINT16 wValue
);

/**
* Write to SS selector
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteSS(
	IN const UINT16 wValue
);

/**
* Write to DS selector
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDS(
	IN const UINT16 wValue
);

/**
* Write to ES selector
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteES(
	IN const UINT16 wValue
);

/**
* Write to FS selector
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteFS(
	IN const UINT16 wValue
);

/**
* Write to GS selector
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteGS(
	IN const UINT16 wValue
);

/**
* Read CS selector
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_ReadCS(
	VOID
);

/**
* Read SS selector
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_ReadSS(
	VOID
);

/**
* Read DS selector
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_ReadDS(
	VOID
);

/**
* Read ES selector
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_ReadES(
	VOID
);

/**
* Read FS selector
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_ReadFS(
	VOID
);

/**
* Read GS selector
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_ReadGS(
	VOID
);

/**
* Perform LSL opcode (Load Segment Limit)
* @param wSegmentSelector - segment selector value
* @param pdwSegmentLimit - Segment limit
* @return TRUE on success, else FALSE
*/
extern
__forceinline
BOOLEAN
__stdcall
ASM64_ReadSegmentLimit(
	IN const UINT16 wSegmentSelector,
	OUT PUINT32 pdwSegmentLimit
);

/**
* Read DR0 value
* @return value read
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadDr0(
	VOID
);

/**
* Read DR1 value
* @return value read
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadDr1(
	VOID
);

/**
* Read DR2 value
* @return value read
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadDr2(
	VOID
);

/**
* Read DR3 value
* @return value read
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadDr3(
	VOID
);

/**
* Read DR6 value
* @return value read
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadDr6(
	VOID
);

/**
* Read DR7 value
* @return value read
*/
extern
__forceinline
UINT64
__stdcall
ASM64_ReadDr7(
	VOID
);

/**
* Write to DR0
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDr0(
	IN const UINT64 qwValue
);

/**
* Write to DR1
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDr1(
	IN const UINT64 qwValue
);

/**
* Write to DR2
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDr2(
	IN const UINT64 qwValue
);

/**
* Write to DR3
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDr3(
	IN const UINT64 qwValue
);

/**
* Write to DR6
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDr6(
	IN const UINT64 qwValue
);

/**
* Write to DR7
* @param qwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_WriteDr7(
	IN const UINT64 qwValue
);

/**
* Perform LAR opcode (Load Access Rights Byte)
* @param wSegementSelector - segment selector value
* @return Access Rights of given selector
*/
extern
__forceinline
UINT64
__stdcall
ASM64_Lar(
	IN const UINT16 wSegmentSelector
);

/**
* Read byte from IO port
* @param wIoPort - IO port number
* @return value read
*/
extern
__forceinline
UINT8
__stdcall
ASM64_IoReadByte(
	IN const UINT16 wIoPort
);

/**
* Read word from IO port
* @param wIoPort - IO port number
* @return value read
*/
extern
__forceinline
UINT16
__stdcall
ASM64_IoReadWord(
	IN const UINT16 wIoPort
);

/**
* Read double-word from IO port
* @param wIoPort - IO port number
* @return value read
*/
extern
__forceinline
UINT32
__stdcall
ASM64_IoReadDword(
	IN const UINT16 wIoPort
);

/**
* Write byte to IO port
* @param wIoPort - IO port number
* @param cValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_IoWriteByte(
	IN const UINT8 cValue,
	IN const UINT16 wIoPort
);

/**
* Write word to IO port
* @param wIoPort - IO port number
* @param wValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_IoWriteWord(
	IN const UINT16 wValue,
	IN const UINT16 wIoPort
);

/**
* Write double-word to IO port
* @param wIoPort - IO port number
* @param dwValue - value to write
*/
extern
__forceinline
VOID
__stdcall
ASM64_IoWriteDword(
	IN const UINT32 dwValue,
	IN const UINT16 wIoPort
);

/**
* Perform INVD opcode (Invalidate Internal Caches)
*/
extern
__forceinline
VOID
__stdcall
ASM64_Invd(
	VOID
);

//! Vol 3C, 30.2 CONVENTIONS
typedef enum _VTX_RC
{
	VTX_SUCCESS = 0,
	VTX_FAIL_VALID = 1,
	VTX_FAIL_INVALID = 2,
} VTX_RC, *PVTX_RC;

//! Vol 3C, 30.3 VMX INSTRUCTIONS
// INVEPT types supported by a logical processors are reported in
// IA32_VMX_EPT_VPID_CAP MSR
typedef enum _INVEPT_TYPE
{
	// Invalidates all mappings associated with bits 51:12 of the EPT pointer(EPTP)
	// specified in the INVEPT descriptor.It may invalidate other mappings as well
	INVEPT_TYPE_SINGLE_CONTEXT = 1,

	// Invalidates mappings associated with all EPTPs
	INVEPT_TYPE_GLOBAL = 2,
} INVEPT_TYPE, *PINVEPT_TYPE;

//! Vol 3C, Figure 30-1. INVEPT Descriptor
typedef struct _INVEPT_DESCRIPTOR
{
	UINT64 qwEptPointer;	//!< 0-63
	UINT64 Reserved0;		//!< 64-127
} INVEPT_DESCRIPTOR, *PINVEPT_DESCRIPTOR;

/**
* Perform INVEPT opcode (Invalidate Translations Derived from EPT)
* @param dwInveptType - See INVEPT_TYPE
* @param dwInveptType - See INVEPT_DESCRIPTOR
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Invept(
	IN const INVEPT_TYPE eInveptType,
	IN const PINVEPT_DESCRIPTOR ptInveptDescriptor
);

typedef enum _INVVPID_TYPE
{
	// Invalidates mappings for the linear address and VPID specified in the 
	// INVVPID descriptor.In some cases, it may invalidate mappings for
	// other linear addresses (or other VPIDs) as well
	INVVPID_TYPE_INDIVIDUAL = 0,

	// Invalidates all mappings tagged with the VPID specified in the INVVPID 
	// descriptor.In some cases, it may invalidate mappings for other VPIDs as
	// well
	INVVPID_TYPE_SINGLE_CONTEXT = 1,

	// Invalidates all mappings tagged with all VPIDs except VPID 0000H. 
	// In some cases, it may invalidate translations with VPID 0000H as well
	INVVPID_TYPE_ALL_CONTEXTS = 2,

	// Invalidates all mappings tagged with the VPID specified in the INVVPID 
	// descriptor except global translations.In some cases, it may invalidate
	// global translations(and mappings with other VPIDs) as well
	INVVPID_TYPE_GLOBAL = 3,
} INVVPID_TYPE, *PINVVPID_TYPE;

//! Vol 3C, Figure 30-2. INVVPID Descriptor
typedef struct _INVVPID_DESCRIPTOR
{
	UINT16 wVpid;			//!< 0-15
	UINT16 Reserved0;		//!< 16-31
	UINT32 Reserved1;		//!< 32-63
	UINT64 qwLinearAddress;	//!< 64-127
} INVVPID_DESCRIPTOR, *PINVVPID_DESCRIPTOR;

/**
* Perform INVVPID opcode (Invalidate Translations Based on VPID)
* @param dwInveptType - See INVVPID_TYPE
* @param dwInveptType - See INVVPID_DESCRIPTOR
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Invvpid(
	IN const INVVPID_TYPE eInvVpidType,
	IN const PINVVPID_DESCRIPTOR ptInvVpidDescriptor
);

/**
* Perform VMCALL opcode (Call to VM Monitor). This opcode only causes a VM-Exit
* the parameters, if any, to the "hypercall" are implementation specific
* @param dwHypercallNumber - RCX will hold hypercall number
* @param qwContext - RDX will hold a pointer to a context structure
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmcall(
	IN const UINT32 dwHypercallNumber,
	IN PVOID ptContext
);

/**
* Perform VMCLEAR opcode (Clear VMCS)
* @param pqwVmcsPhysicalAddress - pointer to VMCS physical address
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmclear(
	IN const PUINT64 pqwVmcsPhysicalAddress
);

/**
* Perform VMFUNC opcode (Invoke VM function). Invoke a VM-function from
* non-root mode (from guest).
* @param dwHypercallNumber - number of VM-function
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmfunc(
	IN const UINT32 dwVmFuncNumber
);

/**
* Perform VMLAUNCH opcode
* @return	On success, this function will not return but "jump" to
*			VMCS_FIELD_GUEST_RIP, otherwise see VTX_RC
*/
extern
__forceinline
// DECLSPEC_NORETURN
VTX_RC
__stdcall
ASM64_Vmlaunch(
	VOID
);

/**
* Perform VMRESUME opcode
* @return	On success, this function will not return but "jump" to
*			VMCS_FIELD_GUEST_RIP, otherwise see VTX_RC
*/
extern
__forceinline
// DECLSPEC_NORETURN
VTX_RC
__stdcall
ASM64_Vmresume(
	VOID
);

/**
* Perform VMPTRLD opcode (Load VMCS current pointer)
* @param pqwVmcsPhysicalAddress - pointer to VMCS physical address
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmptrld(
	IN const PUINT64 pqwVmcsPhysicalAddress
);

/**
* Perform VMPTRST opcode (Store VMCS current pointer)
* @param pqwVmcsPhysicalAddress - pointer to VMCS physical address
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmptrst(
	OUT PUINT64 pqwVmcsPhysicalAddress
);

/**
* Perform VMREAD opcode (Read field from current VMCS)
* @param ulVmcsField - VMCS field encoding
* @param pulValue - VMCS field value
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmread(
	IN const ULONG_PTR ulVmcsField,
	OUT PULONG_PTR pulValue
);

__forceinline
VTX_RC
__stdcall
ASM64_Vmread16(
	IN const ULONG_PTR ulVmcsField,
	OUT PUINT16 pwValue
)
{
	VTX_RC eRc = VTX_FAIL_INVALID;
	UINT64 qwValue = 0;

	if (NULL == pwValue)
	{
		return eRc;
	}

	eRc = ASM64_Vmread(ulVmcsField, &qwValue);
	*pwValue = (UINT16)qwValue;
	return eRc;
}

__forceinline
VTX_RC
__stdcall
ASM64_Vmread32(
	IN const ULONG_PTR ulVmcsField,
	OUT PUINT32 pdwValue
)
{
	VTX_RC eRc = VTX_FAIL_INVALID;
	UINT64 qwValue = 0;

	if (NULL == pdwValue)
	{
		return eRc;
	}

	eRc = ASM64_Vmread(ulVmcsField, &qwValue);
	*pdwValue = (UINT32)qwValue;
	return eRc;
}

__forceinline
VTX_RC
__stdcall
ASM64_Vmread64(
	IN const ULONG_PTR ulVmcsField,
	OUT PUINT64 pqwValue
)
{
	return ASM64_Vmread(ulVmcsField, (PULONG_PTR)pqwValue);
}

/**
* Perform VMWRITE opcode (Write to a field of current VMCS)
* @param ulVmcsField - VMCS field encoding
* @param ulValue - VMCS field value
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmwrite(
	IN const ULONG_PTR ulVmcsField,
	IN const ULONG_PTR ulValue
);

__forceinline
VTX_RC
__stdcall
ASM64_Vmwrite16(
	IN const ULONG_PTR ulVmcsField,
	IN const UINT16 wValue
)
{
	return ASM64_Vmwrite(ulVmcsField, (ULONG_PTR)wValue);
}

__forceinline
VTX_RC
__stdcall
ASM64_Vmwrite32(
	IN const ULONG_PTR ulVmcsField,
	IN const UINT32 dwValue
)
{
	return ASM64_Vmwrite(ulVmcsField, (ULONG_PTR)dwValue);
}

__forceinline
VTX_RC
__stdcall
ASM64_Vmwrite64(
	IN const ULONG_PTR ulVmcsField,
	IN const UINT64 qwValue
)
{
	return ASM64_Vmwrite(ulVmcsField, (ULONG_PTR)qwValue);
}

/**
* Perform VMXOFF opcode (Leave VMX Operation)
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmxoff(
	VOID
);

/**
* Perform VMXON opcode (Enter VMX Operation)
* @param pqwVmxonRegionPhysicalAddress - physical address of VMXON region
* @return See VTX_RC
*/
extern
__forceinline
VTX_RC
__stdcall
ASM64_Vmxon(
	IN const PUINT64 pqwVmxonRegionPhysicalAddress
);

/**
* Save values of all GP registers and segment selectors, and set RIP & RSP to
* return address of this function.
* @param ptContext - saved registers structure
*/
extern
VOID
__stdcall
ASM64_CaptureContext(
	OUT PCONTEXT ptContext
);

/**
* Restore values of all GP registers, segment selectors, RIP & RSP from context.
* On success, this function will not return but "jump" to ptContext->Rip
* @param ptContext - registers to restore
*/
extern
// DECLSPEC_NORETURN
VOID
__cdecl
ASM64_RestoreContext(
	IN const PCONTEXT ptContext
);

/**
* Restore values of all GP registers, and perform VMRESUME opcode.
* On success, this function will not return but "jump" to VMCS_FIELD_GUEST_RIP
* @param ptContext - registers to restore
* @return See VTX_RC
*/
extern
// DECLSPEC_NORETURN
VTX_RC
__cdecl
ASM64_RestoreContextAndVmresume(
	IN const PCONTEXT ptContext
);

#endif /* __INTRINSICS_H__ */
