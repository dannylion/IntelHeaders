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
* @file		apic.c
* @section	Advanced Programmable Interrupt Controller (APIC) 
*/

#include "apic.h"
#include "msr64.h"
#include "intrinsics64.h"

typedef VOID(*APIC_callback_t)(VOID * pvContext);

UINT64
apic_GetBase(
	VOID
)
{
	UINT64 qwApicPhysicalAddr = 0;
	IA32_APIC_BASE tApicBase;
	
	tApicBase.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_APIC_BASE);
	qwApicPhysicalAddr = tApicBase.ApicBase << 12;

	// NOTE: We assume we have a 1:1 mapping of physical to virtual addresses
	return qwApicPhysicalAddr;
}

BOOLEAN
apic_IsApicEnabled(
	VOID
)
{
	IA32_APIC_BASE tApicBase;
	tApicBase.qwValue = ASM64_Rdmsr(MSR_CODE_IA32_APIC_BASE);
	return (	tApicBase.Bsp
			&&	tApicBase.ApicGlobalEnable);
}

// See edk2\EdkCompatibilityPkg\Foundation\Library\EdkIIGlueLib\Library\BaseTimerLibLocalApic\X86TimerLib.c line 161
// TODO: Not tested!
VOID
APIC_DelayMicroSeconds(
	INT32 dwMicroSeconds
)
{
	UINT64 qwApicBase = apic_GetBase();
	PAPIC_TDCR_REG ptTdcr = (PAPIC_TDCR_REG)(qwApicBase + APIC_REG_OFFSET_TDCR);
	INT32 *pdwTmcct = (INT32 *)(qwApicBase + APIC_REG_OFFSET_TMCCT);
	INT64 qwDelayTicks = (((INT64)ptTdcr->Frequency * (INT64)dwMicroSeconds) / 1000000);
	INT64 qwTicks = (*pdwTmcct) - qwDelayTicks;

	// Wait until time out
	while (((*pdwTmcct) - qwTicks) >= 0) {};
}

// TODO: Not tested!
VOID
APIC_DelayNanoSeconds(
	INT32 dwNanoSeconds
)
{
	UINT64 qwApicBase = apic_GetBase();
	PAPIC_TDCR_REG ptTdcr = (PAPIC_TDCR_REG)(qwApicBase + APIC_REG_OFFSET_TDCR);
	INT32 *pdwTmcct = (INT32 *)(qwApicBase + APIC_REG_OFFSET_TMCCT);
	INT64 qwDelayTicks = (((INT64)ptTdcr->Frequency * (INT64)dwNanoSeconds) / 1000000000);
	INT64 qwTicks = (*pdwTmcct) - qwDelayTicks;

	// Wait until time out
	while (((*pdwTmcct) - qwTicks) >= 0) {};
}

// See edk2\UefiCpuPkg\Library\BaseXApicLib\BaseXApicLib.c line 512
// TODO: Not tested!
BOOLEAN
APIC_InitSipiSipiAllAps(
	UINT8 cVector
)
{
	UINT64 qwApicBase = apic_GetBase();
	APIC_ICR0_REG tIcr0;
	PAPIC_ICR0_REG ptIcr0 = (PAPIC_ICR0_REG)(qwApicBase + APIC_REG_OFFSET_ICR0);

	if (!apic_IsApicEnabled())
	{
		return FALSE;
	}

	// Load ICR encoding for broadcast INIT IPI to all APs
	tIcr0.DeliveryMode = APIC_ICR_DELIVERY_MODE_INIT;
	tIcr0.DestinationMode = 0; // Physical
	tIcr0.DeliveryStatus = 0; // Idle
	tIcr0.Level = 1; // Assert
	tIcr0.DestinationShortHand = APIC_ICR_DESTINATION_SHORTHAND_ALL_NOT_SELF;

	// Broadcast INIT IPI to all APs
	ptIcr0->dwValue = tIcr0.dwValue;
	
	// 10-millisecond delay loop (10ms = 10000us)
	APIC_DelayMicroSeconds(10000);

	// Load ICR encoding for broadcast SIPI IP to all APs
	tIcr0.Vector = cVector;
	tIcr0.DeliveryMode = APIC_ICR_DELIVERY_MODE_INIT;
	tIcr0.DestinationMode = 0; // Physical
	tIcr0.DeliveryStatus = 0; // Idle
	tIcr0.Level = 1; // Assert
	tIcr0.DestinationShortHand = APIC_ICR_DESTINATION_SHORTHAND_ALL_NOT_SELF;
	
	// Broadcast first SIPI IPI to all APs
	ptIcr0->dwValue = tIcr0.dwValue;

	// 200-microsecond delay
	APIC_DelayMicroSeconds(200);
	
	// Broadcast second SIPI IPI to all APs
	ptIcr0->dwValue = tIcr0.dwValue;

	return TRUE;
}
