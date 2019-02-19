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
* @file        apic.h
* @section    Advanced Programmable Interrupt Controller (APIC) structures and constants
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
#define APIC_BASE_DEFAULT 0xFEE00000

typedef enum _APIC_REG_OFFSET {
    // 0x0000 - 0x0010 Reserved
    APIC_REG_OFFSET_APICID      = 0x0020, // Local APIC ID Register (Read/Write)
    APIC_REG_OFFSET_VERSION     = 0x0030, // Local APIC Version Register (Read Only)
    // 0x0040 - 0x0070 Reserved
    APIC_REG_OFFSET_TPR         = 0x0080, // Task Priority Register (Read/Write)
    APIC_REG_OFFSET_APR         = 0x0090, // Arbitration Priority Register (Read Only)
    APIC_REG_OFFSET_PPR         = 0x00A0, // Processor Priority Register (Read Only)
    APIC_REG_OFFSET_EOI         = 0x00B0, // EOI Register (Write Only)
    APIC_REG_OFFSET_RRD         = 0x00C0, // Remote Read Register (Read Only)
    APIC_REG_OFFSET_LDR         = 0x00D0, // Logical Destination Register (Read/Write)
    APIC_REG_OFFSET_DFR         = 0x00E0, // Destination Format Register (Read/Write)
    APIC_REG_OFFSET_SVR         = 0x00F0, // Spurious Interrupt Vector Register (Read/Write)
    APIC_REG_OFFSET_ISR0        = 0x0100, // In-Service Register; bits 31:0 (Read Only)
    APIC_REG_OFFSET_ISR1        = 0x0110, // ISR bits 63:32 (Read Only)
    APIC_REG_OFFSET_ISR2        = 0x0120, // ISR bits 95:64 (Read Only)
    APIC_REG_OFFSET_ISR3        = 0x0130, // ISR bits 127:96 (Read Only)
    APIC_REG_OFFSET_ISR4        = 0x0140, // ISR bits 159:128 (Read Only)
    APIC_REG_OFFSET_ISR5        = 0x0150, // ISR bits 191:160 (Read Only)
    APIC_REG_OFFSET_ISR6        = 0x0160, // ISR bits 223:192 (Read Only)
    APIC_REG_OFFSET_ISR7        = 0x0170, // ISR bits 255:224 (Read Only)
    APIC_REG_OFFSET_TMR0        = 0x0180, // Trigger Mode Register; bits 31:0 (Read Only)
    APIC_REG_OFFSET_TMR1        = 0x0190, // TMR bits 63:32 (Read Only)
    APIC_REG_OFFSET_TMR2        = 0x01A0, // TMR bits 95:64 (Read Only)
    APIC_REG_OFFSET_TMR3        = 0x01B0, // TMR bits 127:96 (Read Only)
    APIC_REG_OFFSET_TMR4        = 0x01C0, // TMR bits 159:128 (Read Only)
    APIC_REG_OFFSET_TMR5        = 0x01D0, // TMR bits 191:160 (Read Only)
    APIC_REG_OFFSET_TMR6        = 0x01E0, // TMR bits 223:192 (Read Only)
    APIC_REG_OFFSET_TMR7        = 0x01F0, // TMR bits 255:224 (Read Only)
    APIC_REG_OFFSET_IRR0        = 0x0200, // Interrupt Request Register; 31:0 (Read Only)
    APIC_REG_OFFSET_IRR1        = 0x0210, // IRR bits 63:32    (Read Only)
    APIC_REG_OFFSET_IRR2        = 0x0220, // IRR bits 95:64    (Read Only)
    APIC_REG_OFFSET_IRR3        = 0x0230, // IRR bits 127:96 (Read Only)
    APIC_REG_OFFSET_IRR4        = 0x0240, // IRR bits 159:128 (Read Only)
    APIC_REG_OFFSET_IRR5        = 0x0250, // IRR bits 191:160 (Read Only)
    APIC_REG_OFFSET_IRR6        = 0x0260, // IRR bits 223:192 (Read Only)
    APIC_REG_OFFSET_IRR7        = 0x0270, // IRR bits 255:224 (Read Only)
    APIC_REG_OFFSET_ESR         = 0x0280, // Error Status Register (Read/Write)
    // 0x0290 - 0x02E0 Reserved 
    APIC_REG_OFFSET_LVT_CMCI    = 0x02F0, // LVT CMCI Register (Read/Write)
    APIC_REG_OFFSET_ICR0        = 0x0300, // Interrupt Command Register (Read/Write)
    APIC_REG_OFFSET_ICR1        = 0x0310, // Interrupt Command Register (Read/Write)
    APIC_REG_OFFSET_LVT_TIMER   = 0x0320, // LVT Timer Register (Read/Write)
    APIC_REG_OFFSET_LVT_THERMAL = 0x0330, // LVT Thermal Sensor Register (Read/Write)
    APIC_REG_OFFSET_LVT_PMI     = 0x0340, // LVT Performance Monitoring Counters Register (Read/Write)
    APIC_REG_OFFSET_LVT_LINT0   = 0x0350, // LVT LINT0 Register (Read/Write)
    APIC_REG_OFFSET_LVT_LINT1   = 0x0360, // LVT LINT1 Register (Read/Write)
    APIC_REG_OFFSET_LVT_ERR     = 0x0370, // LVT Error Register (Read/Write)
    APIC_REG_OFFSET_TMICT       = 0x0380, // Initial Count Register (Read/Write)
    APIC_REG_OFFSET_TMCCT       = 0x0390, // Current Count Register (Read Only)
    // 0x03A0 - 0x03D0 Reserved
    APIC_REG_OFFSET_TDCR        = 0x03E0, // Divide Configuration Register (Read/Write)
    // 0x03F0 Reserved
} APIC_REG_OFFSET, *PAPIC_REG_OFFSET;

//! Vol 3B, Table 10-6. Local APIC Register Address Map Supported by x2APIC
// x2APIC registers can also be accessed through MSRs 0x802-0x83F (See msr64.h)
typedef enum _X2APIC_REG_OFFSET {
    X2APIC_REG_OFFSET_APICID        = 0x020, // Local APIC ID register (Read-only)
    X2APIC_REG_OFFSET_VERSION       = 0x030, // Local APIC Version register (Read Only)
    X2APIC_REG_OFFSET_TPR           = 0x080, // Task Priority Register (Read/Write)
    X2APIC_REG_OFFSET_PPR           = 0x0A0, // Processor Priority Register (Read Only)
    X2APIC_REG_OFFSET_EOI           = 0x0B0, // EOI register,Write-only3
                                             // WRMSR of a non-zero value causes #GP(0)
    X2APIC_REG_OFFSET_LDR           = 0x0D0, // Logical Destination Register (Read Only)
                                             // Read/write in xAPIC mode
    X2APIC_REG_OFFSET_SVR           = 0x0F0, // Spurious Interrupt Vector (Read/Write)
    X2APIC_REG_OFFSET_ISR0          = 0x100, // In-Service Register (ISR); bits (Read Only)
    X2APIC_REG_OFFSET_ISR1          = 0x110, // ISR bits 63:32 (Read Only)
    X2APIC_REG_OFFSET_ISR2          = 0x120, // ISR bits 95:64 (Read Only)
    X2APIC_REG_OFFSET_ISR3          = 0x130, // ISR bits 127:96 (Read Only)
    X2APIC_REG_OFFSET_ISR4          = 0x140, // ISR bits 159:128 (Read Only)
    X2APIC_REG_OFFSET_ISR5          = 0x150, // ISR bits 191:160 (Read Only)
    X2APIC_REG_OFFSET_ISR6          = 0x160, // ISR bits 223:192 (Read Only)
    X2APIC_REG_OFFSET_ISR7          = 0x170, // ISR bits 255:224 (Read Only)
    X2APIC_REG_OFFSET_TMR0          = 0x180, // Trigger Mode Register (Read Only)
    X2APIC_REG_OFFSET_TMR1          = 0x190, // TMR bits 63:32 (Read Only)
    X2APIC_REG_OFFSET_TMR2          = 0x1A0, // TMR bits 95:64 (Read Only)
    X2APIC_REG_OFFSET_TMR3          = 0x1B0, // TMR bits 127:96 (Read Only)
    X2APIC_REG_OFFSET_TMR4          = 0x1C0, // TMR bits 159:128 (Read Only)
    X2APIC_REG_OFFSET_TMR5          = 0x1D0, // TMR bits 191:160 (Read Only)
    X2APIC_REG_OFFSET_TMR6          = 0x1E0, // TMR bits 223:192 (Read Only)
    X2APIC_REG_OFFSET_TMR7          = 0x1F0, // TMR bits 255:224 (Read Only)
    X2APIC_REG_OFFSET_IRR0          = 0x200, // Interrupt Request Register (Read Only)
    X2APIC_REG_OFFSET_IRR1          = 0x210, // IRR bits 63:32 (Read Only)
    X2APIC_REG_OFFSET_IRR2          = 0x220, // IRR bits 95:64 (Read Only)
    X2APIC_REG_OFFSET_IRR3          = 0x230, // IRR bits 127:96 (Read Only)
    X2APIC_REG_OFFSET_IRR4          = 0x240, // IRR bits 159:128 (Read Only)
    X2APIC_REG_OFFSET_IRR5          = 0x250, // IRR bits 191:160 (Read Only)
    X2APIC_REG_OFFSET_IRR6          = 0x260, // IRR bits 223:192 (Read Only)
    X2APIC_REG_OFFSET_IRR7          = 0x270, // IRR bits 255:224 (Read Only)
    X2APIC_REG_OFFSET_ESR           = 0x280, // Error Status Register (Read/Write)
                                             // WRMSR of a non-zero value causes #GP(0)
    X2APIC_REG_OFFSET_LVT_CMCI      = 0x2F0, // LVT CMCI register (Read/Write)
    X2APIC_REG_OFFSET_ICR0          = 0x300, // Interrupt Command Register (Read/Write)
    X2APIC_REG_OFFSET_ICR1          = 0x310, // 
    X2APIC_REG_OFFSET_LVT_TIMER     = 0x320, // LVT Timer register (Read/Write)
    X2APIC_REG_OFFSET_LVT_THERMAL   = 0x330, // LVT Thermal Sensor register (Read/Write)
    X2APIC_REG_OFFSET_LVT_PMI       = 0x340, // LVT Performance Monitoring register (Read/Write)
    X2APIC_REG_OFFSET_LVT_LINT0     = 0x350, // LVT LINT0 register (Read/Write)
    X2APIC_REG_OFFSET_LVT_LINT1     = 0x360, // LVT LINT1 register (Read/Write)
    X2APIC_REG_OFFSET_LVT_ERR       = 0x370, // LVT Error register (Read/Write)
    X2APIC_REG_OFFSET_TMICT         = 0x380, // Initial Count register (Read/write)
    X2APIC_REG_OFFSET_TMCCT         = 0x390, // Current Count register (Read-only)
    X2APIC_REG_OFFSET_TDCR          = 0x3E0, // Divide Configuration Register (Read/Write)
} X2APIC_REG_OFFSET, *PX2APIC_REG_OFFSET;

//! Vol 3A, Figure 10-6. Local APIC ID Register
typedef union _APICID_REG {
    // P6 family and Pentium processors
    struct {
        UINT32 Reserved0 : 24;  //!< 0-23
        UINT32 ApicId : 4;      //!< 24-27
        UINT32 Reserved1 : 4;   //!< 28-31
    } p6;
    
    // Pentium 4 processors, Xeon processors, and later processors
    struct {
        UINT32 Reserved2 : 24;  //!< 0-23
        UINT32 ApicId : 8;      //!< 24-31
    } p4;

    UINT32 dwX2ApicId;
} APICID_REG, *PAPICID_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APICID_REG));

//! Vol 3A, Figure 10-7. Local APIC Version Register
typedef union _APIC_VER_REG {
    UINT32 dwValue;
    struct {
        UINT32 Version : 8;                 //!< 0-7    Version numbers of the local APIC
        UINT32 Reserved0 : 8;               //!< 8-15
        UINT32 MaxLvtEntry : 8;             //!< 16-23  Number of LVT entries -1
        UINT32 SuppressEoiBroadcasts : 1;   //!< 24     S/W can inhibit the broadcast of EOI message
        UINT32 Reserved1 : 7;               //!< 25-31
    };
} APIC_VER_REG, *PAPIC_VER_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_VER_REG));

//! Vol 3A, Figure 10-8. Local Vector Table (LVT)
typedef enum _APIC_DELIVERY_MODE {
    APIC_INT_DELIVERY_MODE_FIXED = 0,       // Delivers the interrupt in the vector
    APIC_DELIVERY_MODE_LOWEST_PRIORITY = 1, // Same as fixed but lowest priority
    APIC_INT_DELIVERY_MODE_SMI = 2,         // Delivers an SMI interrupt (vector must be 0)
    // 3 is reserved
    APIC_INT_DELIVERY_MODE_NMI = 4,         // Delivers an NMI interrupt (vector is ignored)
    APIC_INT_DELIVERY_MODE_INIT = 5,        // Delivers an INIT request (vector must be 0)
                                            // Not supported by CMCI, THERMAL and PMI)
    // 6 is reserved
    APIC_INT_DELIVERY_MODE_EXT = 7,         // Respond as if interrupt is external. 
                                            // Not supported by CMCI, THERMAL and PMI.
                                            // Only 1 core may use this at a time.
} APIC_DELIVERY_MODE, *PAPIC_DELIVERY_MODE;

typedef enum _APIC_LVT_TIMER_MODE {
    APIC_LVT_TIMER_MODE_ONESHOT = 0,        // Send one interrupt after countdown
    APIC_LVT_TIMER_MODE_PERIODIC = 1,       // Periodic with countdown as interval
    APIC_LVT_TIMER_MODE_TSC_DEADLINE = 2    // Use value in IA32_TSC_DEADLINE MSR
    // 3 is reserved
} APIC_LVT_TIMER_MODE, *PAPIC_LVT_TIMER_MODE;

// APIC_REG_OFFSET_LVT_TIMER
typedef union _APIC_LVT_TIMER {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 Reserver0 : 1;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Reserved1 : 3;       //!< 13-15
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 TimerMode : 2;       //!< 17-18  See APIC_LVT_TIMER_MODE
        UINT32 Reserved2 : 13;      //!< 19-31
    };
} APIC_LVT_TIMER, *PAPIC_LVT_TIMER;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_TIMER));

// APIC_REG_OFFSET_LVT_CMCI
typedef union _APIC_LVT_CMCI_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 Reserver0 : 1;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Reserved1 : 3;       //!< 13-15
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 Reserved2 : 15;      //!< 17-31
    };
} APIC_LVT_CMCI_REG, *PAPIC_LVT_CMCI_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_CMCI_REG));

// APIC_REG_OFFSET_LVT_LINT0
typedef union _APIC_LVT_LINT0_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 Reserver0 : 1;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Polarity : 1;        //!< 13     0=active high, 1=active low
        UINT32 RemoteIRR : 1;       //!< 14     Only supported for level-triggered interrupts
                                    //          1=servicing interrupt, 0=EOI received
        UINT32 TriggerMode : 1;     //!< 15     0=Edge, 1=Level (only for fixed).
                                    //          NMI, SMI and INIT are always edge sensitive.
                                    //          EXT is always level sensitive.
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 Reserved2 : 15;      //!< 17-31
    };
} APIC_LVT_LINT0_REG, *PAPIC_LVT_LINT0_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_LINT0_REG));

// APIC_REG_OFFSET_LVT_LINT1
typedef union _APIC_LVT_LINT1_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 Reserver0 : 1;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Polarity : 1;        //!< 13     0=active high, 1=active low
        UINT32 RemoteIRR : 1;       //!< 14     Only supported for level-triggered interrupts
                                    //          1=servicing interrupt, 0=EOI received
        UINT32 TriggerMode : 1;     //!< 15     INT1 doesn't support level sensitive for fixed.
                                    //          NMI, SMI and INIT are always edge sensitive.
                                    //          EXT is always level sensitive.
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 Reserved2 : 15;      //!< 17-31
    };
} APIC_LVT_LINT1_REG, *PAPIC_LVT_LINT1_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_LINT1_REG));

// APIC_REG_OFFSET_LVT_ERR
typedef union _APIC_LVT_ERR_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 Reserver0 : 4;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Reserved1 : 3;       //!< 13-15
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 Reserved2 : 15;      //!< 17-31
    };
} APIC_LVT_ERR_REG, *PAPIC_LVT_ERR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_ERR_REG));

// APIC_REG_OFFSET_LVT_PMI
typedef union _APIC_LVT_PMI_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 Reserver0 : 1;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Reserved1 : 3;       //!< 13-15
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 Reserved2 : 15;      //!< 17-31
    };
} APIC_LVT_PMI_REG, *PAPIC_LVT_PMI_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_THERMAL_REG));

// APIC_REG_OFFSET_LVT_THERMAL
typedef union _APIC_LVT_THERMAL_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;          //!< 0-7
        UINT32 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 Reserver0 : 1;       //!< 11
        UINT32 DeliveryStatus : 1;  //!< 12     0=Idle, 1=Pending
        UINT32 Reserved1 : 3;       //!< 13-15
        UINT32 Mask : 1;            //!< 16     0=Not Masked, 1=Masked
        UINT32 Reserved2 : 15;      //!< 17-31
    };
} APIC_LVT_THERMAL_REG, *PAPIC_LVT_THERMAL_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LVT_THERMAL_REG));

//! Vol 3A, Figure 10-9. Error Status Register (ESR)
// APIC_REG_OFFSET_ESR
typedef union _APIC_ESR_REG {
    UINT32 dwValue;
    struct {
        UINT32 ErrorCode : 8;   //!< 0-7
        UINT32 Reserved0 : 24;  //!< 8-31
    };
    struct {
        UINT32 SendChecksumError : 1;   //!< 0  Used only in P6 and Pentium
        UINT32 RecvChecksumError : 1;   //!< 1  Used only in P6 and Pentium
        UINT32 SendAcceptError : 1;     //!< 2  Used only in P6 and Pentium
                                        //      Sent message wasn't accepted by
                                        //      any other APIC
        UINT32 RecvAcceptError : 1;     //!< 3  Used only in P6 and Pentium
                                        //      Received message wasn't accepted
                                        //      by any APIC (including self)
        UINT32 RedirectableIPI : 1;     //!< 4  Used only in Core and Xeon
                                        //      Lowest-priority message was sent
                                        //      but it isn't supported
        UINT32 SendIllegalVector : 1;   //!< 5  Message sent has bad vector
        UINT32 RecvIllegalVector : 1;   //!< 6  Message received has bad vector
        UINT32 IllegalRegAddr : 1;      //!< 7  Reserved on Pentium. Software
                                        //      accessed a reserved xAPIC register
        UINT32 Reserved0 : 24;          //!< 8-31
    };
} APIC_ESR_REG, *PAPIC_ESR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_ESR_REG));

//! Vol 3A, Figure 10-10. Divide Configuration Register
// APIC_REG_OFFSET_TDCR
typedef enum _APIC_TDCR_DIV_VALUE {
    APIC_TDCR_DIV_VALUE_2 = 0,      // Divide by 2
    APIC_TDCR_DIV_VALUE_4 = 1,      // Divide by 4
    APIC_TDCR_DIV_VALUE_8 = 2,      // Divide by 8
    APIC_TDCR_DIV_VALUE_16 = 3,     // Divide by 16
    APIC_TDCR_DIV_VALUE_32 = 4,     // Divide by 32
    APIC_TDCR_DIV_VALUE_64 = 5,     // Divide by 64
    APIC_TDCR_DIV_VALUE_128 = 6,    // Divide by 128
    APIC_TDCR_DIV_VALUE_1 = 7,      // Divide by 1
} APIC_TDCR_DIV_VALUE, *PAPIC_TDCR_DIV_VALUE;

typedef union _APIC_TDCR_REG {
    UINT32 dwValue;
    struct {
        UINT32 DivValue : 4;    //!< 0-3 See APIC_TDCR_DIV_VALUE
        UINT32 Reserved0 : 28;  //!< 4-31
    };
} APIC_TDCR_REG, *PAPIC_TDCR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_TDCR_REG));

//! Vol 3A,Figure 10-12. Interrupt Command Register (ICR)
typedef enum _APIC_ICR_DESTINATION_SHORTHAND {
    APIC_ICR_DESTINATION_SHORTHAND_NONE = 0,            // Send only to destination
    APIC_ICR_DESTINATION_SHORTHAND_SELF = 1,            // Send to self
    APIC_ICR_DESTINATION_SHORTHAND_ALL = 2,             // Send to all
    APIC_ICR_DESTINATION_SHORTHAND_ALL_NOT_SELF = 3,    // Same, excluding self
} APIC_ICR_DESTINATION_SHORTHAND, *PAPIC_ICR_DESTINATION_SHORTHAND;

typedef union _APIC_ICR0_REG {
    UINT32 dwValue;
    struct {
        UINT32 Vector : 8;                  //!< 0-7    The vector number of the interrupt being sent
        UINT32 DeliveryMode : 3;            //!< 8-10   See APIC_DELIVERY_MODE
        UINT32 DestinationMode : 1;         //!< 11     0=Physical, 1=Logical
        UINT32 DeliveryStatus : 1;          //!< 12     0=Idle, 1=Send-Pending
        UINT32 Reserved0 : 1;               //!< 13
        UINT32 Level : 1;                   //!< 14     0=De-assert, 1=Assert
        UINT32 TriggerMode : 1;             //!< 15     0=Edge, 1=Level
        UINT32 Reserved1 : 2;               //!< 16-17
        UINT32 DestinationShortHand : 2;    //!< 18-19  See APIC_ICR_DESTINATION_SHORTHAND
        UINT32 Reserved2 : 12;              //!< 20-31
    };
} APIC_ICR0_REG, *PAPIC_ICR0_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_ICR0_REG));

typedef union _APIC_ICR1_REG {
    UINT32 dwValue;
    struct {
        UINT32 Reserved0 : 24;  //!< 32-55
        UINT32 Destination : 8; //!< 56-63 APIC ID of destination
    };
} APIC_ICR1_REG, *PAPIC_ICR1_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_ICR1_REG));

//! Vol 3A, Figure 10-13. Logical Destination Register(LDR)
typedef union _APIC_LDR_REG {
    UINT32 dwValue;
    struct {
        UINT32 Reserved0 : 24;  //!< 0-23
        UINT32 ApicId : 8;      //!< 24-31
    };
} APIC_LDR_REG, *PAPIC_LDR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_LDR_REG));

//! Vol 3A, Figure 10-14. Destination Format Register (DFR)
typedef enum _APIC_DFR_MODEL {
    APIC_DFR_MODEL_CLUSTER = 0,
    // reserved 1-14
    APIC_DFR_MODEL_FLAT = 15
} APIC_DFR_MODEL, *PAPIC_DFR_MODEL;

typedef union _APIC_DFR_REG {
    UINT32 dwValue;
    struct {
        UINT32 Reserved0 : 28;  //!< 0-27   all bits must be set
        UINT32 Model : 4;       //!< 28-31  See APIC_DFR_MODEL
    };
} APIC_DFR_REG, *PAPIC_DFR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_DFR_REG));

//! Vol 3A, Figure 10-15. Arbitration Priority Register (APR)
typedef union _APIC_APR_REG {
    UINT32 dwValue;
    struct {
        UINT32 SubClass : 4;    //!< 0-3
        UINT32 Class : 4;       //!< 4-7
        UINT32 Reserved0 : 24;  //!< 8-31
    };
} APIC_APR_REG, *PAPIC_APR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_APR_REG));

//! Vol 3A, Figure 10-18. Task-Priority Register (TPR)
// Note that when APIC is enabled, CR8 is used to reflect the APIC TPR
// (see 10.8.6.1 Interaction of Task Priorities between CR8 and APIC)
typedef union _APIC_TPR_REG {
    UINT32 dwValue;
    struct {
        UINT32 SubClass : 4;    //!< 0-3
        UINT32 Class : 4;       //!< 4-7
        UINT32 Reserved0 : 24;  //!< 8-31
    };
} APIC_TPR_REG, *PAPIC_TPR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_TPR_REG));

//! Vol 3A, Figure 10-19. Processor-Priority Register (PPR)
typedef union _APIC_PPR_REG {
    UINT32 dwValue;
    struct {
        UINT32 SubClass : 4;    //!< 0-3
        UINT32 Class : 4;       //!< 4-7
        UINT32 Reserved0 : 24;  //!< 8-31
    };
} APIC_PPR_REG, *PAPIC_PPR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_PPR_REG));

//! Vol 3A, Figure 10-23. Spurious-Interrupt Vector Register (SVR)
typedef union _APIC_SVR_REG {
    UINT32 dwValue;
    struct {
        UINT32 SpuriousVector : 8;          //!< 0-7    Vector number to deliver to processor
        UINT32 EnableApic : 1;              //!< 8      Temporarily enable/disable LAPIC
                                            //          0=LAPIC disabled, 1=LAPIC enabled
        UINT32 FocusProcCheck : 1;          //!< 9      Enables/disable focus processor
                                            //          checking when using lowest 
                                            //          priority delivery mode
                                            //          0=Enabled, 1= Disabled
        UINT32 Reserved0 : 2;               //!< 10-11
        UINT32 SuppressEoiBroadcast : 1;    //!< 12     Enable/disable EOI broadcasts
                                            //          for EOI level-triggered interrupts
                                            //          0=Disabled, 1=Enabled
        UINT32 Reserved1 : 19;              //!< 13-31
    };
} APIC_SVR_REG, *PAPIC_SVR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_SVR_REG));

//! Vol 3A, Figure 10-24. Layout of the MSI Message Address Register
typedef union _APIC_MSI_ADDR_REG {
    UINT32 dwValue;
    struct {
        UINT32 XX : 2;              //!< 0-1    ignored?
        UINT32 DstMode : 1;         //!< 2      0=Physical, 1=Logical
        UINT32 RedirectHint : 1;    //!< 3
        UINT32 Reserved0 : 8;       //!< 4-11
        UINT32 DstId : 8;           //!< 12-19
        UINT32 Fixed : 12;          //!< 20-31  0x0FEE
    };
} APIC_MSI_ADDR_REG, *PAPIC_MSI_ADDR_REG;
C_ASSERT(sizeof(UINT32) == sizeof(APIC_MSI_ADDR_REG));

//! Vol 3A, Figure 10-25. Layout of the MSI Message Data Register
typedef union _APIC_MSI_DATA_REG {
    UINT64 qwValue;
    struct {
        UINT64 Vector : 8;          //!< 0-7
        UINT64 DeliveryMode : 3;    //!< 8-10   See APIC_DELIVERY_MODE
        UINT64 Reserved0 : 3;       //!< 11-13
        UINT64 Level : 1;           //!< 14     0=De-assert, 1=Assert
        UINT64 TriggerMode : 1;     //!< 15     0=Edge, 1=Level
        UINT64 Reserved1 : 48;      //!< 16-63
    };
} APIC_MSI_DATA_REG, *PAPIC_MSI_DATA_REG;
C_ASSERT(sizeof(UINT64) == sizeof(APIC_MSI_DATA_REG));

/**
* Delay execution for the given number of microseconds using APIC timer
* @param dwMicroSeconds - Microseconds to delay
*/
VOID
APIC_delayMicroSeconds(
    INT32 dwMicroSeconds
);

/**
* Delay execution for the given number of nanoseconds using APIC timer
* @param dwNanoSeconds - Nanoseconds to delay
*/
VOID
APIC_delayNanoSeconds(
    INT32 dwNanoSeconds
);

/**
* Send the signals INIT,SIPI,SIPI too all APs from BSP (all cores, except BSP)
* @param cVector - AP will execute at address=(cVector * 0x1000)
* @return TRUE on success, else FALSE
*/
BOOLEAN
APIC_initSipiSipiAllAps(
    UINT8 cVector
);

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_APIC_H__ */
