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
* @file        msr64.h
* @section    Define all Intel MSR codes and structures for x64
*/

#ifndef __INTEL_MSR64_H__
#define __INTEL_MSR64_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning(disable : 4214)
#pragma warning(disable : 4201)
#pragma pack(push, 1)

//! Vol 3A, Table 35-2. IA-32 Architectural MSRs
//! IA32_BD_PROCHOT https://larry1301.wordpress.com/2015/12/14/macbook-cpu-throttling-motherboard-thermal-sensor-and-bd-prochot-msr/
typedef enum _MSR_CODE
{
    MSR_CODE_IA32_P5_MC_ADDR = 0,
    MSR_CODE_IA32_P5_MC_TYPE = 1,
    MSR_CODE_IA32_MONITOR_FILTER_SIZE = 6,
    MSR_CODE_IA32_TIME_STAMP_COUNTER = 0x10,
    MSR_CODE_IA32_PLATFORM_ID = 0x17,
    MSR_CODE_IA32_APIC_BASE = 0x1B,
    MSR_CODE_IA32_FEATURE_CONTROL = 0x3A,
    MSR_CODE_IA32_TSC_ADJUST = 0x3B,
    MSR_CODE_IA32_BIOS_UPDT_TRIG = 0x79,
    MSR_CODE_IA32_BIOS_SIGN_ID = 0x8B,
    MSR_CODE_IA32_SMM_MONITOR_CTL = 0x9B,
    MSR_CODE_IA32_SMBASE = 0x9E,
    MSR_CODE_IA32_PMC0 = 0xC1,
    MSR_CODE_IA32_PMC1 = 0xC2,
    MSR_CODE_IA32_PMC2 = 0xC3,
    MSR_CODE_IA32_PMC3 = 0xC4,
    MSR_CODE_IA32_PMC4 = 0xC5,
    MSR_CODE_IA32_PMC5 = 0xC6,
    MSR_CODE_IA32_PMC6 = 0xC7,
    MSR_CODE_IA32_PMC7 = 0xC8,
    MSR_CODE_IA32_MPERF = 0xE7,
    MSR_CODE_IA32_APERF = 0xE8,
    MSR_CODE_IA32_MTRRCAP = 0xFE,
    MSR_CODE_IA32_SYSENTER_CS = 0x174,
    MSR_CODE_IA32_SYSENTER_ESP = 0x175,
    MSR_CODE_IA32_SYSENTER_EIP = 0x176,
    MSR_CODE_IA32_MCG_CAP = 0x179,
    MSR_CODE_IA32_MCG_STATUS = 0x17A,
    MSR_CODE_IA32_MCG_CTL = 0x17B,
    // 0x180-0x185 Reserved
    MSR_CODE_IA32_PERFEVTSEL0 = 0x186,
    MSR_CODE_IA32_PERFEVTSEL1 = 0x187,
    MSR_CODE_IA32_PERFEVTSEL2 = 0x188,
    MSR_CODE_IA32_PERFEVTSEL3 = 0x189,
    // 0x18A-0x197 Reserved
    MSR_CODE_IA32_PERF_STATUS = 0x198,
    MSR_CODE_IA32_PERF_CTL = 0x199,
    MSR_CODE_IA32_CLOCK_MODULATION = 0x19A,
    MSR_CODE_IA32_THERM_INTERRUPT = 0x19B,
    MSR_CODE_IA32_THERM_STATUS = 0x19C,
    MSR_CODE_IA32_MISC_ENABLE = 0x1A0,
    MSR_CODE_IA32_ENERGY_PERF_BIAS = 0x1B0,
    MSR_CODE_IA32_PACKAGE_THERM_STATUS = 0x1B1,
    MSR_CODE_IA32_PACKAGE_THERM_INTERRUPT = 0x1B2,
    MSR_CODE_IA32_DEBUGCTL = 0x1D9,
    MSR_CODE_IA32_SMRR_PHYSBASE = 0x1F2,
    MSR_CODE_IA32_SMRR_PHYSMASK = 0x1F3,
    MSR_CODE_IA32_PLATFORM_DCA_CAP = 0x1F8,
    MSR_CODE_IA32_CPU_DCA_CAP = 0x1F9,
    MSR_CODE_IA32_DCA_0_CAP = 0x1FA,
    MSR_CODE_IA32_BD_PROCHOT = 0x1FC,
    MSR_CODE_IA32_MTRR_PHYSBASE0 = 0x200,
    MSR_CODE_IA32_MTRR_PHYSMASK0 = 0x201,
    MSR_CODE_IA32_MTRR_PHYSBASE1 = 0x202,
    MSR_CODE_IA32_MTRR_PHYSMASK1 = 0x203,
    MSR_CODE_IA32_MTRR_PHYSBASE2 = 0x204,
    MSR_CODE_IA32_MTRR_PHYSMASK2 = 0x205,
    MSR_CODE_IA32_MTRR_PHYSBASE3 = 0x206,
    MSR_CODE_IA32_MTRR_PHYSMASK3 = 0x207,
    MSR_CODE_IA32_MTRR_PHYSBASE4 = 0x208,
    MSR_CODE_IA32_MTRR_PHYSMASK4 = 0x209,
    MSR_CODE_IA32_MTRR_PHYSBASE5 = 0x20A,
    MSR_CODE_IA32_MTRR_PHYSMASK5 = 0x20B,
    MSR_CODE_IA32_MTRR_PHYSBASE6 = 0x20C,
    MSR_CODE_IA32_MTRR_PHYSMASK6 = 0x20D,
    MSR_CODE_IA32_MTRR_PHYSBASE7 = 0x20E,
    MSR_CODE_IA32_MTRR_PHYSMASK7 = 0x20F,
    MSR_CODE_IA32_MTRR_PHYSBASE8 = 0x210,
    MSR_CODE_IA32_MTRR_PHYSMASK8 = 0x211,
    MSR_CODE_IA32_MTRR_PHYSBASE9 = 0x212,
    MSR_CODE_IA32_MTRR_PHYSMASK9 = 0x213,
    MSR_CODE_IA32_MTRR_FIX64K_00000 = 0x250,
    MSR_CODE_IA32_MTRR_FIX16K_80000 = 0x258,
    MSR_CODE_IA32_MTRR_FIX16K_A0000 = 0x259,
    MSR_CODE_IA32_MTRR_FIX4K_C0000 = 0x268,
    MSR_CODE_IA32_MTRR_FIX4K_C8000 = 0x269,
    MSR_CODE_IA32_MTRR_FIX4K_D0000 = 0x26A,
    MSR_CODE_IA32_MTRR_FIX4K_D8000 = 0x26B,
    MSR_CODE_IA32_MTRR_FIX4K_E0000 = 0x26C,
    MSR_CODE_IA32_MTRR_FIX4K_E8000 = 0x26D,
    MSR_CODE_IA32_MTRR_FIX4K_F0000 = 0x26E,
    MSR_CODE_IA32_MTRR_FIX4K_F8000 = 0x26F,
    MSR_CODE_IA32_PAT = 0x277,
    MSR_CODE_IA32_MC0_CTL2 = 0x280,
    MSR_CODE_IA32_MC1_CTL2 = 0x281,
    MSR_CODE_IA32_MC2_CTL2 = 0x282,
    MSR_CODE_IA32_MC3_CTL2 = 0x283,
    MSR_CODE_IA32_MC4_CTL2 = 0x284,
    MSR_CODE_IA32_MC5_CTL2 = 0x285,
    MSR_CODE_IA32_MC6_CTL2 = 0x286,
    MSR_CODE_IA32_MC7_CTL2 = 0x287,
    MSR_CODE_IA32_MC8_CTL2 = 0x288,
    MSR_CODE_IA32_MC9_CTL2 = 0x289,
    MSR_CODE_IA32_MC10_CTL2 = 0x28A,
    MSR_CODE_IA32_MC11_CTL2 = 0x28B,
    MSR_CODE_IA32_MC12_CTL2 = 0x28C,
    MSR_CODE_IA32_MC13_CTL2 = 0x28D,
    MSR_CODE_IA32_MC14_CTL2 = 0x28E,
    MSR_CODE_IA32_MC15_CTL2 = 0x28F,
    MSR_CODE_IA32_MC16_CTL2 = 0x290,
    MSR_CODE_IA32_MC17_CTL2 = 0x291,
    MSR_CODE_IA32_MC18_CTL2 = 0x292,
    MSR_CODE_IA32_MC19_CTL2 = 0x293,
    MSR_CODE_IA32_MC20_CTL2 = 0x294,
    MSR_CODE_IA32_MC21_CTL2 = 0x295,
    MSR_CODE_IA32_MC22_CTL2 = 0x296,
    MSR_CODE_IA32_MC23_CTL2 = 0x297,
    MSR_CODE_IA32_MC24_CTL2 = 0x298,
    MSR_CODE_IA32_MC25_CTL2 = 0x299,
    MSR_CODE_IA32_MC26_CTL2 = 0x29A,
    MSR_CODE_IA32_MC27_CTL2 = 0x29B,
    MSR_CODE_IA32_MC28_CTL2 = 0x29C,
    MSR_CODE_IA32_MC29_CTL2 = 0x29D,
    MSR_CODE_IA32_MC30_CTL2 = 0x29E,
    MSR_CODE_IA32_MC31_CTL2 = 0x29F,
    MSR_CODE_IA32_MTRR_DEF_TYPE = 0x2FF,
    MSR_CODE_IA32_FIXED_CTR0 = 0x309,
    MSR_CODE_IA32_FIXED_CTR1 = 0x30A,
    MSR_CODE_IA32_FIXED_CTR2 = 0x30B,
    MSR_CODE_IA32_PERF_CAPABILITIES = 0x345,
    MSR_CODE_IA32_FIXED_CTR_CTRL = 0x38D,
    MSR_CODE_IA32_PERF_GLOBAL_STATUS = 0x38E,
    MSR_CODE_IA32_PERF_GLOBAL_CTRL = 0x38F,
    MSR_CODE_IA32_PERF_GLOBAL_OVF_CTRL = 0x390,
    MSR_CODE_IA32_PERF_GLOBAL_STATUS_RESET = 0x390,
    MSR_CODE_IA32_PERF_GLOBAL_STATUS_SET = 0x391,
    MSR_CODE_IA32_PERF_GLOBAL_INUSE = 0x392,
    MSR_CODE_IA32_PEBS_ENABLE = 0x3F1,
    MSR_CODE_IA32_MC0_CTL = 0x400,
    MSR_CODE_IA32_MC0_STATUS = 0x401,
    MSR_CODE_IA32_MC0_ADDR = 0x402,
    MSR_CODE_IA32_MC0_MISC = 0x403,
    MSR_CODE_IA32_MC1_CTL = 0x404,
    MSR_CODE_IA32_MC1_STATUS = 0x405,
    MSR_CODE_IA32_MC1_ADDR = 0x406,
    MSR_CODE_IA32_MC1_MISC = 0x407,
    MSR_CODE_IA32_MC2_CTL = 0x408,
    MSR_CODE_IA32_MC2_STATUS = 0x409,
    MSR_CODE_IA32_MC2_ADDR = 0x40A,
    MSR_CODE_IA32_MC2_MISC = 0x40B,
    MSR_CODE_IA32_MC3_CTL = 0x40C,
    MSR_CODE_IA32_MC3_STATUS = 0x40D,
    MSR_CODE_IA32_MC3_ADDR = 0x40E,
    MSR_CODE_IA32_MC3_MISC = 0x40F,
    MSR_CODE_IA32_MC4_CTL = 0x410,
    MSR_CODE_IA32_MC4_STATUS = 0x411,
    MSR_CODE_IA32_MC4_ADDR = 0x412,
    MSR_CODE_IA32_MC4_MISC = 0x413,
    MSR_CODE_IA32_MC5_CTL = 0x414,
    MSR_CODE_IA32_MC5_STATUS = 0x415,
    MSR_CODE_IA32_MC5_ADDR = 0x416,
    MSR_CODE_IA32_MC5_MISC = 0x417,
    MSR_CODE_IA32_MC6_CTL = 0x418,
    MSR_CODE_IA32_MC6_STATUS = 0x419,
    MSR_CODE_IA32_MC6_ADDR = 0x41A,
    MSR_CODE_IA32_MC6_MISC = 0x41B,
    MSR_CODE_IA32_MC7_CTL = 0x41C,
    MSR_CODE_IA32_MC7_STATUS = 0x41D,
    MSR_CODE_IA32_MC7_ADDR = 0x41E,
    MSR_CODE_IA32_MC7_MISC = 0x41F,
    MSR_CODE_IA32_MC8_CTL = 0x420,
    MSR_CODE_IA32_MC8_STATUS = 0x421,
    MSR_CODE_IA32_MC8_ADDR = 0x422,
    MSR_CODE_IA32_MC8_MISC = 0x423,
    MSR_CODE_IA32_MC9_CTL = 0x424,
    MSR_CODE_IA32_MC9_STATUS = 0x425,
    MSR_CODE_IA32_MC9_ADDR = 0x426,
    MSR_CODE_IA32_MC9_MISC = 0x427,
    MSR_CODE_IA32_MC10_CTL = 0x428,
    MSR_CODE_IA32_MC10_STATUS = 0x429,
    MSR_CODE_IA32_MC10_ADDR = 0x42A,
    MSR_CODE_IA32_MC10_MISC = 0x42B,
    MSR_CODE_IA32_MC11_CTL = 0x42C,
    MSR_CODE_IA32_MC11_STATUS = 0x42D,
    MSR_CODE_IA32_MC11_ADDR = 0x42E,
    MSR_CODE_IA32_MC11_MISC = 0x42F,
    MSR_CODE_IA32_MC12_CTL = 0x430,
    MSR_CODE_IA32_MC12_STATUS = 0x431,
    MSR_CODE_IA32_MC12_ADDR = 0x432,
    MSR_CODE_IA32_MC12_MISC = 0x433,
    MSR_CODE_IA32_MC13_CTL = 0x434,
    MSR_CODE_IA32_MC13_STATUS = 0x435,
    MSR_CODE_IA32_MC13_ADDR = 0x436,
    MSR_CODE_IA32_MC13_MISC = 0x437,
    MSR_CODE_IA32_MC14_CTL = 0x438,
    MSR_CODE_IA32_MC14_STATUS = 0x439,
    MSR_CODE_IA32_MC14_ADDR = 0x43A,
    MSR_CODE_IA32_MC14_MISC = 0x43B,
    MSR_CODE_IA32_MC15_CTL = 0x43C,
    MSR_CODE_IA32_MC15_STATUS = 0x43D,
    MSR_CODE_IA32_MC15_ADDR = 0x43E,
    MSR_CODE_IA32_MC15_MISC = 0x43F,
    MSR_CODE_IA32_MC16_CTL = 0x440,
    MSR_CODE_IA32_MC16_STATUS = 0x441,
    MSR_CODE_IA32_MC16_ADDR = 0x442,
    MSR_CODE_IA32_MC16_MISC = 0x443,
    MSR_CODE_IA32_MC17_CTL = 0x444,
    MSR_CODE_IA32_MC17_STATUS = 0x445,
    MSR_CODE_IA32_MC17_ADDR = 0x446,
    MSR_CODE_IA32_MC17_MISC = 0x447,
    MSR_CODE_IA32_MC18_CTL = 0x448,
    MSR_CODE_IA32_MC18_STATUS = 0x449,
    MSR_CODE_IA32_MC18_ADDR = 0x44A,
    MSR_CODE_IA32_MC18_MISC = 0x44B,
    MSR_CODE_IA32_MC19_CTL = 0x44C,
    MSR_CODE_IA32_MC19_STATUS = 0x44D,
    MSR_CODE_IA32_MC19_ADDR = 0x44E,
    MSR_CODE_IA32_MC19_MISC = 0x44F,
    MSR_CODE_IA32_MC20_CTL = 0x450,
    MSR_CODE_IA32_MC20_STATUS = 0x451,
    MSR_CODE_IA32_MC20_ADDR = 0x452,
    MSR_CODE_IA32_MC20_MISC = 0x453,
    MSR_CODE_IA32_MC21_CTL = 0x454,
    MSR_CODE_IA32_MC21_STATUS = 0x455,
    MSR_CODE_IA32_MC21_ADDR = 0x456,
    MSR_CODE_IA32_MC21_MISC = 0x457,
    MSR_CODE_IA32_MC22_CTL = 0x458,
    MSR_CODE_IA32_MC22_STATUS = 0x459,
    MSR_CODE_IA32_MC22_ADDR = 0x45A,
    MSR_CODE_IA32_MC22_MISC = 0x45B,
    MSR_CODE_IA32_MC23_CTL = 0x45C,
    MSR_CODE_IA32_MC23_STATUS = 0x45D,
    MSR_CODE_IA32_MC23_ADDR = 0x45E,
    MSR_CODE_IA32_MC23_MISC = 0x45F,
    MSR_CODE_IA32_MC24_CTL = 0x460,
    MSR_CODE_IA32_MC24_STATUS = 0x461,
    MSR_CODE_IA32_MC24_ADDR = 0x462,
    MSR_CODE_IA32_MC24_MISC = 0x463,
    MSR_CODE_IA32_MC25_CTL = 0x464,
    MSR_CODE_IA32_MC25_STATUS = 0x465,
    MSR_CODE_IA32_MC25_ADDR = 0x466,
    MSR_CODE_IA32_MC25_MISC = 0x467,
    MSR_CODE_IA32_MC26_CTL = 0x468,
    MSR_CODE_IA32_MC26_STATUS = 0x469,
    MSR_CODE_IA32_MC26_ADDR = 0x46A,
    MSR_CODE_IA32_MC26_MISC = 0x46B,
    MSR_CODE_IA32_MC27_CTL = 0x46C,
    MSR_CODE_IA32_MC27_STATUS = 0x46D,
    MSR_CODE_IA32_MC27_ADDR = 0x46E,
    MSR_CODE_IA32_MC27_MISC = 0x46F,
    MSR_CODE_IA32_MC28_CTL = 0x470,
    MSR_CODE_IA32_MC28_STATUS = 0x471,
    MSR_CODE_IA32_MC28_ADDR = 0x472,
    MSR_CODE_IA32_MC28_MISC = 0x473,
    MSR_CODE_IA32_VMX_BASIC = 0x480,
    MSR_CODE_IA32_VMX_PINBASED_CTLS = 0x481,
    MSR_CODE_IA32_VMX_PROCBASED_CTLS = 0x482,
    MSR_CODE_IA32_VMX_EXIT_CTLS = 0x483,
    MSR_CODE_IA32_VMX_ENTRY_CTLS = 0x484,
    MSR_CODE_IA32_VMX_MISC = 0x485,
    MSR_CODE_IA32_VMX_CR0_FIXED0 = 0x486,
    MSR_CODE_IA32_VMX_CR0_FIXED1 = 0x487,
    MSR_CODE_IA32_VMX_CR4_FIXED0 = 0x488,
    MSR_CODE_IA32_VMX_CR4_FIXED1 = 0x489,
    MSR_CODE_IA32_VMX_VMCS_ENUM = 0x48A,
    MSR_CODE_IA32_VMX_PROCBASED_CTLS2 = 0x48B,
    MSR_CODE_IA32_VMX_EPT_VPID_CAP = 0x48C,
    MSR_CODE_IA32_VMX_TRUE_PINBASED_CTLS = 0x48D,
    MSR_CODE_IA32_VMX_TRUE_PROCBASED_CTLS = 0x48E,
    MSR_CODE_IA32_VMX_TRUE_EXIT_CTLS = 0x48F,
    MSR_CODE_IA32_VMX_TRUE_ENTRY_CTLS = 0x490,
    MSR_CODE_IA32_VMX_VMFUNC = 0x491,
    MSR_CODE_IA32_A_PMC0 = 0x4C1,
    MSR_CODE_IA32_A_PMC1 = 0x4C2,
    MSR_CODE_IA32_A_PMC2 = 0x4C3,
    MSR_CODE_IA32_A_PMC3 = 0x4C4,
    MSR_CODE_IA32_A_PMC4 = 0x4C5,
    MSR_CODE_IA32_A_PMC5 = 0x4C6,
    MSR_CODE_IA32_A_PMC6 = 0x4C7,
    MSR_CODE_IA32_A_PMC7 = 0x4C8,
    MSR_CODE_IA32_MCG_EXT_CTL = 0x4D0,
    MSR_CODE_IA32_SGX_SVN_STATUS = 0x500,
    MSR_CODE_IA32_RTIT_OUTPUT_BASE = 0x560,
    MSR_CODE_IA32_RTIT_OUTPUT_MASK_PTRS = 0x561,
    MSR_CODE_IA32_RTIT_CTL = 0x570,
    MSR_CODE_IA32_RTIT_STATUS = 0x571,
    MSR_CODE_IA32_RTIT_CR3_MATCH = 0x572,
    MSR_CODE_IA32_RTIT_ADDR0_A = 0x580,
    MSR_CODE_IA32_RTIT_ADDR0_B = 0x581,
    MSR_CODE_IA32_RTIT_ADDR1_A = 0x582,
    MSR_CODE_IA32_RTIT_ADDR1_B = 0x583,
    MSR_CODE_IA32_RTIT_ADDR2_A = 0x584,
    MSR_CODE_IA32_RTIT_ADDR2_B = 0x585,
    MSR_CODE_IA32_RTIT_ADDR3_A = 0x586,
    MSR_CODE_IA32_RTIT_ADDR3_B = 0x587,
    MSR_CODE_IA32_DS_AREA = 0x600,
    MSR_CODE_IA32_TSC_DEADLINE = 0x6E0,
    MSR_CODE_IA32_PM_ENABLE = 0x770,
    MSR_CODE_IA32_HWP_CAPABILITIES = 0x771,
    MSR_CODE_IA32_HWP_REQUEST_PKG = 0x772,
    MSR_CODE_IA32_HWP_INTERRUPT = 0x773,
    MSR_CODE_IA32_HWP_REQUEST = 0x774,
    MSR_CODE_IA32_HWP_STATUS = 0x777,
    MSR_CODE_IA32_X2APIC_APICID = 0x802,
    MSR_CODE_IA32_X2APIC_VERSION = 0x803,
    MSR_CODE_IA32_X2APIC_TPR = 0x808,
    MSR_CODE_IA32_X2APIC_PPR = 0x80A,
    MSR_CODE_IA32_X2APIC_EOI = 0x80B,
    MSR_CODE_IA32_X2APIC_LDR = 0x80D,
    MSR_CODE_IA32_X2APIC_SIVR = 0x80F,
    MSR_CODE_IA32_X2APIC_ISR0 = 0x810,
    MSR_CODE_IA32_X2APIC_ISR1 = 0x811,
    MSR_CODE_IA32_X2APIC_ISR2 = 0x812,
    MSR_CODE_IA32_X2APIC_ISR3 = 0x813,
    MSR_CODE_IA32_X2APIC_ISR4 = 0x814,
    MSR_CODE_IA32_X2APIC_ISR5 = 0x815,
    MSR_CODE_IA32_X2APIC_ISR6 = 0x816,
    MSR_CODE_IA32_X2APIC_ISR7 = 0x817,
    MSR_CODE_IA32_X2APIC_TMR0 = 0x818,
    MSR_CODE_IA32_X2APIC_TMR1 = 0x819,
    MSR_CODE_IA32_X2APIC_TMR2 = 0x81A,
    MSR_CODE_IA32_X2APIC_TMR3 = 0x81B,
    MSR_CODE_IA32_X2APIC_TMR4 = 0x81C,
    MSR_CODE_IA32_X2APIC_TMR5 = 0x81D,
    MSR_CODE_IA32_X2APIC_TMR6 = 0x81E,
    MSR_CODE_IA32_X2APIC_TMR7 = 0x81F,
    MSR_CODE_IA32_X2APIC_IRR0 = 0x820,
    MSR_CODE_IA32_X2APIC_IRR1 = 0x821,
    MSR_CODE_IA32_X2APIC_IRR2 = 0x822,
    MSR_CODE_IA32_X2APIC_IRR3 = 0x823,
    MSR_CODE_IA32_X2APIC_IRR4 = 0x824,
    MSR_CODE_IA32_X2APIC_IRR5 = 0x825,
    MSR_CODE_IA32_X2APIC_IRR6 = 0x826,
    MSR_CODE_IA32_X2APIC_IRR7 = 0x827,
    MSR_CODE_IA32_X2APIC_ESR = 0x828,
    MSR_CODE_IA32_X2APIC_LVT_CMCI = 0x82F,
    MSR_CODE_IA32_X2APIC_ICR = 0x830,
    MSR_CODE_IA32_X2APIC_LVT_TIMER = 0x832,
    MSR_CODE_IA32_X2APIC_LVT_THERMAL = 0x833,
    MSR_CODE_IA32_X2APIC_LVT_PMI = 0x834,
    MSR_CODE_IA32_X2APIC_LVT_LINT0 = 0x835,
    MSR_CODE_IA32_X2APIC_LVT_LINT1 = 0x836,
    MSR_CODE_IA32_X2APIC_LVT_ERROR = 0x837,
    MSR_CODE_IA32_X2APIC_INIT_COUNT = 0x838,
    MSR_CODE_IA32_X2APIC_CUR_COUNT = 0x839,
    MSR_CODE_IA32_X2APIC_DIV_CONF = 0x83E,
    MSR_CODE_IA32_X2APIC_SELF_IPI = 0x83F,
    MSR_CODE_IA32_DEBUG_INTERFACE = 0xC80,
    MSR_CODE_IA32_L3_QOS_CFG = 0xC81,
    MSR_CODE_IA32_QM_EVTSEL = 0xC8D,
    MSR_CODE_IA32_QM_CTR = 0xC8E,
    MSR_CODE_IA32_PQR_ASSOC = 0xC8F,
    // 0xC90 - 0xD8F Reserved
    MSR_CODE_IA32_L3_MASK_0 = 0xC90,
    MSR_CODE_IA32_BNDCFGS = 0xD90,
    MSR_CODE_IA32_XSS = 0xDA0,
    MSR_CODE_IA32_PKG_HDC_CTL = 0xDB0,
    MSR_CODE_IA32_PM_CTL1 = 0xDB1,
    MSR_CODE_IA32_THREAD_STALL = 0xDB2,
    // 0x40000000 - 0x400000FF Reserved
    MSR_CODE_IA32_EFER = 0xC0000080,
    MSR_CODE_IA32_STAR = 0xC0000081,
    MSR_CODE_IA32_LSTAR = 0xC0000082,
    MSR_CODE_IA32_FMASK = 0xC0000084,
    MSR_CODE_IA32_FS_BASE = 0xC0000100,
    MSR_CODE_IA32_GS_BASE = 0xC0000101,
    MSR_CODE_IA32_KERNEL_GS_BASE = 0xC0000102,
    MSR_CODE_IA32_TSC_AUX = 0xC0000103,
} MSR_CODE, *PMSR_CODE;

// MSR_CODE_IA32_APIC_BASE = 0x1B
typedef union _IA32_APIC_BASE
{
    UINT64 qwValue;
    struct {
        UINT64 Reserved0 : 8;           //!< 0-7
        UINT64 Bsp : 1;                 //!< 8      Is this the bootstrap processor
        UINT64 Reserved1 : 2;           //!< 9-10
        UINT64 ApicGlobalEnable : 1;    //!< 11     Enables or disables the local APIC
        UINT64 ApicBase : 24;           //!< 12-35  Base address of the APIC registers. After a
                                        //          power-up or reset, this is set to 0xFEE00000
        UINT64 Reserved2 : 28;          //!< 36-63
    };
} IA32_APIC_BASE, *PIA32_APIC_BASE;

// MSR_CODE_IA32_FEATURE_CONTROL = 0x3A
//! Vol 3A, Table 5-1. Layout of IA32_FEATURE_CONTROL
typedef union _IA32_FEATURE_CONTROL
{
    UINT64 qwValue;
    struct {
        UINT64 LockBit : 1;         //!< 0      If the lock bit is clear, an attempt to execute
                                    //          VMXON will cause a #GP fault
        UINT64 VmxInSmx : 1;        //!< 1      Enables VMX in SMX operation
        UINT64 VmxOutsideSmx : 1;   //!< 2      Enables VMX outside SMX operation
        UINT64 Reserved0 : 5;       //!< 3-7
        UINT64 SenterLocals : 7;    //!< 8-14   Enabled functionality of the SENTER leaf function
        UINT64 SenterGlobal : 1;    //!< 15     Global enable of all SENTER functionalities
        UINT64 Reserved1 : 48;      //!< 16-63
    };
} IA32_FEATURE_CONTROL, *PIA32_FEATURE_CONTROL;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_FEATURE_CONTROL));

// MSR_CODE_IA32_SMM_MONITOR_CTL = 0x9B
//! 26.15.5 Enabling the Dual-Monitor Treatment
// WRMSR to IA32_SMM_MONITOR_CTL generates a #GP if outside SMM, or if an attempt is
// made to set any reserved bit
typedef union _IA32_SMM_MONITOR_CTL
{
    UINT64 qwValue;
    struct {
        UINT64 Valid : 1;           //!< 0      SMM monitor can only be used if this is set
        UINT64 Reserved0 : 1;       //!< 1      0
        UINT64 UnblockSmi : 1;      //!< 2      VMXOFF unblock SMIs unless this bit is set
        UINT64 Reserved1 : 9;       //!< 3-11   0
        UINT64 MsegAddress : 20;    //!< 12-31  Physical address of MSEG base
        UINT64 Reserved2 : 32;      //!< 32-63  0
    };
} IA32_SMM_MONITOR_CTL, *PIA32_SMM_MONITOR_CTL;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_SMM_MONITOR_CTL));

// MSR_CODE_IA32_MTRRCAP = 0xFE
//! Vol 3A, Table 35-2. IA-32 Architectural MSRs 
typedef union _IA32_MTRRCAP
{
    UINT64 qwValue;
    struct {
        UINT64 Vcnt : 8;        //!< 0-7    Number of variable range registers
        UINT64 Fix : 1;         //!< 8      Fixed range registers supported
        UINT64 Reserved0 : 1;   //!< 9
        UINT64 Wc : 1;          //!< 10     Write-combining memory type supported
        UINT64 Smrr : 1;        //!< 11     SMRR interface supported
        UINT64 Reserved1 : 52;  //!< 12-63
    };    
} IA32_MTRRCAP, *PIA32_MTRRCAP;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRRCAP));

//! Vol 3A, Table 11-9. Address Mapping for Fixed-Range MTRRs
// MSR_CODE_IA32_MTRR_FIX64K_00000 (0x250)
typedef union _IA32_MTRR_FIX64K
{
    UINT64 qwValue;
    UINT8 acRanges[8];
    struct {
        UINT8 Range0;   //!< 0-7    0x00000-0x0FFFF
        UINT8 Range1;   //!< 8-15   0x10000-0x1FFFF
        UINT8 Range2;   //!< 16-23  0x20000-0x2FFFF
        UINT8 Range3;   //!< 24-31  0x30000-0x3FFFF
        UINT8 Range4;   //!< 32-39  0x40000-0x4FFFF
        UINT8 Range5;   //!< 40-47  0x50000-0x5FFFF
        UINT8 Range6;   //!< 48-55  0x60000-0x6FFFF
        UINT8 Range7;   //!< 56-63  0x70000-0x7FFFF
    };
} IA32_MTRR_FIX64K, *PIA32_MTRR_FIX64K;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRR_FIX64K));

// MSR_CODE_IA32_MTRR_FIX16K_80000 (0x258)
// MSR_CODE_IA32_MTRR_FIX16K_A0000 (0x259)
typedef union _IA32_MTRR_FIX16K
{
    UINT64 qwValue;
    UINT8 acRanges[8];
    struct {
        UINT8 Range0;   //!< 0-7    0x80000-0x83FFF
        UINT8 Range1;   //!< 8-15   0x84000-0x87FFF
        UINT8 Range2;   //!< 16-23  0x88000-0x8BFFF
        UINT8 Range3;   //!< 24-31  0x8C000-0x8FFFF
        UINT8 Range4;   //!< 32-39  0x90000-0x93FFF
        UINT8 Range5;   //!< 40-47  0x94000-0x97FFF
        UINT8 Range6;   //!< 48-55  0x98000-0x9BFFF
        UINT8 Range7;   //!< 56-63  0x9C000-0x9FFFF
    };
} IA32_MTRR_FIX16K, *PIA32_MTRR_FIX16K;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRR_FIX16K));

// MSR_CODE_IA32_MTRR_FIX4K_C0000 (0x268)
// MSR_CODE_IA32_MTRR_FIX4K_C8000 (0x269)
// MSR_CODE_IA32_MTRR_FIX4K_D0000 (0x26A)
// MSR_CODE_IA32_MTRR_FIX4K_D8000 (0x26B)
// MSR_CODE_IA32_MTRR_FIX4K_E0000 (0x26C)
// MSR_CODE_IA32_MTRR_FIX4K_E8000 (0x26D)
// MSR_CODE_IA32_MTRR_FIX4K_F0000 (0x26E)
// MSR_CODE_IA32_MTRR_FIX4K_F8000 (0x26F)
typedef union _IA32_MTRR_FIX4K
{
    UINT64 qwValue;
    UINT8 acRanges[8];
    struct {
        UINT8 Range0;   //!< 0-7    0xC0000-0xC0FFF
        UINT8 Range1;   //!< 8-15   0xC1000-0xC1FFF
        UINT8 Range2;   //!< 16-23  0xC2000-0xC2FFF
        UINT8 Range3;   //!< 24-31  0xC3000-0xC3FFF
        UINT8 Range4;   //!< 32-39  0xC4000-0xC4FFF
        UINT8 Range5;   //!< 40-47  0xC5000-0xC5FFF
        UINT8 Range6;   //!< 48-55  0xC6000-0xC6FFF
        UINT8 Range7;   //!< 56-63  0xC7000-0xC7FFF
    };
} IA32_MTRR_FIX4K, *PIA32_MTRR_FIX4K;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRR_FIX4K));


//! Vol 3A, Figure 11-7. IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register Pair
// MSR_CODE_IA32_MTRR_PHYSBASE0 = 0x200
typedef union _IA32_MTRR_PHYSBASE
{
    UINT64 qwValue;
    struct {
        UINT64 Type : 8;        //!< 0-7    Memory type for the range 
        UINT64 Reserved0 : 4;   //!< 8-11
        UINT64 Base : 52;       //!< 12-63  Base address of the address range
    };
} IA32_MTRR_PHYSBASE, *PIA32_MTRR_PHYSBASE;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRR_PHYSBASE));

// MSR_CODE_IA32_MTRR_PHYSMASK0 = 0x201
typedef union _IA32_MTRR_PHYSMASK
{
    UINT64 qwValue;
    struct {
        UINT64 Reserved0 : 11;  //!< 0-10
        UINT64 Valid : 1;       //!< 11     Enables the register pair when set
        UINT64 Mask : 52;       //!< 12-63  Determines the range of the region being mapped
    };
} IA32_MTRR_PHYSMASK, *PIA32_MTRR_PHYSMASK;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRR_PHYSMASK));


//! Vol 3A, Figure 11-8. IA32_SMRR_PHYSBASE and IA32_SMRR_PHYSMASK SMRR Pair
// MSR_CODE_IA32_SMRR_PHYSBASE = 0x1F2
typedef union _IA32_SMRR_PHYSBASE
{
    UINT64 qwValue;
    struct {
        UINT64 Type : 8;        //!< 0-7    Memory type for the range 
        UINT64 Reserved0 : 4;   //!< 8-11
        UINT64 Base : 20;       //!< 12-31  Base address of SMM address range
        UINT64 Reserved1 : 32;  //!< 32-63
    };
} IA32_SMRR_PHYSBASE, *PIA32_SMRR_PHYSBASE;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_SMRR_PHYSBASE));

// MSR_CODE_IA32_SMRR_PHYSMASK = 0x1F3
typedef union _IA32_SMRR_PHYSMASK
{
    UINT64 qwValue;
    struct {
        UINT64 Reserved0 : 11;  //!< 0-10
        UINT64 Valid : 1;       //!< 11     Enables the register pair when set
        UINT64 Mask : 20;       //!< 12-63  Determines the range of the SMM region being mapped
        UINT64 Reserved1 : 32;  //!< 32-63
    };
} IA32_SMRR_PHYSMASK, *PIA32_SMRR_PHYSMASK;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_SMRR_PHYSMASK));

// MSR_CODE_IA32_PAT = 0x277
//! Vol 3A, Table 11-10. Memory Types That Can Be Encoded With PAT
typedef enum _IA32_PAT_MEMTYPE
{
    IA32_PAT_MEMTYPE_UC = 0,    //!< Uncacheable (UC)
    IA32_PAT_MEMTYPE_WC = 1,    //!< Write Combining (WC)
    // 2-3 Reserved
    IA32_PAT_MEMTYPE_WT = 4,    //!< Write Through (WT)
    IA32_PAT_MEMTYPE_WP = 5,    //!< Write Protected (WP)
    IA32_PAT_MEMTYPE_WB = 6,    //!< Write Back (WB)
    IA32_PAT_MEMTYPE_UCM = 7,   //!< Uncached (UC-)
    // 8-0xFF Reserved
    IA32_PAT_MEMTYPE_INVALID = 0xFF
} IA32_PAT_MEMTYPE, *PIA32_PAT_MEMTYPE;

//! Vol 3A, Table 11-12. Memory Type Setting of PAT Entries Following a Power-up or Reset
#define PAT0_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_WB
#define PAT1_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_WT
#define PAT2_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_UCM
#define PAT3_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_WC
#define PAT4_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_WB
#define PAT5_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_WT
#define PAT6_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_UCM
#define PAT7_DEFAULT_MEMTYPE IA32_PAT_MEMTYPE_UC

//! Vol 3A, Figure 11-9. IA32_PAT MSR
// Also see, Table 11-11. Selection of PAT Entries with PAT, PCD, and PWT Flags
typedef union _IA32_PAT
{
    UINT64 qwValue;
    struct {
        UINT64 Pa0 : 3;         //!< 0-2
        UINT64 Reserved0 : 5;   //!< 3-7
        UINT64 Pa1 : 3;         //!< 8-10
        UINT64 Reserved1 : 5;   //!< 11-15
        UINT64 Pa2 : 3;         //!< 16-18
        UINT64 Reserved2 : 5;   //!< 19-23
        UINT64 Pa3 : 3;         //!< 24-26
        UINT64 Reserved3 : 5;   //!< 27-31
        UINT64 Pa4 : 3;         //!< 32-34
        UINT64 Reserved4 : 5;   //!< 35-39
        UINT64 Pa5 : 3;         //!< 40-42
        UINT64 Reserved5 : 5;   //!< 43-47
        UINT64 Pa6 : 3;         //!< 48-50
        UINT64 Reserved6 : 5;   //!< 51-55
        UINT64 Pa7 : 3;         //!< 56-58
        UINT64 Reserved7 : 5;   //!< 59-63
    };
} IA32_PAT, *PIA32_PAT;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_PAT));

// MSR_CODE_IA32_MTRR_DEF_TYPE = 0x2FF
//! Vol 3A, 11.11.2.1 IA32_MTRR_DEF_TYPE MSR
typedef union _IA32_MTRR_DEF_TYPE
{
    UINT64 qwValue;
    struct {
        UINT64 Type : 8;        //!< 0-7    Default memory type
        UINT64 Reserved0 : 2;   //!< 8-9    0
        UINT64 Fe : 1;          //!< 10     Fixed-range MTRRs enable/disable
        UINT64 E : 1;           //!< 11     MTRR enable/disable
        UINT64 Reserved1 : 42;  //!< 12-63  0
    };
} IA32_MTRR_DEF_TYPE, *PIA32_MTRR_DEF_TYPE;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_MTRR_DEF_TYPE));

// MSR_CODE_IA32_VMX_BASIC = 0x480
//! Vol 3C, A.1 BASIC VMX INFORMATION
typedef union _IA32_VMX_BASIC
{
    UINT64 qwValue;
    struct {
        UINT64 RevisionId : 31; //!< 0-30   VMCS revision identifier
        UINT64 Reserved0 : 1;   //!< 31     0
        UINT64 VmcsSize : 13;   //!< 32-44  Size of VMXON and VMCS regions
        UINT64 Reserved1 : 3;   //!< 45-47  0
        UINT64 Only32bit : 1;   //!< 48     Support only 32bit addresses in VMCS
        UINT64 DualMonitor : 1; //!< 49     Support dual monitor
        UINT64 VmcsMemType : 4; //!< 50-53  0=UC, 6=WB, else undefined
        UINT64 IoExitInfo : 1;  //!< 54     INS/OUTS opcodes have exit information
        UINT64 TrueMsrs : 1;    //!< 55     Support VMX true MSRs
        UINT64 Reserved2 : 8;   //!< 56-63  0
    };
} IA32_VMX_BASIC, *PIA32_VMX_BASIC;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_VMX_BASIC));

// MSR_CODE_IA32_VMX_MISC = 0x485
// A.6 MISCELLANEOUS DATA
typedef union _IA32_VMX_MISC
{
    UINT64 qwValue;
    struct {
        UINT64 TscInc : 5;          //!< 0-4    VMX-preemption timer counts down by 1 every time bit X
                                    //          in the TSC changes due to a TSC increment
        UINT64 StoreEferLma : 1;    //!< 5      If 1, VM exits store the value of IA32_EFER.LMA
                                    //          into the "IA-32e mode guest" VM-entry control
        UINT64 StateHlt : 1;        //!< 6      If 0, VM-Entry to HLT state will fail
        UINT64 StateShutdown : 1;   //!< 7      If 0, VM-Entry to Shutdown state will fail
        UINT64 StateWaitForSipi : 1;//!< 8      If 0, VM-Entry to Wait-for-SIPI state will fail
        UINT64 Reserved0 : 6;       //!< 9-14   0
        UINT64 SmmIa32Smbase : 1;   //!< 15     RDMSR can be used in SMM to read IA32_SMBASE MSR
        UINT64 Cr3Values : 9;       //!< 16-24  CR3-target values supported by the processor
        UINT64 MsrListMax : 3;      //!< 25-27  Max number of MSRs that appear in VM-Exit MSR-store list,
                                    //          MSR-load list, or the VM-entry MSR-load list
        UINT64 UnblockSmi : 1;      //!< 28     IA32_SMM_MONITOR_CTL.UnblockSmi can be set to 1
        UINT64 WriteInfoFields : 1; //!< 29     If 1, can VMWRITE to VM-exit information fields
        UINT64 Reserved1 : 2;       //!< 30-31  0
        UINT64 MsegId : 32;         //!< 32-63  MSEG revision identifier used by the processor
    };
} IA32_VMX_MISC, *PIA32_VMX_MISC;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_VMX_MISC));

// MSR_CODE_IA32_VMX_EPT_VPID_CAP = 0x48C
// A.10 VPID AND EPT CAPABILITIES
// reports information about the capabilities of the logical processor with regard 
// to virtual-processor identifiers (VPIDs) and extended page tables (EPT)
typedef union _IA32_VMX_EPT_VPID_CAP
{
    UINT64 qwValue;
    struct {
        UINT64 AllowExecOnly : 1;   //!< 0      allows bits 2:0 of PTE to be 100b
                                    //          (indicating an execute - only translation)
        UINT64 Reserved0 : 5;       //!< 1-5
        UINT64 Support4kb : 1;      //!< 6      indicates support for a page-walk length of 4
        UINT64 Reserved1 : 1;       //!< 7
        UINT64 Uc : 1;              //!< 8      allow uncacheable memory type (UC)
        UINT64 Reserved2 : 5;       //!< 9-13 
        UINT64 Wb : 1;              //!< 14     allow write-back memory type (WB)
        UINT64 Reserved3 : 1;       //!< 15
        UINT64 Support2mb : 1;      //!< 16     allow 2MB page size
        UINT64 Support1gb : 1;      //!< 17     allow 1GB page size
        UINT64 Reserved4 : 2;       //!< 18-19
        UINT64 Invept : 1;          //!< 20     supports INVEPT
        UINT64 AccessAndDirty : 1;  //!< 21     accessed and dirty flags are supported
        UINT64 Reserved5 : 3;       //!< 22-24
        UINT64 InveptSingle : 1;    //!< 25     single-context INVEPT is supported
        UINT64 InveptAll : 1;       //!< 26     all-context INVEPT is supported
        UINT64 Reserved6 : 5;       //!< 27-31
        UINT64 Invvpid : 1;         //!< 32     INVVPID instruction is supported
        UINT64 Reserved7 : 7;       //!< 33-39
        UINT64 InvvpidInd : 1;      //!< 40     individual-address INVVPID type is supported
        UINT64 InvvpidSingle : 1;   //!< 41     single-context INVVPID type is supported
        UINT64 InvvpidAll : 1;      //!< 42     all-context INVVPID type is supported
        UINT64 InvvpidSingleG : 1;  //!< 43     single-context-retaining-globals INVVPID type is supported
        UINT64 Reserved8 : 20;      //!< 44-63
    };
} IA32_VMX_EPT_VPID_CAP, *PIA32_VMX_EPT_VPID_CAP;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_VMX_EPT_VPID_CAP));

// MSR_CODE_IA32_EFER = 0xC0000080
typedef union _IA32_EFER
{
    UINT64 qwValue;
    struct {
        UINT64 Sce : 1;         //!< 0      Enables SYSCALL/SYSRET instructions in 64bit
        UINT64 Reserved0 : 7;   //!< 1-7    
        UINT64 Lme : 1;         //!< 8      Enables IA-32e mode operation
        UINT64 Reserved1 : 1;   //!< 9    
        UINT64 Lma : 1;         //!< 10     Indicates IA-32e mode is active when set
        UINT64 Nxe : 1;         //!< 11     Execute Disable Bit Enable
        UINT64 Reserved2 : 52;  //!< 12-63
    };
} IA32_EFER, *PIA32_EFER;
C_ASSERT(sizeof(UINT64) == sizeof(IA32_EFER));

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_MSR64_H__ */
