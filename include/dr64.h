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
* @file        dr64.h
* @section    Intel Debug Registers
*/

#ifndef __INTEL_DR64_H__
#define __INTEL_DR64_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

// Debug Registers only allow up to 4 breakpoints to be set at any time
#define MAX_DR_BREAKPOINTS 4

//! Vol 3B, Figure 17-1. Debug Registers
//! Vol 3B, 17.2.3 Debug Status Register (DR6)
typedef union _DR6_REG
{
    UINT32 dwValue;
    struct {
        UINT32 B0 : 1;          //!< 0      Breakpoint 0 conditions have been met
        UINT32 B1 : 1;          //!< 1      Breakpoint 1 conditions have been met
        UINT32 B2 : 1;          //!< 2      Breakpoint 2 conditions have been met
        UINT32 B3 : 1;          //!< 3      Breakpoint 3 conditions have been met
        UINT32 MustBeOne0 : 8;  //!< 4-11   1
        UINT32 Reserved0 : 1;   //!< 12     0
        UINT32 Bd : 1;          //!< 13     Next instruction will access a DR
        UINT32 Bs : 1;          //!< 14     Fault caused by single-step
        UINT32 Bt : 1;          //!< 15     Fault caused by task-switch
        UINT32 Rtm : 1;         //!< 16     Fault is within a RTM region
        UINT32 MustBeOne1 : 15; //!< 17-31  1
    };
} DR6_REG, *PDR6_REG;
C_ASSERT(sizeof(UINT32) == sizeof(DR6_REG));

//! Vol 3B, Figure 17-1. Debug Registers
//! Vol 3B, 17.2.3 Debug Control Register (DR7)
typedef enum _DR_CONDITION
{
    DR_CONDITION_EXECUTE = 0,       // Break on execution only. When this flag is used
                                    // the size must be DR_SIZE_1
    DR_CONDITION_DATA_WRITE = 1,    // Break on data write only
    DR_CONDITION_IO_ACCESS = 2,     // Break on I/O access, or undefined if CR4.DE is clear
    DR_CONDITION_DATA_ACCESS = 3,   // Break on data read/write but not instruction fetch
    DR_CONDITION_COUNT              // Must be last!
} DR_CONDITION, *PDR_CONDITION;

typedef enum _DR_SIZE
{
    DR_SIZE_1 = 0,    // 1 byte
    DR_SIZE_2 = 1,    // 2 bytes
    DR_SIZE_8 = 2,    // 8 bytes on some architectures, on others it might be undefined
    DR_SIZE_4 = 3,    // 4 bytes
    DR_SIZE_COUNT     // Must be last!
} DR_SIZE, *PDR_SIZE;

typedef union _DR7_REG
{
    UINT32 dwValue;
    struct {
        UINT32 L0 : 1;          //!< 0      Enable breakpoint 0 for current task
        UINT32 G0 : 1;          //!< 1      Enable breakpoint 0 for all tasks
        UINT32 L1 : 1;          //!< 2      Enable breakpoint 1 for current task
        UINT32 G1 : 1;          //!< 3      Enable breakpoint 1 for all tasks
        UINT32 L2 : 1;          //!< 4      Enable breakpoint 2 for current task
        UINT32 G2 : 1;          //!< 5      Enable breakpoint 2 for all tasks
        UINT32 L3 : 1;          //!< 6      Enable breakpoint 3 for current task
        UINT32 G3 : 1;          //!< 7      Enable breakpoint 3 for all tasks
        UINT32 Le : 1;          //!< 8      Find the opcode that caused a data BP fault
        UINT32 Ge : 1;          //!< 9      Find the opcode that caused a data BP fault
        UINT32 MustBeOne0 : 1;  //!< 10     1
        UINT32 Rtm : 1;         //!< 11     Enable advanced debugging of RTM regions
        UINT32 Reserved0 : 1;   //!< 12     0
        UINT32 Gd : 1;          //!< 13     Cause a fault for every MOV with a DR
        UINT32 Reserved1 : 2;   //!< 14-15  0
        UINT32 Rw0 : 2;         //!< 16-17  See DR_CONDITION enum
        UINT32 Len0 : 2;        //!< 18-19  See DR_SIZE enum
        UINT32 Rw1 : 2;         //!< 20-21  See DR_CONDITION enum
        UINT32 Len1 : 2;        //!< 22-23  See DR_SIZE enum
        UINT32 Rw2 : 2;         //!< 24-25  See DR_CONDITION enum
        UINT32 Len2 : 2;        //!< 26-27  See DR_SIZE enum
        UINT32 Rw3 : 2;         //!< 28-29  See DR_CONDITION enum
        UINT32 Len3 : 2;        //!< 30-31  See DR_SIZE enum
    };
} DR7_REG, *PDR7_REG;
C_ASSERT(sizeof(UINT32) == sizeof(DR7_REG));

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_DR64_H__ */

/**
 * Add a new hardware breakpoint through Debug Registers
 * @param pvAddress - Address of breakpoint
 * @param eCondition - Condition to raise fault at
 * @param eSize - Size of the area that will trigger the fault
 * @param pcBreakpointNumber - Number of added breakpoint
 * @return TRUE on success, else FALSE
 */
BOOLEAN
DR_AddBreakpoint(
    IN const PVOID pvAddress,
    IN const DR_CONDITION eCondition,
    IN const DR_SIZE eSize,
    OUT PUINT8 pcBreakpointNumber
);

/**
* Remove a hardware breakpoint set in Debug Registers
* @param cBreakpointNumber - Number of breakpoint to remove
*/
VOID
DR_RemoveBreakpoint(
    IN const UINT8 cBreakpointNumber
);

/**
* Remove all hardware breakpoints set in Debug Registers
*/
VOID
DR_RemoveAllBreakpoints(
    VOID
);
