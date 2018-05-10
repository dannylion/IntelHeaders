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
* @file        VT-d.h
* @section    Intel VT-d structures and constants
*/

#ifndef __INTEL_VTD_H__
#define __INTEL_VTD_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

#define CAP_REG                    0x8
#define EX_CAP_REG                0x10
#define GLOBAL_COMMAND_REG        0x18
#define GLOBAL_STATUS_REG        0x1c
#define ROOT_TABLE_ADDRESS_REG    0x20
#define CONTEXT_COMMAND_REG        0x28
 
typedef union _R_CAP
{
    UINT64 qwValue;
    struct {
        UINT64 NumberOfDomainsSupported : 3;        //!< 0-2
        UINT64 AdvancedFaultLogging : 1;            //!< 3
        UINT64 RequiredWriteBufferFlush : 1;        //!< 4
        UINT64 ProtectedLowMemoryRegion : 1;        //!< 5
        UINT64 ProtectedHighMemoryRegion : 1;       //!< 6
        UINT64 CachingMode : 1;                     //!< 7
        UINT64 AdjuctedGuestAddressWidth : 5;       //!< 8-12
        UINT64 Reserved1 : 3;                       //!< 13-15
        UINT64 MaximumGuestAddressWidth : 6;        //!< 16-21
        UINT64 ZeroLengthRead : 1;                  //!< 22
        UINT64 Reserved2 : 1;                       //!< 23
        UINT64 FaultRecordingRegisterOffset : 10;   //!< 24-33
        UINT64 SLLargePageSupport : 4;              //!< 34-37
        UINT64 Reserved3 : 1;                       //!< 38
        UINT64 PageSelectiveInvalidation : 1;       //!< 39
        UINT64 NumberOfFaultRecordingRegs : 8;      //!< 40-47
        UINT64 MaximumAddressMaxValue : 6;          //!< 48-53
        UINT64 WriteDraining : 1;                   //!< 54
        UINT64 ReadDraining : 1;                    //!< 55
        UINT64 FLOneGBPageSupport : 1;              //!< 56
        UINT64 Reserved4 : 2;                       //!< 57-58
        UINT64 PostedInterruptsSupport : 1;         //!< 59
        UINT64 Reserved5 : 4;                       //!< 60-63
    };
} R_CAP, *PR_CAP;
C_ASSERT(sizeof(R_CAP) == sizeof(UINT64));

typedef union _R_EXT_CAP
{
    UINT64 qwValue;
    struct {
        UINT64 PageWalkCoherency : 1;               //!< 0
        UINT64 QueuedInvalidationSupport : 1;       //!< 1
        UINT64 DeviceTLBSupport : 1;                //!< 2
        UINT64 InterruptRemappingSupport : 1;       //!< 3
        UINT64 ExtendedInterruptMode : 1;           //!< 4
        UINT64 Reserved1 : 1;                       //!< 5
        UINT64 PassThrough : 1;                     //!< 6
        UINT64 SnoopControl : 1;                    //!< 7
        UINT64 IOTLBRegOffset : 10;                 //!< 8-17
        UINT64 Reserved2 : 2;                       //!< 18-19
        UINT64 MaximumHandleMaskValue : 4;          //!< 20-23
        UINT64 ExtendedContextSupport : 1;          //!< 24
        UINT64 MemoryTypeSupport : 1;               //!< 25
        UINT64 NestedTranslationSupport : 1;        //!< 26
        UINT64 DeferredInvalidateSupport : 1;       //!< 27
        UINT64 Reserved3 : 1;                       //!< 28
        UINT64 PageRequestSupport : 1;              //!< 29
        UINT64 ExecuteRequestSupport : 1;           //!< 30
        UINT64 SupervisorRequestSupport : 1;        //!< 31
        UINT64 Reserved4 : 1;                       //!< 32
        UINT64 NoWriteFlagSupport : 1;              //!< 33
        UINT64 ExtendedAccessFlagSupport : 1;       //!< 34
        UINT64 PASIDSizeSupport : 5;                //!< 35-39
        UINT64 PASIDSupport : 1;                    //!< 40
        UINT64 DeviceTLBInvalidationThrottle : 1;   //!< 41
        UINT64 PageRequestDrainSupport : 1;         //!< 42
        UINT64 Reserved5 : 21;                      //!< 43-63
    };
} R_EXT_CAP, *PR_EXT_CAP;
C_ASSERT(sizeof(R_EXT_CAP) == sizeof(UINT64));

typedef union _R_GLOBAL_COMMAND
{
    UINT32 dwValue;
    struct {
        UINT32 Reserved : 23;                       //!< 0-22
        UINT32 CompatibilityFormatInterrupt : 1;    //!< 23
        UINT32 SetInterruptRemapTablePointer : 1;   //!< 24
        UINT32 EnableInterruptRemapping : 1;        //!< 25
        UINT32 EnableQueuedInvalidation : 1;        //!< 26
        UINT32 WriteBufferFlush : 1;                //!< 27
        UINT32 EnableAdvancedFaultLogging : 1;      //!< 28
        UINT32 SetFaultLog : 1;                     //!< 29
        UINT32 SetRootTablePointer : 1;             //!< 30
        UINT32 EnableTranslation : 1;               //!< 31
    };
} R_GLOBAL_COMMAND, *PR_GLOBAL_COMMAND;
C_ASSERT(sizeof(R_GLOBAL_COMMAND) == sizeof(UINT32));

typedef union _R_GLOBAL_STATUS
{
    UINT32 dwValue;
    struct {
        UINT32 Reserved : 23;                           //!< 0-22
        UINT32 CompatibilityFormatInterruptStatus : 1;  //!< 23
        UINT32 InterruptRemapTablePointerStatus : 1;    //!< 24
        UINT32 InterruptRemappingEnableStatus : 1;      //!< 25
        UINT32 QueuedInvalidationEnableStatus : 1;      //!< 26
        UINT32 WriteBufferFlushStatus : 1;              //!< 27
        UINT32 AdvancedFaultLoggingStatus : 1;          //!< 28
        UINT32 FaultLogStatus : 1;                      //!< 29
        UINT32 RootTablePointerStatus : 1;              //!< 30
        UINT32 TransitionEnableStatus : 1;              //!< 31
    };
} R_GLOBAL_STATUS, *PR_GLOBAL_STATUS;
C_ASSERT(sizeof(R_GLOBAL_STATUS) == sizeof(UINT32));

typedef union _R_ROOT_TABLE_ADDRESS
{
    UINT64 qwValue;
    struct {
        UINT64 Reserved : 11;   //!< 0-10
        UINT64 Type : 1;        //!< 11
        UINT64 Address : 52;    //!< 12-63
    };
} R_ROOT_TABLE_ADDRESS, *PR_ROOT_TABLE_ADDRESS;
C_ASSERT(sizeof(R_ROOT_TABLE_ADDRESS) == sizeof(UINT64));

typedef union _R_IOTLB
{
    UINT64 qwValue;
    struct {
        UINT64 Reserved1 : 32;                          //!< 0-31
        UINT64 DomainID : 16;                           //!< 32-47
        UINT64 DrainWrites : 1;                         //!< 48
        UINT64 DrainReads : 1;                          //!< 49
        UINT64 Reserved2 : 7;                           //!< 50-56
        UINT64 IOTLBActualInvalidationGranularity : 2;  //!< 57-58
        UINT64 Reserved3 : 1;                           //!< 59
        UINT64 IOTLBInvalidationRequestGranularity : 2; //!< 60-61
        UINT64 Reserved4 : 1;                           //!< 62
        UINT64 InvalidateIOTLB : 1;                     //!< 63
    };
} R_IOTLB, *PR_IOTLB;
C_ASSERT(sizeof(R_IOTLB) == sizeof(UINT64));

typedef union _R_CONTEXT_CMD
{
    UINT64 qwValue;
    struct {
        UINT64 DomainID : 16;                               //!< 0-15
        UINT64 SourceID : 16;                               //!< 16-31
        UINT64 FunctionMask : 2;                            //!< 32-33
        UINT64 Reserved1 : 25;                              //!< 34-58
        UINT64 ContextActualInvalidationGranularity : 2;    //!< 59-60
        UINT64 ContextInvalidationRequestGranularity : 2;   //!< 61-62
        UINT64 InvalidateContextCache : 1;                  //!< 63
    };
} R_CONTEXT_CMD, *PR_CONTEXT_CMD;
C_ASSERT(sizeof(R_CONTEXT_CMD) == sizeof(UINT64));

typedef struct _ROOT_ENTRY
{
    UINT64 Present : 1;                 //!< 0
    UINT64 Reserved1 : 11;              //!< 1-11
    UINT64 ContextTablePointer : 52;    //!< 12-63
    UINT64 Reserved2;                   //!< 64-127
} ROOT_ENTRY, *PROOT_ENTRY;
C_ASSERT(sizeof(ROOT_ENTRY) == (2 * sizeof(UINT64)));

typedef struct _EXTENDED_ROOT_ENTRY
{
    UINT64 LowerPresent : 1;                //!< 0
    UINT64 Reserved1 : 11;                  //!< 1-11
    UINT64 LowerContextTablePointer : 52;   //!< 12-63
    UINT64 UpperPresent : 1;                //!< 64
    UINT64 Reserved2 : 11;                  //!< 65-75
    UINT64 UpperContextTablePointer : 52;   //!< 76-127
} EXTENDED_ROOT_ENTRY, *PEXTENDED_ROOT_ENTRY;
C_ASSERT(sizeof(EXTENDED_ROOT_ENTRY) == (2 * sizeof(UINT64)));

typedef struct _CONTEXT_ENTRY
{
    UINT64 Present : 1;                     //!< 0
    UINT64 FaultProcessingDisable : 1;      //!< 1
    UINT64 TranslationType : 2;             //!< 2-3
    UINT64 Reserved1 : 8;                   //!< 4-11
    UINT64 SLPageTranslationPointer : 52;   //!< 12-63
    UINT64 AddressWidth : 3;                //!< 64-66
    UINT64 Ignored : 4;                     //!< 67-70
    UINT64 Reserved2 : 1;                   //!< 71
    UINT64 DomainIdentifier : 16;           //!< 72-87
    UINT64 Reserved3 : 40;                  //!< 88-127
} CONTEXT_ENTRY, *PCONTEXT_ENTRY;
C_ASSERT(sizeof(CONTEXT_ENTRY) == (2 * sizeof(UINT64)));

typedef struct _EXTENDED_CONTEXT_ENTRY
{
    UINT64 Present : 1;                     //!< 0
    UINT64 FaultProcessingDisable : 1;      //!< 1
    UINT64 TranslationType : 3;             //!< 2-4
    UINT64 ExtendedMemoryType : 3;          //!< 5-7
    UINT64 DeferredInterruptEnable : 1;     //!< 8
    UINT64 PageRequestEnable : 1;           //!< 9
    UINT64 NestedTranslationEnable : 1;     //!< 10
    UINT64 PASIDEnable : 1;                 //!< 11
    UINT64 SLPageTranslationPointer : 52;   //!< 12-63
    UINT64 AddressWidth : 3;                //!< 64-66
    UINT64 PageGlobalEnable : 1;            //!< 67
    UINT64 NoExecuteEnable : 1;             //!< 68
    UINT64 WriteProtectEnable : 1;          //!< 69
    UINT64 CacheDisable : 1;                //!< 70
    UINT64 ExtendedMemoryTypeEnable : 1;    //!< 71
    UINT64 DomainIdentifier : 16;           //!< 72-87
    UINT64 SMEP : 1;                        //!< 88
    UINT64 ExtendedAccessedFlagEnable : 1;  //!< 89
    UINT64 ExecuteRequestsEnable : 1;       //!< 90
    UINT64 SecondLevelExecuteEnable : 1;    //!< 91
    UINT64 Reserved1 : 4;                   //!< 92-95
    UINT64 PAT : 32;                        //!< 96-127
    UINT64 PASIDTableSize : 4;              //!< 128-131
    UINT64 Reserved2 : 8;                   //!< 132-139
    UINT64 PASIDTablePointer : 52;          //!< 140-191
    UINT64 Reserved3 : 12;                  //!< 192-203
    UINT64 PASIDStateTablePointer : 52;     //!< 204-255
} EXTENDED_CONTEXT_ENTRY, *PEXTENDED_CONTEXT_ENTRY;
C_ASSERT(sizeof(EXTENDED_CONTEXT_ENTRY) == (4 * sizeof(UINT64)));

typedef union _PASID_ENTRY
{
    UINT64 qwValue;
    struct {
        UINT64 Present : 1;                     //!< 0
        UINT64 Reserved1 : 2;                   //!< 1-2
        UINT64 PageLevelWriteThrough : 1;       //!< 3
        UINT64 PageLevelCacheDisable : 1;       //!< 4
        UINT64 Reserved2 : 6;                   //!< 5-10
        UINT64 SupervisorRequestsEnable : 1;    //!< 11
        UINT64 FLPageTranslationPointer : 52;   //!< 12-63
    };
} PASID_ENTRY, *PPASID_ENTRY;
C_ASSERT(sizeof(PASID_ENTRY) == sizeof(UINT64));

typedef union _PASID_STATE_ENTRY
{
    UINT64 qwValue;
    struct {
        UINT64 Reserved1 : 32;              //!< 0-31
        UINT64 ActiveReferenceCount : 16;   //!< 32-47
        UINT64 Reserved2 : 15;              //!< 48-62
        UINT64 DeferredInvalidate : 1;      //!< 63
    };
} PASID_STATE_ENTRY, *PPASID_STATE_ENTRY;
C_ASSERT(sizeof(PASID_STATE_ENTRY) == sizeof(UINT64));

#pragma pack(pop)
#pragma warning(push)
#endif /* __INTEL_VTD_H__ */
