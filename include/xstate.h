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
* @file     xstate.h
* @section  x86 extended state (SSE extensions)
* Data in this file is based on "Intel® Architecture Instruction Set
* Extensions Programming Reference" document
*/

#ifndef __INTEL_XSTATE_H__
#define __INTEL_XSTATE_H__

#include "ntdatatypes.h"

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning( disable : 4214)
#pragma warning( disable : 4201)
#pragma pack(push, 1)

//! Table 3-1. XCR0 Processor State Components
typedef union _XSTATE_XCR0 {
    UINT64 qwValue;
    struct {
        UINT64 Fp : 1;          //!< 0      Must be 1
        UINT64 Sse : 1;         //!< 1      SSE state (MXCSR and XMM regs) support
        UINT64 YmmHi : 1;       //!< 2      YMM_hi128 support
        UINT64 Bndregs : 1;     //!< 3      MPX bound register support
        UINT64 Bndscr : 1;      //!< 4      MPX configuration and status support
        UINT64 Opmask : 1;      //!< 5      Opmask support
        UINT64 ZmmHi256 : 1;    //!< 6      ZMM_Hi256 support
        UINT64 ZmmHi16 : 1;     //!< 6      Hi16-_ZMM support
        UINT64 Reserved0 : 1;   //!< 8
        UINT64 Pkru : 1;        //!< 9      PKRU support
        UINT64 Reserved1 : 53;  //!< 10-62
        UINT64 Lwp : 1;         //!< 63     
    };
} XSTATE_XCR0, *PXSTATE_XCR0;
C_ASSERT(sizeof(UINT64) == sizeof(XSTATE_XCR0));

// TODO: XSAVE Save Tables 3-3 to 3-8

#pragma pack(pop)
#pragma warning(pop)
#endif /* __INTEL_XSTATE_H__ */
