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
* @file		ntdatatypes.h
* @section	Define NT data types
*/

#ifndef __NT_DATA_TYPES_H__
#define __NT_DATA_TYPES_H__

#ifdef WIN32
#include <ntddk.h>
#else

// Disable 'warning C4214: nonstandard extension used: bit field types other than int'
// Disable 'warning C4201: nonstandard extension used: nameless struct/union'
#pragma warning(push)
#pragma warning(disable : 4214)
#pragma warning(disable : 4201)

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef INOUT
#define INOUT
#endif

#ifndef ANYSIZE_ARRAY
#define ANYSIZE_ARRAY 1
#endif

#ifndef CONST
#define CONST const
#endif

#ifndef UNALIGNED
#define UNALIGNED __unaligned
#endif

#ifndef C_ASSERT
#define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#endif

#ifndef DECLSPEC_ALIGN
#define DECLSPEC_ALIGN(x) __declspec(align(x))
#endif

#ifndef DECLSPEC_NORETURN
#define DECLSPEC_NORETURN __declspec(noreturn)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef NT_ASSERT
#define NT_ASSERT
#endif

#ifndef DECLSPEC_NORETURN
#define DECLSPEC_NORETURN __declspec(noreturn)
#endif

#ifndef FORCEINLINE
#define FORCEINLINE __forceinline
#endif

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x)   (x)
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

#ifndef VOID
#define VOID void
#endif

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field)    ((LONG)(LONG_PTR)&(((type *)0)->field))
#endif

#define MINCHAR			0x80
#define MAXCHAR			0x7f
#define MINSHORT		0x8000
#define MAXSHORT		0x7fff
#define MINLONG			0x80000000
#define MAXLONG			0x7fffffff
#define MAXUCHAR		0xff
#define MAXUSHORT		0xffff
#define MAXULONG		0xffffffff
#define INT8_MAX        127i8
#define UINT8_MAX       0xffui8
#define BYTE_MAX        0xff
#define SHORT_MAX       32767
#define INT16_MAX       32767i16
#define USHORT_MAX      0xffff
#define UINT16_MAX      0xffffui16
#define WORD_MAX        0xffff
#define INT_MAX         2147483647
#define INT32_MAX       2147483647i32
#define UINT_MAX        0xffffffff
#define UINT32_MAX      0xffffffffui32
#define LONG_MAX        2147483647L
#define ULONG_MAX       0xffffffffUL
#define DWORD_MAX       0xffffffffUL
#define LONGLONG_MAX    9223372036854775807i64
#define LONG64_MAX      9223372036854775807i64
#define INT64_MAX       9223372036854775807i64
#define ULONGLONG_MAX   0xffffffffffffffffui64
#define DWORDLONG_MAX   0xffffffffffffffffui64
#define ULONG64_MAX     0xffffffffffffffffui64
#define DWORD64_MAX     0xffffffffffffffffui64
#define UINT64_MAX      0xffffffffffffffffui64
#define INT128_MAX      170141183460469231731687303715884105727i128
#define UINT128_MAX     0xffffffffffffffffffffffffffffffffui128

typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef signed __int64      INT64, *PINT64;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;
typedef unsigned __int64    UINT64, *PUINT64;

typedef UINT64  UINTN;

typedef signed int LONG32, *PLONG32;

// The following types are guaranteed to be unsigned and 32 bits wide.
typedef unsigned int ULONG32, *PULONG32;
typedef unsigned int DWORD32, *PDWORD32;

typedef unsigned __int64 size_t;

typedef __int64 INT_PTR, *PINT_PTR;
typedef unsigned __int64 UINT_PTR, *PUINT_PTR;

typedef __int64 LONG_PTR, *PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;

typedef __int64 SHANDLE_PTR;
typedef unsigned __int64 HANDLE_PTR;
typedef unsigned int UHALF_PTR, *PUHALF_PTR;
typedef int HALF_PTR, *PHALF_PTR;

typedef void *PVOID;
typedef void *PVOID64;

typedef char CHAR;
typedef short SHORT;
typedef long LONG;

typedef unsigned short WCHAR;    // wc,   16-bit UNICODE character
typedef WCHAR *PWCHAR, *LPWCH, *PWCH;
typedef CONST WCHAR *LPCWCH, *PCWCH;

typedef WCHAR *NWPSTR, *LPWSTR, *PWSTR;
typedef PWSTR *PZPWSTR;
typedef CONST PWSTR *PCZPWSTR;
typedef WCHAR UNALIGNED *LPUWSTR, *PUWSTR;
typedef CONST WCHAR *LPCWSTR, *PCWSTR;
typedef PCWSTR *PZPCWSTR;
typedef CONST PCWSTR *PCZPCWSTR;
typedef CONST WCHAR UNALIGNED *LPCUWSTR, *PCUWSTR;

typedef WCHAR *PZZWSTR;
typedef CONST WCHAR *PCZZWSTR;
typedef WCHAR UNALIGNED *PUZZWSTR;
typedef CONST WCHAR UNALIGNED *PCUZZWSTR;

typedef  WCHAR *PNZWCH;
typedef  CONST WCHAR *PCNZWCH;
typedef  WCHAR UNALIGNED *PUNZWCH;
typedef  CONST WCHAR UNALIGNED *PCUNZWCH;

typedef CONST WCHAR *LPCWCHAR, *PCWCHAR;
typedef CONST WCHAR UNALIGNED *LPCUWCHAR, *PCUWCHAR;

typedef unsigned long UCSCHAR;

typedef UCSCHAR *PUCSCHAR;
typedef const UCSCHAR *PCUCSCHAR;

typedef UCSCHAR *PUCSSTR;
typedef UCSCHAR UNALIGNED *PUUCSSTR;

typedef const UCSCHAR *PCUCSSTR;
typedef const UCSCHAR UNALIGNED *PCUUCSSTR;

typedef UCSCHAR UNALIGNED *PUUCSCHAR;
typedef const UCSCHAR UNALIGNED *PCUUCSCHAR;

typedef CHAR *PCHAR, *LPCH, *PCH;
typedef CONST CHAR *LPCCH, *PCCH;

typedef CHAR *NPSTR, *LPSTR, *PSTR;
typedef PSTR *PZPSTR;
typedef CONST PSTR *PCZPSTR;
typedef CONST CHAR *LPCSTR, *PCSTR;
typedef PCSTR *PZPCSTR;
typedef CONST PCSTR *PCZPCSTR;

typedef CHAR *PZZSTR;
typedef CONST CHAR *PCZZSTR;

typedef  CHAR *PNZCH;
typedef  CONST CHAR *PCNZCH;

#ifndef _TCHAR_DEFINED
typedef char TCHAR, *PTCHAR;
typedef unsigned char TUCHAR, *PTUCHAR;
#define _TCHAR_DEFINED
#endif /* !_TCHAR_DEFINED */

typedef LPCH LPTCH, PTCH;
typedef LPCCH LPCTCH, PCTCH;
typedef LPSTR PTSTR, LPTSTR, PUTSTR, LPUTSTR;
typedef LPCSTR PCTSTR, LPCTSTR, PCUTSTR, LPCUTSTR;
typedef PZZSTR PZZTSTR, PUZZTSTR;
typedef PCZZSTR PCZZTSTR, PCUZZTSTR;
typedef PZPSTR PZPTSTR;
typedef PNZCH PNZTCH, PUNZTCH;
typedef PCNZCH PCNZTCH, PCUNZTCH;

typedef double DOUBLE;

typedef SHORT *PSHORT;
typedef LONG *PLONG;

typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;

typedef UCHAR *PUCHAR;
typedef USHORT *PUSHORT;
typedef ULONG *PULONG;

typedef CONST UCHAR *PCUCHAR;
typedef CONST USHORT *PCUSHORT;
typedef CONST ULONG *PCULONG;

typedef signed char SCHAR;
typedef SCHAR *PSCHAR;

typedef CONST SCHAR *PCSCHAR;

typedef PVOID HANDLE;
typedef HANDLE *PHANDLE;

typedef char CCHAR;
typedef short CSHORT;
typedef ULONG CLONG;

typedef CCHAR *PCCHAR;
typedef CSHORT *PCSHORT;
typedef CLONG *PCLONG;

typedef ULONG LCID;
typedef PULONG PLCID;
typedef USHORT LANGID;

typedef ULONG LOGICAL;
typedef ULONG *PLOGICAL;

typedef __int64 LONGLONG;
typedef unsigned __int64 ULONGLONG;
typedef LONGLONG *PLONGLONG;
typedef ULONGLONG *PULONGLONG;

typedef union _LARGE_INTEGER {
	struct {
		ULONG LowPart;
		LONG HighPart;
	};
	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef unsigned char BOOLEAN;
typedef BOOLEAN *PBOOLEAN;
typedef unsigned int BOOL;
typedef BOOL *PBOOL;


typedef struct DECLSPEC_ALIGN(16) _M128A
{
	UINT64 Low;
	INT64 High;
} M128A, *PM128A;

typedef struct DECLSPEC_ALIGN(16) _XSAVE_FORMAT
{
	UINT16 ControlWord;
	UINT16 StatusWord;
	UINT8 TagWord;
	UINT8 Reserved1;
	UINT16 ErrorOpcode;
	UINT32 ErrorOffset;
	UINT16 ErrorSelector;
	UINT16 Reserved2;
	UINT32 DataOffset;
	UINT16 DataSelector;
	UINT16 Reserved3;
	UINT32 MxCsr;
	UINT32 MxCsr_Mask;
	M128A FloatRegisters[8];
	M128A XmmRegisters[16];
	UINT8 Reserved4[96];
} XSAVE_FORMAT, *PXSAVE_FORMAT;
typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT
{
	UINT64 P1Home;
	UINT64 P2Home;
	UINT64 P3Home;
	UINT64 P4Home;
	UINT64 P5Home;
	UINT64 P6Home;
	UINT32 ContextFlags;
	UINT32 MxCsr;
	UINT16 SegCs;
	UINT16 SegDs;
	UINT16 SegEs;
	UINT16 SegFs;
	UINT16 SegGs;
	UINT16 SegSs;
	UINT32 EFlags;
	UINT64 Dr0;
	UINT64 Dr1;
	UINT64 Dr2;
	UINT64 Dr3;
	UINT64 Dr6;
	UINT64 Dr7;
	UINT64 Rax;
	UINT64 Rcx;
	UINT64 Rdx;
	UINT64 Rbx;
	UINT64 Rsp;
	UINT64 Rbp;
	UINT64 Rsi;
	UINT64 Rdi;
	UINT64 R8;
	UINT64 R9;
	UINT64 R10;
	UINT64 R11;
	UINT64 R12;
	UINT64 R13;
	UINT64 R14;
	UINT64 R15;
	UINT64 Rip;
	union
	{
		XMM_SAVE_AREA32 FltSave;
		struct
		{
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		};
	};
	M128A VectorRegister[26];
	UINT64 VectorControl;
	UINT64 DebugControl;
	UINT64 LastBranchToRip;
	UINT64 LastBranchFromRip;
	UINT64 LastExceptionToRip;
	UINT64 LastExceptionFromRip;
} CONTEXT, *PCONTEXT;

// Macros and type copied from edk2\MdePkg\Include\Base.h
// We added a __ prefix and suffix to avoid macro/type-redefinitions
#ifndef __INT_SIZE_OF__
#define __INT_SIZE_OF__(n) ((sizeof (n) + sizeof (UINTN) - 1) &~(sizeof (UINTN) - 1))
#endif

typedef char *__VA_LIST__;

#ifndef __VA_START__
#define __VA_START__(Marker, Parameter) \
	(Marker = (__VA_LIST__) ((UINTN) & (Parameter) + __INT_SIZE_OF__ (Parameter)))
#endif

#ifndef __VA_ARG__
#define __VA_ARG__(Marker, TYPE) \
	(*(TYPE *) ((Marker += __INT_SIZE_OF__ (TYPE)) - __INT_SIZE_OF__ (TYPE)))
#endif

#ifndef __VA_END__
#define __VA_END__(Marker) (Marker = (__VA_LIST__) 0)
#endif

#ifndef __VA_COPY__
#define __VA_COPY__(Dest, Start) ((void)((Dest) = (Start)))
#endif

#pragma warning(pop)
#endif /* ifndef WIN32 */
#endif /* __NT_DATA_TYPES_H__ */
