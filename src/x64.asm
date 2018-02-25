;++
; MIT License
;
; Copyright (c) 2017 Viral Security Group
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.
;
; @file		x64.asm
; @section	Define functions that are that perform specific opcodes
;--

.CODE

ASM64_Rdmsr PROC
	push rbx
	
	rdmsr ; rcx = dwMsrCode
	mov rbx, rdx
	shl rbx, 32
	mov ebx, eax ; rbx = edx:eax
	
	mov rax, rbx
	pop rbx
	ret
ASM64_Rdmsr ENDP

ASM64_Wrmsr PROC
	push rax
	push rbx
	
	mov eax, edx ; eax = (UINT32)qwValue
	mov rbx, rdx
	shr rbx, 32 ; ebx = (UINT32)(qwValue >> 32)
	mov edx, ebx ; edx = ebx
	wrmsr ; rcx = dwMsrCode

	pop rbx
	pop rax
	ret
ASM64_Wrmsr ENDP

ASM64_Cpuid PROC
	push rax
	push rbx
	push r9
	
	mov r9, rcx ; r9 = adwRegs
	mov rax, rdx ; rax = dwFunction
	mov rcx, r8 ; rcx = dwSubFunction
	cpuid

	; adwRegs = { EAX, EBX, ECX, EDX }
	mov [r9 + 0], eax
	mov [r9 + 4], ebx
	mov [r9 + 8], ecx
	mov [r9 + 12], edx

	pop r9
	pop rbx
	pop rax
	ret
ASM64_Cpuid ENDP

ASM64_ReadCr0 PROC
	mov rax, cr0
	ret
ASM64_ReadCr0 ENDP

ASM64_ReadCr3 PROC
	mov rax, cr3
	ret
ASM64_ReadCr3 ENDP

ASM64_ReadCr4 PROC
	mov rax, cr4
	ret
ASM64_ReadCr4 ENDP

ASM64_ReadCr8 PROC
	mov rax, cr8
	ret
ASM64_ReadCr8 ENDP

ASM64_Lgdt PROC
	lgdt fword ptr [rcx]
	ret
ASM64_Lgdt ENDP

ASM64_Sgdt PROC
	sgdt fword ptr [rcx]
	ret
ASM64_Sgdt ENDP

ASM64_Lidt PROC
	lidt fword ptr [rcx]
	ret
ASM64_Lidt ENDP

ASM64_Sidt PROC
	sidt fword ptr [rcx]
	ret
ASM64_Sidt ENDP

END
