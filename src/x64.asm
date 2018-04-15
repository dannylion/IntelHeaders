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
; @section	Define functions that perform specific opcodes in assembly
;--

.CODE

; VOID
; __stdcall
; LOCK_SpinlockAcquire(
; 	IN PSPINLOCK ptLock
; );
LOCK_SpinlockAcquire PROC
	push rax
	push rbx
	mov rbx, 1

l_spin:
	xor rax, rax
	cmpxchg byte ptr [rcx], bl
	pause
	jnz l_spin

	pop rbx
	pop rax
	ret
LOCK_SpinlockAcquire ENDP

; VOID
; __stdcall
; LOCK_SpinlockRelease(
; 	IN PSPINLOCK ptLock
; );
LOCK_SpinlockRelease PROC
	mov byte ptr [rcx], 0
	ret
LOCK_SpinlockRelease ENDP

; UINT64
; __stdcall
; ASM64_Rdmsr(
; 	IN const UINT32 dwMsrCode
; );
ASM64_Rdmsr PROC
	push rbx
	
	rdmsr ; rcx = dwMsrCode
	mov rbx, rdx
	shl rbx, 32
	add rbx, rax ; rbx = edx:eax
	
	mov rax, rbx
	pop rbx
	ret
ASM64_Rdmsr ENDP

; VOID
; __stdcall
; ASM64_Wrmsr(
; 	IN const UINT32 dwMsrCode,
; 	IN const UINT64 qwValue
; );
ASM64_Wrmsr PROC
	push rax
	
	mov eax, edx ; eax = (UINT32)qwValue
	shr rdx, 32
	wrmsr ; rcx = dwMsrCode, edx:eax = qwValue

	pop rax
	ret
ASM64_Wrmsr ENDP

; VOID
; __stdcall
; ASM64_Cpuid(
; 	OUT UINT32 adwRegs[4],
; 	IN const UINT32 dwFunction,
; 	IN const UINT32 dwSubFunction
; );
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

; UINT64
; __stdcall
; ASM64_ReadCr0(
; 	VOID
; );
ASM64_ReadCr0 PROC
	mov rax, cr0
	ret
ASM64_ReadCr0 ENDP

; UINT64
; __stdcall
; ASM64_ReadCr2(
; 	VOID
; );
ASM64_ReadCr2 PROC
	mov rax, cr2
	ret
ASM64_ReadCr2 ENDP

; UINT64
; __stdcall
; ASM64_ReadCr3(
; 	VOID
; );
ASM64_ReadCr3 PROC
	mov rax, cr3
	ret
ASM64_ReadCr3 ENDP

; UINT64
; __stdcall
; ASM64_ReadCr4(
; 	VOID
; );
ASM64_ReadCr4 PROC
	mov rax, cr4
	ret
ASM64_ReadCr4 ENDP

; UINT64
; __stdcall
; ASM64_ReadCr8(
; 	VOID
; );
ASM64_ReadCr8 PROC
	mov rax, cr8
	ret
ASM64_ReadCr8 ENDP

; UINT64
; __stdcall
; ASM64_ReadRflags(
; 	VOID
; );
ASM64_ReadRflags PROC
	pushfq
	mov rax, [rsp]
	popfq
	ret
ASM64_ReadRflags ENDP

; VOID
; __stdcall
; ASM64_WriteRflags(
; 	IN const UINT64 qwValue
; );
ASM64_WriteRflags PROC
	push rcx
	popfq
	ret
ASM64_WriteRflags ENDP

; VOID
; __stdcall
; ASM64_Lgdt(
; 	IN const PUINT64 pqwValue
; );
ASM64_Lgdt PROC
	lgdt fword ptr [rcx]
	ret
ASM64_Lgdt ENDP

; VOID
; __stdcall
; ASM64_Sgdt(
; 	OUT PUINT64 pqwValue
; );
ASM64_Sgdt PROC
	sgdt fword ptr [rcx]
	ret
ASM64_Sgdt ENDP

; VOID
; __stdcall
; ASM64_Lidt(
; 	IN const PUINT64 pqwValue
; );
ASM64_Lidt PROC
	lidt fword ptr [rcx]
	ret
ASM64_Lidt ENDP

; VOID
; __stdcall
; ASM64_Sidt(
; 	OUT PUINT64 pqwValue
; );
ASM64_Sidt PROC
	sidt fword ptr [rcx]
	ret
ASM64_Sidt ENDP

; VOID
; __stdcall
; ASM64_Lldt(
; 	IN const PUINT16 pwValue
; );
ASM64_Lldt PROC
	lldt word ptr [rcx]
	ret
ASM64_Lldt ENDP

; UINT16
; __stdcall
; ASM64_Sldt(
; 	VOID
; );
ASM64_Sldt PROC
	sldt ax
	ret
ASM64_Sldt ENDP

; UINT16
; __stdcall
; ASM64_Ltr(
; 	IN const UINT16 wValue
; );
ASM64_Ltr PROC
	ltr cx
	ret
ASM64_Ltr ENDP

; UINT16
; __stdcall
; ASM64_Str(
; 	VOID
; );
ASM64_Str PROC
	str ax
	ret
ASM64_Str ENDP

; VOID
; __stdcall
; ASM64_WriteCr0(
; 	IN const UINT64 qwValue
; );
ASM64_WriteCr0 PROC
	mov cr0, rcx
	ret
ASM64_WriteCr0 ENDP

; VOID
; __stdcall
; ASM64_WriteCr2(
; 	IN const UINT64 qwValue
; );
ASM64_WriteCr2 PROC
	mov cr2, rcx
	ret
ASM64_WriteCr2 ENDP

; VOID
; __stdcall
; ASM64_WriteCr3(
; 	IN const UINT64 qwValue
; );
ASM64_WriteCr3 PROC
	mov cr3, rcx
	ret
ASM64_WriteCr3 ENDP

; VOID
; __stdcall
; ASM64_WriteCr4(
; 	IN const UINT64 qwValue
; );
ASM64_WriteCr4 PROC
	mov cr4, rcx
	ret
ASM64_WriteCr4 ENDP

; VOID
; __stdcall
; ASM64_WriteCr8(
; 	IN const UINT64 qwValue
; );
ASM64_WriteCr8 PROC
	mov cr8, rcx
	ret
ASM64_WriteCr8 ENDP

; VOID
; __stdcall
; ASM64_WriteCS(
; 	IN const UINT16 wValue
; );
ASM64_WriteCS PROC
	mov cs, cx
	ret
ASM64_WriteCS ENDP

; VOID
; __stdcall
; ASM64_WriteSS(
; 	IN const UINT16 wValue
; );
ASM64_WriteSS PROC
	mov ss, cx
	ret
ASM64_WriteSS ENDP

; VOID
; __stdcall
; ASM64_WriteDS(
; 	IN const UINT16 wValue
; );
ASM64_WriteDS PROC
	mov ds, cx
	ret
ASM64_WriteDS ENDP

; VOID
; __stdcall
; ASM64_WriteES(
; 	IN const UINT16 wValue
; );
ASM64_WriteES PROC
	mov es, cx
	ret
ASM64_WriteES ENDP

; VOID
; __stdcall
; ASM64_WriteFS(
; 	IN const UINT16 wValue
; );
ASM64_WriteFS PROC
	mov fs, cx
	ret
ASM64_WriteFS ENDP

; VOID
; __stdcall
; ASM64_WriteGS(
; 	IN const UINT16 wValue
; );
ASM64_WriteGS PROC
	mov gs, cx
	ret
ASM64_WriteGS ENDP

; UINT16
; __stdcall
; ASM64_ReadCS(
; 	VOID
; );
ASM64_ReadCS PROC
	mov ax, cs
	ret
ASM64_ReadCS ENDP

; UINT16
; __stdcall
; ASM64_ReadSS(
; 	VOID
; );
ASM64_ReadSS PROC
	mov ax, ss
	ret
ASM64_ReadSS ENDP

; UINT16
; __stdcall
; ASM64_ReadDS(
; 	VOID
; );
ASM64_ReadDS PROC
	mov ax, ds
	ret
ASM64_ReadDS ENDP

; UINT16
; __stdcall
; ASM64_ReadES(
; 	VOID
; );
ASM64_ReadES PROC
	mov ax, es
	ret
ASM64_ReadES ENDP

; UINT16
; __stdcall
; ASM64_ReadFS(
; 	VOID
; );
ASM64_ReadFS PROC
	mov ax, fs
	ret
ASM64_ReadFS ENDP

; UINT16
; __stdcall
; ASM64_ReadGS(
; 	VOID
; );
ASM64_ReadGS PROC
	mov ax, gs
	ret
ASM64_ReadGS ENDP

; BOOLEAN
; __stdcall
; ASM64_ReadSegmentLimit(
; 	IN const UINT16 wSegmentSelector,
; 	OUT PUINT32 pdwSegmentLimit
; );
ASM64_ReadSegmentLimit PROC
	and ecx, 0FFFFh
	lsl ecx, ecx
	jz l_success
	xor rax, rax
	ret
l_success:
	mov dword ptr [rdx], ecx
	mov rax, 1
	ret
ASM64_ReadSegmentLimit ENDP

; UINT64
; __stdcall
; ASM64_ReadDr0(
; 	VOID
; );
ASM64_ReadDr0 PROC
	mov rax, dr0
	ret
ASM64_ReadDr0 ENDP

; UINT64
; __stdcall
; ASM64_ReadDr1(
; 	VOID
; );
ASM64_ReadDr1 PROC
	mov rax, dr1
	ret
ASM64_ReadDr1 ENDP

; UINT64
; __stdcall
; ASM64_ReadDr2(
; 	VOID
; );
ASM64_ReadDr2 PROC
	mov rax, dr2
	ret
ASM64_ReadDr2 ENDP

; UINT64
; __stdcall
; ASM64_ReadDr3(
; 	VOID
; );
ASM64_ReadDr3 PROC
	mov rax, dr3
	ret
ASM64_ReadDr3 ENDP

; UINT64
; __stdcall
; ASM64_ReadDr6(
; 	VOID
; );
ASM64_ReadDr6 PROC
	mov rax, dr0
	ret
ASM64_ReadDr6 ENDP

; UINT64
; __stdcall
; ASM64_ReadDr7(
; 	VOID
; );
ASM64_ReadDr7 PROC
	mov rax, dr7
	ret
ASM64_ReadDr7 ENDP

; VOID
; __stdcall
; ASM64_WriteDr0(
; 	IN const UINT64 qwValue
; );
ASM64_WriteDr0 PROC
	mov dr0, rcx
	ret
ASM64_WriteDr0 ENDP

; VOID
; __stdcall
; ASM64_WriteDr1(
; 	IN const UINT64 qwValue
; );
ASM64_WriteDr1 PROC
	mov dr1, rcx
	ret
ASM64_WriteDr1 ENDP

; VOID
; __stdcall
; ASM64_WriteDr2(
; 	IN const UINT64 qwValue
; );
ASM64_WriteDr2 PROC
	mov dr2, rcx
	ret
ASM64_WriteDr2 ENDP

; VOID
; __stdcall
; ASM64_WriteDr3(
; 	IN const UINT64 qwValue
; );
ASM64_WriteDr3 PROC
	mov dr3, rcx
	ret
ASM64_WriteDr3 ENDP

; VOID
; __stdcall
; ASM64_WriteDr6(
; 	IN const UINT64 qwValue
; );
ASM64_WriteDr6 PROC
	mov dr6, rcx
	ret
ASM64_WriteDr6 ENDP

; VOID
; __stdcall
; ASM64_WriteDr7(
; 	IN const UINT64 qwValue
; );
ASM64_WriteDr7 PROC
	mov dr7, rcx
	ret
ASM64_WriteDr7 ENDP

; UINT64
; __stdcall
; ASM64_Lar(
; 	IN const UINT16 wSegmentSelector
; );
ASM64_Lar PROC
	lar rax, rcx
	ret
ASM64_Lar ENDP

; UINT8
; __stdcall
; ASM64_IoReadByte(
; 	IN const UINT16 wIoPort
; );
ASM64_IoReadByte PROC
	push rdx
	mov dx, cx
	in al, dx
	pop rdx
	ret
ASM64_IoReadByte ENDP

; UINT16
; __stdcall
; ASM64_IoReadWord(
; 	IN const UINT16 wIoPort
; );
ASM64_IoReadWord PROC
	push rdx
	mov dx, cx
	in ax, dx
	pop rdx
	ret
ASM64_IoReadWord ENDP

; UINT32
; __stdcall
; ASM64_IoReadDword(
; 	IN const UINT16 wIoPort
; );
ASM64_IoReadDword PROC
	push rdx
	mov dx, cx
	in eax, dx
	pop rdx
	ret
ASM64_IoReadDword ENDP

; VOID
; __stdcall
; ASM64_IoWriteByte(
; 	IN const UINT8 cValue,
; 	IN const UINT16 wIoPort
; );
ASM64_IoWriteByte PROC
	push rax
	mov rax, rcx
	out dx, al
	pop rax
	ret
ASM64_IoWriteByte ENDP

; VOID
; __stdcall
; ASM64_IoWriteWord(
; 	IN const UINT16 wValue,
; 	IN const UINT16 wIoPort
; );
ASM64_IoWriteWord PROC
	push rax
	mov rax, rcx
	out dx, ax
	pop rax
	ret
ASM64_IoWriteWord ENDP

; VOID
; __stdcall
; ASM64_IoWriteDword(
; 	IN const UINT32 dwValue,
; 	IN const UINT16 wIoPort
; );
ASM64_IoWriteDword PROC
	push rax
	mov rax, rcx
	out dx, eax
	pop rax
	ret
ASM64_IoWriteDword ENDP

; VOID
; __stdcall
; ASM64_Invd(
; 	VOID
; );
ASM64_Invd PROC
	invd
	ret
ASM64_Invd ENDP

; VOID
; __stdcall
; ASM64_Wbinvd(
; 	VOID
; );
ASM64_Wbinvd PROC
	wbinvd
	ret
ASM64_Wbinvd ENDP

; VTX_RC
; __stdcall
; ASM64_Invept(
; 	IN const UINT32 dwInveptType, 
; 	IN const ULONG_PTR qwInveptDescriptor
; );
ASM64_Invept PROC
	; invept  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 80h, 0ah

	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Invept ENDP

; VTX_RC
; __stdcall
; ASM64_Invvpid(
; 	IN const UINT32 dwInvVpidType,
; 	IN const ULONG_PTR qwInvVpidDescriptor
; );
ASM64_Invvpid PROC
	; invvpid  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 81h, 0ah

	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Invvpid ENDP

; VTX_RC
; __stdcall
; ASM64_Vmcall(
; 	IN const UINT32 dwHypercallNumber,
; 	IN PVOID ptContext
; );
ASM64_Vmcall PROC
	vmcall
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmcall ENDP

; VTX_RC
; __stdcall
; ASM64_Vmclear(
; 	IN const UINT64 qwVmcsPhysicalAddress
; );
ASM64_Vmclear PROC
	vmclear qword ptr [rcx]
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmclear ENDP

; VTX_RC
; __stdcall
; ASM64_Vmfunc(
; 	IN const UINT32 dwVmFuncNumber
; );
ASM64_Vmfunc PROC
	mov eax, ecx
	db  0fh, 01h, 212, 0ah	; vmfunc
	jz l_VtxFailValid		; if (ZF) jmp
    jc l_VtxFailInvalid		; if (CF) jmp
    xor rax, rax			; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmfunc ENDP

; DECLSPEC_NORETURN
; VTX_RC
; __stdcall
; ASM64_Vmlaunch(
; 	VOID
; );
ASM64_Vmlaunch PROC
	vmlaunch
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmlaunch ENDP

; DECLSPEC_NORETURN
; VTX_RC
; __stdcall
; ASM64_Vmresume(
; 	VOID
; );
ASM64_Vmresume PROC
	vmresume
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmresume ENDP

; VTX_RC
; __stdcall
; ASM64_Vmptrld(
; 	IN const PUINT64 pqwVmcsPhysicalAddress
; );
ASM64_Vmptrld PROC
	vmptrld qword ptr [rcx]
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmptrld ENDP

; VTX_RC
; __stdcall
; ASM64_Vmptrst(
; 	OUT PUINT64 pqwVmcsPhysicalAddress
; );
ASM64_Vmptrst PROC
	vmptrst qword ptr [rcx]
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmptrst ENDP

; VTX_RC
; __stdcall
; ASM64_Vmread(
; 	IN const ULONG_PTR ulVmcsField,
; 	OUT PUINT64 pqwValue
; );
ASM64_Vmread PROC
	vmread qword ptr [rdx], rcx
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmread ENDP

; VTX_RC
; __stdcall
; ASM64_Vmwrite(
; 	IN const ULONG_PTR ulVmcsField,
; 	IN const UINT64 qwValue
; );
ASM64_Vmwrite PROC
	vmwrite rcx, rdx
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmwrite ENDP

; VTX_RC
; __stdcall
; ASM64_Vmxoff(
; 	VOID
; );
ASM64_Vmxoff PROC
	vmxoff
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmxoff ENDP

; VTX_RC
; __stdcall
; ASM64_Vmxon(
; 	IN const PUINT64 pqwVmxonRegionPhysicalAddress
; );
ASM64_Vmxon PROC
	vmxon qword ptr [rcx]
	jz l_VtxFailValid	; if (ZF) jmp
    jc l_VtxFailInvalid	; if (CF) jmp
    xor rax, rax		; return VTX_SUCCESS
	ret
    
l_VtxFailInvalid:
    mov rax, 2 ; return VTX_FAIL_INVALID
    ret

l_VtxFailValid:
    mov rax, 1 ; return VTX_FAIL_VALID
	ret
ASM64_Vmxon ENDP

; VOID
; __stdcall
; ASM64_CaptureContext(
; 	OUT PCONTEXT ptContext
; );
ASM64_CaptureContext PROC
    pushfq
    mov     [rcx+78h], rax
    mov     [rcx+80h], rcx
    mov     [rcx+88h], rdx
    mov     [rcx+0B8h], r8
    mov     [rcx+0C0h], r9
    mov     [rcx+0C8h], r10
    mov     [rcx+0D0h], r11

    mov     word ptr [rcx+38h], cs
    mov     word ptr [rcx+3Ah], ds
    mov     word ptr [rcx+3Ch], es
    mov     word ptr [rcx+42h], ss
    mov     word ptr [rcx+3Eh], fs
    mov     word ptr [rcx+40h], gs

    mov     [rcx+90h], rbx
    mov     [rcx+0A0h], rbp
    mov     [rcx+0A8h], rsi
    mov     [rcx+0B0h], rdi
    mov     [rcx+0D8h], r12
    mov     [rcx+0E0h], r13
    mov     [rcx+0E8h], r14
    mov     [rcx+0F0h], r15

    lea     rax, [rsp+10h]
    mov     [rcx+98h], rax
    mov     rax, [rsp+8]
    mov     [rcx+0F8h], rax
    mov     eax, [rsp]
    mov     [rcx+44h], eax

    add     rsp, 8
    ret
ASM64_CaptureContext ENDP

; DECLSPEC_NORETURN
; VOID
; __cdecl
; ASM64_RestoreContext(
; 	IN const PCONTEXT ptContext
; );
ASM64_RestoreContext PROC
    mov     ax, [rcx+42h]
    mov     [rsp+20h], ax	; ss selector
    mov     rax, [rcx+98h]
    mov     [rsp+18h], rax	; rsp
    mov     eax, [rcx+44h]
    mov     [rsp+10h], eax	; rflags
    mov     ax, [rcx+38h]
    mov     [rsp+8], ax		; cs selector
    mov     rax, [rcx+0F8h]
    mov     [rsp], rax		; rip

    mov     rax, [rcx+78h]
    mov     rdx, [rcx+88h]
    mov     r8, [rcx+0B8h]
    mov     r9, [rcx+0C0h]
    mov     r10, [rcx+0C8h]
    mov     r11, [rcx+0D0h]
    cli

    mov     rbx, [rcx+90h]
    mov     rsi, [rcx+0A8h]
    mov     rdi, [rcx+0B0h]
    mov     rbp, [rcx+0A0h]
    mov     r12, [rcx+0D8h]
    mov     r13, [rcx+0E0h]
    mov     r14, [rcx+0E8h]
    mov     r15, [rcx+0F0h]
    mov     rcx, [rcx+80h]

    iretq					; pop rip, cs, rflags, rsp, ss in that order
ASM64_RestoreContext ENDP

; DECLSPEC_NORETURN
; VTX_RC
; __cdecl
; ShvAsmVmresume(
; 	IN const PCONTEXT ptContext
; );
ASM64_RestoreContextAndVmresume PROC
	mov     rax, [rcx+78h]
    mov     rdx, [rcx+88h]
    mov     r8, [rcx+0B8h]
    mov     r9, [rcx+0C0h]
    mov     r10, [rcx+0C8h]
    mov     r11, [rcx+0D0h]
    mov     rbx, [rcx+90h]
    mov     rsi, [rcx+0A8h]
    mov     rdi, [rcx+0B0h]
    mov     rbp, [rcx+0A0h]
    mov     r12, [rcx+0D8h]
    mov     r13, [rcx+0E0h]
    mov     r14, [rcx+0E8h]
    mov     r15, [rcx+0F0h]
    mov     rcx, [rcx+80h]
	vmresume
	ret
ASM64_RestoreContextAndVmresume ENDP

END
