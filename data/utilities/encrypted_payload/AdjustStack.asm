/*
 * This code is provided under the 3-clause BSD license below.
 * ***********************************************************
 *
 * Copyright (c) 2013, Matthew Graeber
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *   Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *   The names of its contributors may not be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

; Author:       Matthew Graeber (@mattifestation)
; License:      BSD 3-Clause
; Syntax:       MASM
; Build Syntax: ml64 /c /Cx AdjustStack.asm
; Output:       AdjustStack.obj
; Notes: I really wanted to avoid having this external dependency but I couldnt
; come up with any other way to guarantee 16-byte stack alignment in 64-bit
; shellcode written in C.

extern	ExecutePayload
global  AlignRSP			; Marking AlignRSP as PUBLIC allows for the function
							; to be called as an extern in our C code.

segment .text

; AlignRSP is a simple call stub that ensures that the stack is 16-byte aligned prior
; to calling the entry point of the payload. This is necessary because 64-bit functions
; in Windows assume that they were called with 16-byte stack alignment. When amd64
; shellcode is executed, you cant be assured that you stack is 16-byte aligned. For example,
; if your shellcode lands with 8-byte stack alignment, any call to a Win32 function will likely
; crash upon calling any ASM instruction that utilizes XMM registers (which require 16-byte)
; alignment.

AlignRSP:
	push	rsi						; Preserve RSI since were stomping on it
	mov		rsi, rsp				; Save the value of RSP so it can be restored
	and		rsp, 0FFFFFFFFFFFFFFF0h	; Align RSP to 16 bytes
	sub		rsp, 020h				; Allocate homing space for ExecutePayload
	call	ExecutePayload			; Call the entry point of the payload
	mov		rsp, rsi				; Restore the original value of RSP
	pop		rsi						; Restore RSI
	ret								; Return to caller
