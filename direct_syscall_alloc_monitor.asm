; Nirvana v2: Electric Boogaloo
; Return-provenance detection for raw and gadgeted direct syscalls.
;
; Project: DirectSyscallDetector
; Copyright 2026 Cameron Babcock
;
; Author / Researcher: Cameron Babcock
; GitHub: https://github.com/CameronBabcock
; Email: Cameron@CameronBabcock.net
; LinkedIn: https://www.linkedin.com/in/cameronbabcock/
;
; Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
; For EDR, CNO, pentest agent work, endpoint security, Windows internals,
; or detection engineering work,
; please contact Cameron Babcock using the email or LinkedIn profile above.

OPTION PROLOGUE:NONE, EPILOGUE:NONE

EXTERN g_AllocSyscallNumber:DWORD
EXTERN g_AllocCbReady:DWORD
EXTERN g_AllocCbAck:DWORD
EXTERN g_AllocCbCount:QWORD
EXTERN g_AllocCbDirectHits:QWORD
EXTERN g_AllocCbPrevPc:QWORD
EXTERN g_AllocCbRax:QWORD
EXTERN g_AllocCbRcx:QWORD
EXTERN g_AllocCbRdx:QWORD
EXTERN g_AllocCbR8:QWORD
EXTERN g_AllocCbR9:QWORD
EXTERN g_AllocCbRsp:QWORD
EXTERN g_AllocCbStackArg5:QWORD
EXTERN g_AllocCbStackArg6:QWORD
EXTERN g_AllocCbBaseValue:QWORD
EXTERN g_AllocCbRegionValue:QWORD
EXTERN g_AllocCbDecodedSyscall:DWORD
EXTERN g_AllocCbHome1:QWORD
EXTERN g_AllocCbHome2:QWORD
EXTERN g_AllocCbHome3:QWORD
EXTERN g_AllocCbHome4:QWORD

PUBLIC AllocPicCallbackThunk
PUBLIC DirectNtAllocateVirtualMemory
PUBLIC DirectNtAllocateVirtualMemoryReturn

.code

DirectNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [g_AllocSyscallNumber]
    syscall
DirectNtAllocateVirtualMemoryReturn::
    ret
DirectNtAllocateVirtualMemory ENDP

AllocPicCallbackThunk PROC
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    lock inc qword ptr [g_AllocCbCount]

    mov rax, qword ptr [rsp+40]
    mov r11, OFFSET DirectNtAllocateVirtualMemoryReturn
    cmp rax, r11
    jne return_to_previous_pc

    lock inc qword ptr [g_AllocCbDirectHits]

    mov qword ptr [g_AllocCbPrevPc], rax

    xor eax, eax
    mov r11, qword ptr [rsp+40]
    cmp byte ptr [r11-8], 08Bh
    jne syscall_decode_done
    cmp byte ptr [r11-7], 05h
    jne syscall_decode_done
    movsxd rax, dword ptr [r11-6]
    lea r10, qword ptr [r11-2]
    add r10, rax
    mov eax, dword ptr [r10]
syscall_decode_done:
    mov dword ptr [g_AllocCbDecodedSyscall], eax

    mov rax, qword ptr [rsp+112]
    mov qword ptr [g_AllocCbRax], rax

    mov rax, qword ptr [rsp+104]
    mov qword ptr [g_AllocCbRcx], rax

    mov rax, qword ptr [rsp+96]
    mov qword ptr [g_AllocCbRdx], rax
    xor rax, rax
    mov qword ptr [g_AllocCbBaseValue], rax

    mov rax, qword ptr [rsp+56]
    mov qword ptr [g_AllocCbR8], rax

    mov rax, qword ptr [rsp+48]
    mov qword ptr [g_AllocCbR9], rax
    xor rax, rax
    mov qword ptr [g_AllocCbRegionValue], rax

    lea r11, qword ptr [rsp+128]
    mov qword ptr [g_AllocCbRsp], r11

    mov rax, qword ptr [r11+8]
    mov qword ptr [g_AllocCbHome1], rax

    mov rax, qword ptr [r11+10h]
    mov qword ptr [g_AllocCbHome2], rax

    mov rax, qword ptr [r11+18h]
    mov qword ptr [g_AllocCbHome3], rax

    mov rax, qword ptr [r11+20h]
    mov qword ptr [g_AllocCbHome4], rax

    mov rax, qword ptr [r11+28h]
    mov qword ptr [g_AllocCbStackArg5], rax

    mov rax, qword ptr [r11+30h]
    mov qword ptr [g_AllocCbStackArg6], rax

    mov dword ptr [g_AllocCbReady], 1

wait_for_monitor_ack:
    pause
    cmp dword ptr [g_AllocCbAck], 0
    je wait_for_monitor_ack

return_to_previous_pc:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq
    mov r11, r10
    jmp r11
AllocPicCallbackThunk ENDP

END
