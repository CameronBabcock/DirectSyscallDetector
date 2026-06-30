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

EXTERN g_DsdCallbackArmed:DWORD
EXTERN g_DsdCallbackCount:QWORD
EXTERN g_DsdCapturedCount:QWORD
EXTERN g_DsdDroppedCount:QWORD
EXTERN g_DsdTargetThreadId:QWORD
EXTERN g_DsdCallbackSlots:QWORD

EXTERN g_DsdNtAllocateVirtualMemorySyscall:DWORD
EXTERN g_DsdNtProtectVirtualMemorySyscall:DWORD
EXTERN g_DsdGadgetSyscallInstruction:QWORD

PUBLIC DsdInstrumentationCallbackThunk
PUBLIC DsdDirectNtAllocateVirtualMemory
PUBLIC DsdDirectNtProtectVirtualMemory
PUBLIC DsdGadgetNtProtectVirtualMemory

.code

CallbackSlotCount EQU 16
CallbackSlotSize EQU 64
CallbackSlotStateOffset EQU 0
CallbackSlotThreadIdOffset EQU 8
CallbackSlotPreviousPcOffset EQU 16
CallbackSlotStackPointerOffset EQU 24
CallbackSlotStackArg5Offset EQU 32
CallbackSlotStackArg6Offset EQU 40
CallbackSlotWriting EQU 1
CallbackSlotReady EQU 2

DsdDirectNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [g_DsdNtAllocateVirtualMemorySyscall]
    syscall
    ret
DsdDirectNtAllocateVirtualMemory ENDP

DsdDirectNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [g_DsdNtProtectVirtualMemorySyscall]
    syscall
    ret
DsdDirectNtProtectVirtualMemory ENDP

DsdGadgetNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [g_DsdNtProtectVirtualMemorySyscall]
    mov r11, qword ptr [g_DsdGadgetSyscallInstruction]
    jmp r11
DsdGadgetNtProtectVirtualMemory ENDP

; Process instrumentation callbacks run on the returning syscall thread. Keep
; this thunk leaf-like: capture volatile evidence, wait for the monitor, and
; jump back to the previous PC supplied by the kernel in r10.
DsdInstrumentationCallbackThunk PROC
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

    lock inc qword ptr [g_DsdCallbackCount]

    cmp dword ptr [g_DsdCallbackArmed], 0
    je return_to_previous_pc

    mov rax, qword ptr gs:[48h]
    mov r11, qword ptr [g_DsdTargetThreadId]
    test r11, r11
    je find_callback_slot
    cmp rax, r11
    jne return_to_previous_pc

find_callback_slot:
    xor r12d, r12d

try_callback_slot:
    cmp r12d, CallbackSlotCount
    jae no_callback_slot

    mov rbx, OFFSET g_DsdCallbackSlots
    mov rax, r12
    shl rax, 6
    add rbx, rax

    xor eax, eax
    mov ecx, CallbackSlotWriting
    lock cmpxchg dword ptr [rbx+CallbackSlotStateOffset], ecx
    je capture_callback_slot

    inc r12d
    jmp try_callback_slot

no_callback_slot:
    lock inc qword ptr [g_DsdDroppedCount]
    jmp return_to_previous_pc

capture_callback_slot:
    lock inc qword ptr [g_DsdCapturedCount]

    mov rax, qword ptr gs:[48h]
    mov qword ptr [rbx+CallbackSlotThreadIdOffset], rax

    ; Saved r10 is the syscall return PC. Matching this address against the
    ; live ntdll/win32u catalog distinguishes normal stubs from raw/gadget use.
    mov rax, qword ptr [rsp+40]
    mov qword ptr [rbx+CallbackSlotPreviousPcOffset], rax

    ; Reconstruct the original user stack pointer after our save frame. On
    ; Windows x64, arguments five and six live after the four register slots.
    lea r11, qword ptr [rsp+128]
    mov qword ptr [rbx+CallbackSlotStackPointerOffset], r11

    mov rax, qword ptr [r11+28h]
    mov qword ptr [rbx+CallbackSlotStackArg5Offset], rax

    mov rax, qword ptr [r11+30h]
    mov qword ptr [rbx+CallbackSlotStackArg6Offset], rax

    mov eax, CallbackSlotReady
    xchg dword ptr [rbx+CallbackSlotStateOffset], eax

wait_for_monitor_clear:
    pause
    cmp dword ptr [rbx+CallbackSlotStateOffset], 0
    jne wait_for_monitor_clear

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
DsdInstrumentationCallbackThunk ENDP

END
