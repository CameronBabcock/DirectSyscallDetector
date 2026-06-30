# Nirvana v2: Electric Boogaloo

Return-provenance detection for raw and gadgeted direct syscalls.

## ProcessInstrumentationCallback on x64: Kernel Handoff, Syscall Metadata, and Direct Syscall Recovery

## TL;DR

`ProcessInstrumentationCallback` is not set with `NtSetInformationSystem`; the relevant path is `NtSetInformationProcess(ProcessInstrumentationCallback)`. On the tested Windows 26100 x64 target, the information class is `0x28` / decimal `40`.

The most important x64 finding is that the kernel does preserve the original user control-flow target, but not in `RAX`. The observed kernel path copies the trap-frame `Rip` into trap-frame `R10`, then overwrites trap-frame `Rip` with the process instrumentation callback pointer. At callback entry:

```text
RIP = callback
R10 = previous user PC
RSP = original user RSP
RAX = syscall/exception return value or whatever the trap frame already held
```

That means a correct callback must start in assembly, save registers immediately, treat `R10` as the previous PC, and return with `jmp saved_r10`.

For syscall metadata, the kernel keeps per-thread fields:

```text
_KTHREAD+0x080 SystemCallNumber
_KTHREAD+0x088 FirstArgument
_KTHREAD+0x090 TrapFrame
```

`NtQueryInformationThread(ThreadLastSystemCall)` exposes `SystemCallNumber` and `FirstArgument` through `PspQueryLastCallThread`, but not for the current thread and only when the target is in a narrow waiting/user-mode state. It is useful for cross-thread observation of a blocked syscall. It is not a same-thread in-callback escape hatch.

For a direct `NtAllocateVirtualMemory` syscall, the callback could recover:

- previous PC, from callback-entry `R10`;
- syscall number, by decoding the direct syscall stub bytes before the previous PC;
- stack arguments 5 and 6, from the saved user stack;
- syscall return status, from `RAX`.

It could not recover the first four syscall arguments from callback-entry volatile registers on this tested path. `RCX`, `RDX`, `R8`, and `R9` were not the original user syscall arguments by the time the callback ran.

## Test Environment

Target:

```text
Windows 10 Kernel Version 26100 MP (4 procs) Free x64
Edition build lab: 26100.1.amd64fre.ge_release.240331-1435
Kernel base = 0xfffff803`b6c00000
```

Symbols:

```text
ntkrnlmp.pdb
GUID: 11D7FE79-CC24-5612-0555-03EE86BB0E3E
Symbol path: SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
```

Kernel image:

```text
Image name: ntkrnlmp.exe
Timestamp: 90B083DA
CheckSum: 00C74D68
ImageSize: 01450000
```

The host `C:\Windows\System32\ntoskrnl.exe` matched the live kernel timestamp, checksum, and image size, and was copied to:

```text
C:\Users\analyst\Documents\Kernel Research\ntoskrnl_26100_90b083da_c74d68.exe
```

IDA opened it as session `ntoskrnl_26100_pic`.

## Relevant Kernel Types and Symbols

WinDbg symbol discovery:

```text
x nt!*Instrumentation*
fffff803`b7047af0 nt!KiSetupForInstrumentationReturn

x nt!*SetInformationProcess*
fffff803`b74eca90 nt!NtSetInformationProcess
fffff803`b72a4f30 nt!ZwSetInformationProcess
```

Important offsets:

```text
dt nt!_KPROCESS Instrumentation*
+0x168 InstrumentationCallback : Ptr64 Void
```

```text
dt nt!_KTRAP_FRAME Rip Rsp Rax Rcx R10 R11 SegCs EFlags
+0x030 Rax
+0x038 Rcx
+0x058 R10
+0x060 R11
+0x168 Rip
+0x170 SegCs
+0x178 EFlags
+0x180 Rsp
```

```text
dt nt!_TEB Instrumentation*
+0x2d0 InstrumentationCallbackSp
+0x2d8 InstrumentationCallbackPreviousPc
+0x2e0 InstrumentationCallbackPreviousSp
+0x2ec InstrumentationCallbackDisabled
+0x16b8 Instrumentation : [11] Ptr64 Void
```

The TEB fields exist, but in the observed 26100 x64 path they were not the source of the previous PC. The previous PC was in trap-frame `R10`.

## Setting the Callback

IDA found `NtSetInformationProcess` at:

```text
IDA:  0x1408eca90
Live: nt+0x8eca90
```

The switch case for `ProcessInstrumentationCallback` is case `40`:

```text
ProcessInstrumentationCallback = 0x28
```

The case accepts two input buffer shapes on this build:

```c
// 8-byte shape
PVOID Callback;
```

```c
// 16-byte shape
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;   // 0 in tested x64 path
    ULONG Reserved;  // 0
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;
```

IDA showed the length and parse logic:

```asm
lea eax, [r13-8]
test eax, 0FFFFFFF7h
jnz STATUS_INFO_LENGTH_MISMATCH
cmp r13d, 8
jz short raw_pointer_shape
movups xmm0, xmmword ptr [r15]
psrldq xmm0, 8
movq rcx, xmm0         ; callback from struct+8
...
raw_pointer_shape:
mov rcx, [r15]         ; callback from 8-byte buffer
```

The callback pointer is validated:

```asm
call MmValidateUserCallTarget
```

The successful store path takes the process lock and writes `_KPROCESS.InstrumentationCallback`:

```asm
loc_1408EEDB3:
call PspLockProcessExclusive
mov rax, [rsp+Object]
mov [rax+168h], r15   ; _KPROCESS.InstrumentationCallback
...
test r15, r15
jz clear_thread_bit
lock bts dword ptr [rcx-578h], 19h
...
clear_thread_bit:
lock btr dword ptr [rcx-578h], 19h
```

Live breakpoint proof at `nt!NtSetInformationProcess+0x2330`:

```text
nt!NtSetInformationProcess+0x2330:
fffff803`b74eedc0 4c89b868010000  mov qword ptr [rax+168h],r15
```

Registers at the store:

```text
rax=ffffd7830acc6080  ; process object
r13=0000000000000008  ; input length
r15=00007ff6f9fb2455  ; callback VA
```

Before:

```text
dt nt!_KPROCESS @rax InstrumentationCallback
+0x168 InstrumentationCallback : (null)
```

After single-step:

```text
dt nt!_KPROCESS @rax InstrumentationCallback
+0x168 InstrumentationCallback : 0x00007ff6`f9fb2455 Void

dq @rax+168 L1
ffffd783`0acc61e8  00007ff6`f9fb2455
```

Practical implication: use an image-backed callback thunk unless you are deliberately handling CFG-valid dynamic code. The kernel calls `MmValidateUserCallTarget`.

## Kernel Return Handoff

`KiSetupForInstrumentationReturn` is the core return rewrite function. IDA located it at:

```text
IDA:  0x140447af0
Live: nt+0x447af0
```

Static disassembly:

```asm
mov rax, gs:188h
mov rdx, [rax+0B8h]
mov r8,  [rdx+168h]       ; _KPROCESS.InstrumentationCallback
test r8, r8
jnz  callback_present
ret

callback_present:
cmp word ptr [rcx+170h], 33h
jnz ret
mov rax, [rcx+168h]       ; old trap-frame Rip
mov [rcx+58h], rax        ; trap-frame R10 = old Rip
mov [rcx+168h], r8        ; trap-frame Rip = callback
ret
```

`RCX` is the trap-frame pointer. The key writes are:

```text
_KTRAP_FRAME+0x058 = R10
_KTRAP_FRAME+0x168 = Rip
```

The kernel only rewrites user-mode returns in this function:

```asm
cmp word ptr [rcx+170h], 33h   ; SegCs == user x64 code segment
```

IDA direct xrefs found:

```text
KiInitializeUserApc
KiDispatchException
KeRaiseUserException
KiRaiseException
```

Live direct-syscall probes also observed callbacks where the previous PC matched the post-`syscall` label. So for the writeup, the safe wording is:

- exception/APC/user-exception paths were statically confirmed callers of `KiSetupForInstrumentationReturn`;
- live direct-syscall probes confirmed a callback can also arrive with previous PC equal to a post-`syscall` instruction;
- not every syscall-return path behaved identically in the early smoke test, so this is build/path sensitive.

### Trap Frame Before and After

Breakpoint:

```text
bp nt!KiSetupForInstrumentationReturn+0x28
```

Stopped at:

```text
nt!KiSetupForInstrumentationReturn+0x28:
fffff803`b7047b18 488b8168010000  mov rax,qword ptr [rcx+168h]
```

Registers:

```text
rcx=ffffa90c4da27ae0  ; trap frame
r8 =00007ff6f9fb2455  ; callback
```

Before rewrite:

```text
dt nt!_KTRAP_FRAME @rcx Rip Rsp R10 Rax
+0x030 Rax : 0
+0x058 R10 : 0x00007ffc`1a502ec4
+0x168 Rip : 0x00007ffc`1a5040c0
+0x180 Rsp : 0x00000032`7c99f3c0
```

After `mov rax,[rcx+168h]`:

```text
rax=00007ffc1a5040c0
```

After `mov [rcx+58h],rax`:

```text
+0x058 R10 : 0x00007ffc`1a5040c0
+0x168 Rip : 0x00007ffc`1a5040c0
```

After `mov [rcx+168h],r8`:

```text
+0x030 Rax    : 0
+0x058 R10    : 0x00007ffc`1a5040c0
+0x168 Rip    : 0x00007ff6`f9fb2455
+0x170 SegCs  : 0x33
+0x178 EFlags : 0x10246
+0x180 Rsp    : 0x00000032`7c99f3c0
```

At callback entry:

```text
rip=00007ff6f9fb2455
rsp=000000327c99f3c0
r10=00007ffc1a5040c0
rax=0000000000000000
cs=0033
```

This proves that callback-entry `R10`, not `RAX`, is the previous user PC for this x64 path.

## TEB Instrumentation Fields

At callback entry, the TEB fields existed but were not populated with previous PC/SP:

```text
TEB at 000000327cb2d000
dq 00000032`7cb2d000+2d0 L4
00000032`7cb2d2d0  00000000`00000000 00000000`00000000
00000032`7cb2d2e0  00000000`00000000 00000000`0000fffe
```

Interpretation:

- `InstrumentationCallbackSp`, `InstrumentationCallbackPreviousPc`, and `InstrumentationCallbackPreviousSp` were zero in the tested path.
- `InstrumentationCallbackDisabled` was not the source of the handoff.
- The observed authoritative handoff is trap-frame `R10`.

Those TEB fields are internal and should be treated as version-sensitive implementation details.

## The Correct Callback Thunk Shape

The callback must be a save-first assembly thunk. Do not enter C/C++ first; the compiler is allowed to clobber volatile registers before you inspect them.

Minimal shape:

```asm
PicCallbackThunk PROC
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
    push r10        ; previous user PC on x64
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Copy saved state to shared memory or a lock-free buffer.
    ; Avoid syscalls in the raw callback path.

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
PicCallbackThunk ENDP
```

The early probe originally treated `RAX` as the previous PC and crashed. After switching to `R10`, the probe completed cleanly.

Guest probe result:

```text
shape 8:  exit=0, count=2, entry_r10_prev_pc=0x00007ffc1a503f50
shape 16: exit=0, count=2, entry_r10_prev_pc=0x00007ffc1a503f50
```

## Syscall Entry State in the Kernel

On x64, a normal NTDLL stub uses:

```asm
mov r10, rcx
mov eax, ServiceNumber
syscall
ret
```

Kernel entry starts by restoring `RCX` from `R10`:

```asm
nt!KiSystemCall64:
swapgs
...
mov rcx, r10
```

Later, the user syscall dispatcher stores the syscall metadata into the current `_KTHREAD`:

```asm
nt!KiSystemServiceUser+0xc6:
mov [rbx+88h], rcx     ; _KTHREAD.FirstArgument
mov [rbx+80h], eax     ; _KTHREAD.SystemCallNumber
mov [rbx+90h], rsp     ; _KTHREAD.TrapFrame
```

Relevant offsets:

```text
dt nt!_KTHREAD SystemCallNumber FirstArgument State TrapFrame PreviousMode
+0x080 SystemCallNumber : Uint4B
+0x088 FirstArgument    : Ptr64 Void
+0x090 TrapFrame        : Ptr64 _KTRAP_FRAME
+0x184 State            : UChar
+0x232 PreviousMode     : Char
```

This is the kernel-side truth for syscall number and first argument. If user code jumps directly to a `syscall` instruction with unusual register state, the kernel records whatever was in `EAX` and whatever `RCX` becomes after `mov rcx,r10`. There is no shadow-stack-like source of an "intended" syscall number or an "intended" first argument.

CET/shadow-stack instructions appear in the syscall entry/exit path (`setssbsy`, `rstorssp`, `saveprevssp`, `rdsspq`, etc.), but they protect/control shadow-stack state. They do not preserve syscall arguments.

## `ThreadLastSystemCall` and `PspQueryLastCallThread`

`NtQueryInformationThread(ThreadLastSystemCall)` is information class `21` in the observed `NtQueryInformationThread` switch.

IDA case body:

```asm
loc_14099BA0B:
mov r8, cs:PsThreadType        ; case 21
...
call ObpReferenceObjectByHandleWithTag
...
mov r9, r13                   ; ReturnLength
mov r8d, r15d                 ; ThreadInformationLength
mov rdx, rsi                  ; ThreadInformation
mov rcx, [rsp+Thread]         ; target ETHREAD/KTHREAD
call PspQueryLastCallThread
```

WinDbg disassembly of `nt!PspQueryLastCallThread`:

```asm
mov r10, rdx
lea eax, [r8-10h]
test eax, 0FFFFFFF7h
jne STATUS_INFO_LENGTH_MISMATCH     ; accepts 0x10 or 0x18

mov rax, gs:[188h]
cmp rcx, rax
je STATUS_INVALID_PARAMETER         ; rejects current thread

mov r11d, [rcx+154h]                ; ContextSwitches snapshot
...
cmp byte ptr [rcx+184h], 5          ; _KTHREAD.State == Waiting
jne STATUS_UNSUCCESSFUL

cmp byte ptr [rcx+232h], 1          ; _KTHREAD.PreviousMode == UserMode
jne STATUS_UNSUCCESSFUL

mov rbx, [rcx+88h]                  ; _KTHREAD.FirstArgument
movzx edi, word ptr [rcx+80h]       ; low 16 bits of _KTHREAD.SystemCallNumber
mov eax, [rcx+1B4h]                 ; _KTHREAD.WaitTime
mov [rsp+10h], rax
...
cmp r11d, [rcx+154h]                ; reject if context switches changed
jne STATUS_UNSUCCESSFUL

mov rax, 0FFFFF78000000320h         ; shared tick count-ish source
mov ecx, [rax]
sub ecx, [rsp+10h]
imul rcx, [nt!KeMaximumIncrement]

mov [r10], rbx                      ; output FirstArgument
mov word ptr [r10+8], di            ; output SystemCallNumber
...
mov [r10+10h], rcx                  ; optional 0x18-byte output
```

The output structure is at least:

```c
typedef struct _THREAD_LAST_SYSCALL_INFORMATION {
    PVOID FirstArgument;       // offset 0x00
    USHORT SystemCallNumber;   // offset 0x08
    USHORT Reserved0;          // inferred padding
    ULONG Reserved1;           // inferred padding
    // Optional 0x18-byte form:
    // ULONGLONG WaitTimeOrAge; // offset 0x10
} THREAD_LAST_SYSCALL_INFORMATION;
```

The helper accepts output lengths `0x10` or `0x18`.

Important restrictions:

- It rejects the current thread.
- The target must be in `KTHREAD.State == Waiting`.
- The target must have `PreviousMode == UserMode`.
- The target must remain stable across a sampled `ContextSwitches` value.
- It only exposes first argument and syscall number, not the full argument vector.

### Same-Thread Callback Query Does Not Work

Calling `NtQueryInformationThread(ThreadLastSystemCall)` inside the instrumentation callback is not a good same-thread recovery mechanism:

- `PspQueryLastCallThread` rejects the current thread.
- Even if a same-thread query path existed, making a syscall from the callback would update the caller's `_KTHREAD.SystemCallNumber` and `_KTHREAD.FirstArgument` early in `KiSystemServiceUser`.
- That would make the query syscall itself the newest syscall state for the thread.

### Cross-Thread Query Can Work

A helper thread can query a separate target thread. The query syscall updates the helper thread's `_KTHREAD`, not the target's. This works when the target is blocked in a suitable user-mode syscall.

This was proven with a direct `NtWaitForSingleObject` harness.

## Direct Syscall Experiment 1: Blocked `NtWaitForSingleObject`

Goal: prove that `ThreadLastSystemCall` can catch syscall number and first argument from another thread, and separately prove that the instrumentation callback can see a direct syscall return.

Artifacts:

```text
direct_syscall_monitor.cpp
direct_syscall_monitor.asm
build_direct_syscall_monitor.ps1
direct_syscall_monitor.exe
```

Direct syscall stub:

```asm
DirectNtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, dword ptr [g_NtWaitForSingleObjectSyscall]
    syscall
DirectNtWaitForSingleObjectReturn:
    ret
DirectNtWaitForSingleObject ENDP
```

Design:

- Extract `NtWaitForSingleObject` service number from loaded `ntdll`.
- Install the instrumentation callback.
- Worker thread calls the direct syscall stub and blocks on an unsignaled event.
- Monitor thread repeatedly calls `NtQueryInformationThread(ThreadLastSystemCall)` on the worker.
- Callback increments a filtered hit counter if previous PC equals `DirectNtWaitForSingleObjectReturn`.

Successful run:

```text
ntdll!NtWaitForSingleObject       00007FF8EEA200E0
direct syscall stub               00007FF6A57017E0
direct syscall return label       00007FF6A57017EB
pic callback                      00007FF6A57017EC
block event handle                00000000000000D4
expected syscall number           0x0004
set callback status                0x00000000
clear callback status              0x00000000
worker direct wait status          0x00000000
last query status                  0x00000000
query attempts                    54
query return length               16
monitor detected                  1
last first argument               00000000000000D4
last syscall number               0x0004
monitor syscall match             1
monitor first-arg match           1
pic callback count                80
pic direct return hits            1
```

Interpretation:

- The monitor detected the worker's direct syscall metadata via `_KTHREAD.SystemCallNumber` and `_KTHREAD.FirstArgument`.
- The first argument matched the event handle.
- The callback saw one return through the direct syscall stub's post-`syscall` label.

This is the best use case for `ThreadLastSystemCall`: another thread is blocked in a syscall and therefore satisfies the waiting-state requirement.

## Direct Syscall Experiment 2: `NtAllocateVirtualMemory` With Atomic/Spin Coordination

Goal: remove the blocked wait syscall and test what can be extracted during an allocation syscall return. The worker does not block in kernel. Instead, the callback publishes a snapshot into shared memory and spins until the monitor reads it.

Artifacts:

```text
direct_syscall_alloc_monitor.cpp
direct_syscall_alloc_monitor.asm
build_direct_syscall_alloc_monitor.ps1
direct_syscall_alloc_monitor.exe
```

Worker syscall:

```c
PVOID base = nullptr;
SIZE_T region_size = 0x3000;

NtStatus status = DirectNtAllocateVirtualMemory(
    (HANDLE)-1,
    &base,
    0,
    &region_size,
    MEM_RESERVE | MEM_COMMIT,
    PAGE_READWRITE);
```

Direct syscall stub:

```asm
DirectNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [g_AllocSyscallNumber]
    syscall
DirectNtAllocateVirtualMemoryReturn:
    ret
DirectNtAllocateVirtualMemory ENDP
```

Callback behavior:

- save registers immediately;
- filter on `saved_r10 == DirectNtAllocateVirtualMemoryReturn`;
- decode syscall number from bytes before previous PC;
- capture volatile registers;
- capture home-space slots;
- capture stack arguments 5 and 6 from original user stack;
- set an atomic ready flag;
- spin with `pause` until the monitor sets an ack flag;
- restore registers and `jmp saved_r10`.

The syscall number decode is deliberately local to this direct stub shape. Because previous PC points at the instruction after `syscall`, the callback can look backward:

```asm
; Previous PC is DirectNtAllocateVirtualMemoryReturn.
; Direct stub bytes before it:
;   8B 05 xx xx xx xx    mov eax, dword ptr [rip+disp32]
;   0F 05                syscall

mov r11, saved_previous_pc
cmp byte ptr [r11-8], 08Bh
jne syscall_decode_done
cmp byte ptr [r11-7], 05h
jne syscall_decode_done
movsxd rax, dword ptr [r11-6]
lea r10, qword ptr [r11-2]
add r10, rax
mov eax, dword ptr [r10]
```

Successful run:

```text
ntdll!NtAllocateVirtualMemory        00007FF8EEA20360
direct syscall stub                  00007FF696061BB0
direct syscall return label          00007FF696061BBB
pic callback                         00007FF696061BBC
expected syscall number              0x0018
set callback status                    0x00000000
clear callback status                  0x00000000
worker direct allocate status          0x00000000
free status                            0x00000000
worker allocated base                000001A516570000
worker region size                     0x0000000000003000
callback ready                       1
callback ack                         1
callback count                         0x0000000000000018
callback direct hits                   0x0000000000000001
callback previous pc                   0x00007ff696061bbb
callback decoded syscall               0x0018
callback return rax                    0x0000000000000000
callback arg1 rcx/process              0x00007ff696061bbc
callback arg2 rdx/base ptr             0x0000000000000000
callback arg3 r8/zero bits             0x00000083545ff878
callback arg4 r9/size ptr              0x0000000000000000
callback home slot 1                   0x0000000000000000
callback home slot 2                   0x0000000000000000
callback home slot 3                   0x0000000000000000
callback home slot 4                   0x0000000000000000
callback arg5 stack/alloc type         0x0000000000003000
callback arg6 stack/protect            0x0000000000000004
callback prev-pc match               1
callback decoded syscall match       1
callback arg1 match                  0
callback arg2 pointer nonzero        0
callback arg3 match                  0
callback arg4 pointer nonzero        0
callback arg5 match                  1
callback arg6 match                  1
monitor callback-snapshot detected   1
last ThreadLastSystemCall status       0xc0000001
ThreadLastSystemCall attempts        8
ThreadLastSystemCall detected        0
```

### What Was Recoverable

Recovered:

- previous PC: `0x00007ff696061bbb`, matching the direct stub return label;
- syscall number: `0x0018`, decoded from the direct stub;
- return status: `RAX == 0`;
- stack argument 5: `0x3000`, matching `MEM_RESERVE | MEM_COMMIT`;
- stack argument 6: `0x4`, matching `PAGE_READWRITE`.

Not recovered:

- first arg / process handle from `RCX`;
- second arg / base-address pointer from `RDX`;
- third arg / zero bits from `R8`;
- fourth arg / region-size pointer from `R9`;
- first four args from caller home space.

Observed callback-entry register state for the first four args:

```text
RCX = callback address
RDX = 0
R8  = unrelated stack-ish value
R9  = 0
home slots 1-4 = 0
```

Interpretation: on this build/path, the callback should not assume original volatile argument registers survive. Stack arguments can still be recovered from the saved user stack because the callback uses the original user `RSP`.

### Crash During Development

The first allocation harness tried to dereference saved `RDX` and `R9` inside the callback to read the `BaseAddress` and `RegionSize` output values. It crashed:

```text
Exception: c0000005
Fault offset: 0x1b0a
Faulting instruction: mov rax, [r11]
```

The faulting `r11` came from saved `RDX`.

Fix: do not dereference arbitrary captured pointer registers in the callback. Record raw values and let safer code reason about them later.

### `ThreadLastSystemCall` Failed Here

The worker was spinning in user-mode callback, not blocked in a kernel wait. `PspQueryLastCallThread` requires `KTHREAD.State == Waiting`, so the monitor's `ThreadLastSystemCall` attempts failed:

```text
last ThreadLastSystemCall status 0xc0000001
ThreadLastSystemCall detected   0
```

That matches the static RE.

## Detection Strategy From the Research

For direct syscall detection using instrumentation callbacks, the strongest user-mode path from this research is:

1. Install `ProcessInstrumentationCallback`.
2. Use a CFG-valid, image-backed, save-first assembly thunk.
3. In the thunk, save all GPRs/flags immediately.
4. Treat saved `R10` as previous PC.
5. Check whether previous PC points inside a known syscall stub or to a post-`syscall` instruction.
6. Decode the syscall number from the stub bytes when possible.
7. Recover stack arguments from saved user `RSP` when the syscall has stack-passed parameters.
8. Do not expect first-four register arguments to be intact at callback entry.
9. Avoid syscalls inside the callback; publish to shared memory and use atomics/spin coordination for experiments.

For blocked target threads, a monitor thread can additionally call `NtQueryInformationThread(ThreadLastSystemCall)` and read:

```text
FirstArgument
SystemCallNumber
```

But that is a cross-thread, waiting-state-only primitive. It is not a general in-callback primitive.

## Limitations and Open Questions

- This is a Windows 26100 x64 result. Older builds, x86, and WOW64 may differ.
- The input structure and callback contract are private and version-sensitive.
- The TEB instrumentation fields exist but were not active in the tested path.
- `ThreadLastSystemCall` exposes only syscall number and first argument.
- `ThreadLastSystemCall` requires the target to be another waiting user-mode thread.
- Direct syscall previous-PC detection depends on the actual code bytes around the return PC.
- Direct/indirect jumps to `syscall` can intentionally make the kernel's recorded `EAX`/`R10` state weird; the kernel records what actually arrived, not what an NTDLL stub would have intended.
- The first four syscall args were not recoverable from callback-entry volatile registers in the allocation experiment.
- Stack args 5+ were recoverable in the tested direct-call shape, but different compiler/codegen patterns may alter stack layout.

## Artifact Index

Primary notes:

```text
memory.md
ProcessInstrumentationCallbackwriteup.md
Writeup.md
```

Initial callback proof:

```text
pic_probe.cpp
pic_callback.asm
run_pic_probe_guest.py
pic_probe.exe
```

Cross-thread `ThreadLastSystemCall` proof:

```text
direct_syscall_monitor.cpp
direct_syscall_monitor.asm
build_direct_syscall_monitor.ps1
direct_syscall_monitor.exe
```

Allocation/direct-stub callback snapshot proof:

```text
direct_syscall_alloc_monitor.cpp
direct_syscall_alloc_monitor.asm
build_direct_syscall_alloc_monitor.ps1
direct_syscall_alloc_monitor.exe
```

Kernel/IDA:

```text
ntoskrnl_26100_90b083da_c74d68.exe
ntoskrnl_26100_90b083da_c74d68.exe.id0
ntoskrnl_26100_90b083da_c74d68.exe.id1
ntoskrnl_26100_90b083da_c74d68.exe.id2
ntoskrnl_26100_90b083da_c74d68.exe.nam
ntoskrnl_26100_90b083da_c74d68.exe.til
```

## Claim-to-Evidence Map

- `ProcessInstrumentationCallback` is `NtSetInformationProcess` class `0x28` / decimal `40`: IDA jump-table case `40`; live breakpoint in `NtSetInformationProcess`; successful probe using class `0x28`.
- The callback is stored at `_KPROCESS.InstrumentationCallback`: WinDbg `dt nt!_KPROCESS Instrumentation*`; live store at `nt!NtSetInformationProcess+0x2330`.
- x64 previous PC is handed to the callback in `R10`: IDA/WinDbg disassembly of `KiSetupForInstrumentationReturn`; live trap-frame before/after; callback-entry registers.
- `RAX` is not previous PC: trap-frame after rewrite kept `Rax=0`; callback entry had `rax=0` in the initial proof; allocation probe showed `RAX` as syscall return status.
- TEB instrumentation fields were not the source of previous PC: WinDbg TEB field dump at callback entry and probe snapshot.
- `ThreadLastSystemCall` goes through `PspQueryLastCallThread`: IDA `NtQueryInformationThread` case `21`; WinDbg `uf nt!PspQueryLastCallThread`.
- `PspQueryLastCallThread` reads `_KTHREAD.FirstArgument` and low 16 bits of `_KTHREAD.SystemCallNumber`: WinDbg disassembly and `dt nt!_KTHREAD`.
- Every user syscall updates current-thread `SystemCallNumber` and `FirstArgument`: WinDbg `uf nt!KiSystemServiceUser`.
- Cross-thread waiting syscall detection works: `direct_syscall_monitor.exe` matched event handle and syscall number.
- Allocation callback snapshot works for previous PC, syscall number, return status, and stack args 5/6: `direct_syscall_alloc_monitor.exe` output.
- Allocation callback did not recover first four args from volatile registers/home space: `direct_syscall_alloc_monitor.exe` output.

## References

- Microsoft Learn, x64 `CONTEXT`: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
- Microsoft Learn, `TEB`: https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-teb
- Microsoft Learn, debugger symbol path: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path
- Microsoft Learn, Microsoft public symbols: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/microsoft-public-symbols
- NtDoc, `NtSetInformationProcess`: https://ntdoc.m417z.com/ntsetinformationprocess
- Winternl background article on instrumentation callbacks/Nirvana, treated as context rather than authority for this build: https://winternl.com/detecting-manual-syscalls-from-user-mode/
