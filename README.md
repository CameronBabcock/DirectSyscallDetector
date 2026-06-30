# Nirvana v2: Electric Boogaloo

Return-provenance detection for raw and gadgeted direct syscalls.

DirectSyscallDetector is a native x64 AMD64 C++23 / Visual Studio project that
demonstrates instrumentation-callback-based direct syscall detection.

The detector builds a live syscall return-address catalog from `ntdll.dll` and
`win32u.dll`, queries `ThreadLastSystemCall`, and classifies:

- clean syscalls that return through the expected exported syscall stub;
- raw direct syscalls that execute `syscall` outside the cataloged stubs;
- syscall-gadget mismatches where the syscall ID and post-syscall return
  address describe different stubs.

The demo is intentionally in-process and research-oriented. It is not an
injectable EDR sensor, but it is structured as a reusable static library plus a
console probe runner.

## Why This Exists

Many direct-syscall examples focus on bypassing user-mode hooks by skipping the
front of an `ntdll` export. This project looks at the defensive side:

> if the kernel reports that a thread just executed syscall `X`, did that
> thread return to the post-syscall address that belongs to syscall `X`?

That catches both raw syscall instructions in arbitrary code and gadgeted
syscalls that borrow a `syscall` instruction from the wrong `ntdll` stub. The
research name for that technique is **Nirvana v2: Electric Boogaloo**: a
return-provenance detector for raw and gadgeted direct syscalls.

## Solution Layout

- `DirectSyscallDetectorLib` - static library with the catalog, detector
  session, callback ring, generated signature registry, and MASM thunk.
- `DirectSyscallDetectorDemo` - console app that runs clean, raw, and gadgeted
  syscall probes.
- `tools/generate_syscall_signatures.py` - developer-time generator for PHNT
  backed syscall signatures.
- `third_party/phnt` - vendored PHNT headers pinned to the referenced upstream
  snapshot and retained under PHNT's MIT license.

## Core Technique

1. Walk loaded exports from `ntdll.dll` and `win32u.dll`.
2. Scan syscall stubs for `mov eax, imm32` followed by `syscall`.
3. Store the recovered syscall number and expected return address
   (`syscall + 2`).
4. Install a process instrumentation callback with
   `NtSetInformationProcess(ProcessInstrumentationCallback)`.
5. Let the MASM callback capture the previous PC plus stack arguments 5 and 6.
6. Let a monitor thread query the paused worker with
   `NtQueryInformationThread(ThreadLastSystemCall)`.
7. Classify by comparing the recovered syscall ID to the owner of the observed
   return PC.
8. Print available arguments using generated PHNT-backed C++ templates keyed by
   the recovered syscall ID.

## Requirements

- Windows x64 on AMD64.
- Visual Studio 2026 / MSVC with C++23 or latest language mode.
- MASM build support.
- Native x64 build configuration. ARM64, ARM64EC, WOW64, and 32-bit syscall
  behavior are out of scope for this revision.

## Build And Verify

From a Visual Studio developer shell or a shell with MSBuild available:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  .\DirectSyscallDetector.sln /m /p:Configuration=Debug /p:Platform=x64

& 'C:\Program Files\Microsoft Visual Studio\18\Insiders\MSBuild\Current\Bin\amd64\MSBuild.exe' `
  .\DirectSyscallDetector.sln /m /p:Configuration=Release /p:Platform=x64

.\x64\Release\DirectSyscallDetectorDemo.exe
```

The demo returns nonzero if any expected classification fails. A successful run
prints catalog coverage and verdict checks similar to:

```text
catalog NtAllocateVirtualMemory: ntdll.dll!NtAllocateVirtualMemory ...
catalog NtProtectVirtualMemory: ntdll.dll!NtProtectVirtualMemory ...
catalog NtQuerySystemTime: ntdll.dll!NtQuerySystemTime ...
catalog win32u.dll entries: present

[baseline ntdll!NtAllocateVirtualMemory] clean
[raw MASM NtAllocateVirtualMemory] raw direct syscall
[raw MASM NtProtectVirtualMemory] raw direct syscall
[ntdll syscall gadget for NtProtectVirtualMemory] syscall-return mismatch

expect baseline ntdll allocate: pass
expect raw allocate: pass
expect raw protect: pass
expect ntdll gadget protect: pass
```

## Signature Generation

Generated signatures are checked into the project so normal builds do not need
Python or `dumpbin`.

To regenerate:

```powershell
python .\tools\generate_syscall_signatures.py
```

The generated registry uses PHNT declarations through expressions such as
`std::remove_pointer_t<decltype(&::NtAllocateVirtualMemory)>`. If a generated
prototype drifts away from PHNT, the project fails at compile time instead of
silently printing stale argument metadata.

## Limitations

- Native AMD64/x64 only.
- In-process research demo only.
- Does not cover WOW64 syscall transitions.
- Does not attempt arbitrary pointer dereferencing while printing arguments.
- Captures argument 1 through `ThreadLastSystemCall` and stack arguments 5 and
  6 from the instrumentation callback snapshot. Arguments 2-4 are intentionally
  not fabricated.
- A production sensor would need a broader architecture for deployment,
  telemetry export, callback ownership, lost-event handling, protected process
  boundaries, and performance control.

## Attribution And Contact

Author / Researcher: Cameron Babcock

Email: Cameron@CameronBabcock.net

LinkedIn: https://www.linkedin.com/in/cameronbabcock/

If this work is useful to your EDR, CNO, pentest agent work, endpoint security,
Windows internals, or detection engineering team, please contact Cameron
Babcock using the email or LinkedIn profile above regarding research,
consulting, or employment opportunities.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

Redistributions and derivative works must preserve the attribution notices
required by the Apache License, Version 2.0, including [NOTICE](NOTICE) where
applicable.

This project is provided on an "AS IS" basis without warranties or conditions
of any kind. See the license for the full warranty disclaimer and limitation of
liability.

Third-party components retain their own licenses. PHNT is vendored under
`third_party/phnt` and remains under its MIT license.
