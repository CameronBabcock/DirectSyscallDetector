/*
Nirvana v2: Electric Boogaloo
Return-provenance detection for raw and gadgeted direct syscalls.

Project: DirectSyscallDetector
Copyright 2026 Cameron Babcock

Author / Researcher: Cameron Babcock
GitHub: https://github.com/CameronBabcock
Email: Cameron@CameronBabcock.net
LinkedIn: https://www.linkedin.com/in/cameronbabcock/

Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
For EDR, CNO, pentest agent work, endpoint security, Windows internals,
or detection engineering work,
please contact Cameron Babcock using the email or LinkedIn profile above.
*/

#pragma once

#include "DirectSyscallDetector/NativeApi.h"

#include <cstdint>

extern "C" NTSTATUS NTAPI DsdDirectNtAllocateVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    ULONG_PTR zeroBits,
    PSIZE_T regionSize,
    ULONG allocationType,
    ULONG pageProtection);

extern "C" NTSTATUS NTAPI DsdDirectNtProtectVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    PSIZE_T regionSize,
    ULONG newProtection,
    PULONG oldProtection);

extern "C" NTSTATUS NTAPI DsdGadgetNtProtectVirtualMemory(
    HANDLE processHandle,
    PVOID* baseAddress,
    PSIZE_T regionSize,
    ULONG newProtection,
    PULONG oldProtection);

namespace DirectSyscallDetector
{
    void ConfigureTestSyscalls(
        std::uint32_t allocateVirtualMemorySyscall,
        std::uint32_t protectVirtualMemorySyscall,
        std::uintptr_t gadgetSyscallInstruction) noexcept;
}
