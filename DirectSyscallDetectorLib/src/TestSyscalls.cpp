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

#include "DirectSyscallDetector/TestSyscalls.h"

namespace DirectSyscallDetector
{
    extern "C" __declspec(align(64)) volatile std::uint32_t g_DsdNtAllocateVirtualMemorySyscall = 0;
    extern "C" __declspec(align(64)) volatile std::uint32_t g_DsdNtProtectVirtualMemorySyscall = 0;
    extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdGadgetSyscallInstruction = 0;

    void ConfigureTestSyscalls(
        const std::uint32_t allocateVirtualMemorySyscall,
        const std::uint32_t protectVirtualMemorySyscall,
        const std::uintptr_t gadgetSyscallInstruction) noexcept
    {
        InterlockedExchange(
            reinterpret_cast<volatile LONG*>(&g_DsdNtAllocateVirtualMemorySyscall),
            static_cast<LONG>(allocateVirtualMemorySyscall));
        InterlockedExchange(
            reinterpret_cast<volatile LONG*>(&g_DsdNtProtectVirtualMemorySyscall),
            static_cast<LONG>(protectVirtualMemorySyscall));
        InterlockedExchange64(
            reinterpret_cast<volatile LONG64*>(&g_DsdGadgetSyscallInstruction),
            static_cast<LONG64>(gadgetSyscallInstruction));
    }
}
