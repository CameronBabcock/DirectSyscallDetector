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

#include <cstddef>
#include <cstdint>

namespace DirectSyscallDetector
{
    enum class CallbackSlotState : LONG
    {
        Free = 0,
        Writing = 1,
        Ready = 2
    };

    constexpr std::size_t CallbackSlotCount{ 16 };

    // Shared verbatim with the MASM thunk. Keep this cache-line sized so the
    // callback can publish one compact record and spin on only the slot state.
    struct alignas(64) CallbackSlot
    {
        volatile LONG State{};
        ULONG Reserved0{};
        volatile std::uint64_t ThreadId{};
        volatile std::uint64_t PreviousProgramCounter{};
        volatile std::uint64_t StackPointer{};
        volatile std::uint64_t StackArgument5{};
        volatile std::uint64_t StackArgument6{};
        volatile std::uint64_t Reserved1{};
        volatile std::uint64_t Reserved2{};
    };

    static_assert(sizeof(CallbackSlot) == 64);
    static_assert(offsetof(CallbackSlot, State) == 0);
    static_assert(offsetof(CallbackSlot, ThreadId) == 8);
    static_assert(offsetof(CallbackSlot, PreviousProgramCounter) == 16);
    static_assert(offsetof(CallbackSlot, StackPointer) == 24);
    static_assert(offsetof(CallbackSlot, StackArgument5) == 32);
    static_assert(offsetof(CallbackSlot, StackArgument6) == 40);

    struct CallbackRecord
    {
        std::size_t SlotIndex{};
        DWORD ThreadId{};
        std::uintptr_t PreviousProgramCounter{};
        std::uint64_t StackPointer{};
        std::uint64_t StackArgument5{};
        std::uint64_t StackArgument6{};
    };
}

extern "C" __declspec(align(64)) DirectSyscallDetector::CallbackSlot
    g_DsdCallbackSlots[DirectSyscallDetector::CallbackSlotCount];
extern "C" __declspec(align(64)) volatile LONG g_DsdCallbackArmed;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdCallbackCount;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdCapturedCount;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdDroppedCount;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdTargetThreadId;
