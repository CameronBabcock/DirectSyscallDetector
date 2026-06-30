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

#include "CallbackRing.h"

#include <cstdint>

extern "C" void DsdInstrumentationCallbackThunk();

extern "C" __declspec(align(64)) DirectSyscallDetector::CallbackSlot
    g_DsdCallbackSlots[DirectSyscallDetector::CallbackSlotCount] = {};
extern "C" __declspec(align(64)) volatile LONG g_DsdCallbackArmed = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdCallbackCount = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdCapturedCount = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdDroppedCount = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_DsdTargetThreadId = 0;
