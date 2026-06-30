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

#ifndef PHNT_VERSION
#define PHNT_VERSION PHNT_WINDOWS_11_24H2
#endif

#include <phnt_windows.h>
#include <phnt.h>

#include <string>

namespace DirectSyscallDetector
{
    template <typename TFunction>
    [[nodiscard]] TFunction* ResolveProcedure(HMODULE module, const char* procedureName) noexcept
    {
        if (nullptr == module || nullptr == procedureName)
        {
            return nullptr;
        }

        return reinterpret_cast<TFunction*>(GetProcAddress(module, procedureName));
    }

    [[nodiscard]] HMODULE GetOrLoadModule(const wchar_t* moduleName) noexcept;
    [[nodiscard]] std::string NarrowModuleName(const wchar_t* moduleName);
}
