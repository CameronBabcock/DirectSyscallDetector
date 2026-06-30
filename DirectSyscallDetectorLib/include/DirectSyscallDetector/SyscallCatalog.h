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
#include "DirectSyscallDetector/SignaturePrinter.h"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace DirectSyscallDetector
{
    struct SyscallEntry
    {
        std::uint32_t Number{};
        std::wstring ModuleName{};
        std::string FunctionName{};
        std::uintptr_t FunctionAddress{};
        std::uintptr_t SyscallAddress{};
        std::uintptr_t ExpectedReturnAddress{};
        std::unique_ptr<const ISyscallSignature> Signature{};
    };

    struct ExpectedReturnCandidate
    {
        std::uint32_t Number{};
        std::wstring ModuleName{};
        std::string FunctionName{};
        std::uintptr_t ExpectedReturnAddress{};
    };

    class SyscallCatalog
    {
    public:
        [[nodiscard]] static SyscallCatalog BuildForCurrentProcess();

        SyscallCatalog() = default;
        ~SyscallCatalog();

        SyscallCatalog(const SyscallCatalog&) = delete;
        SyscallCatalog& operator=(const SyscallCatalog&) = delete;

        SyscallCatalog(SyscallCatalog&&) noexcept = default;
        SyscallCatalog& operator=(SyscallCatalog&&) noexcept = default;

        [[nodiscard]] std::span<const SyscallEntry> Entries() const noexcept;
        [[nodiscard]] std::span<const std::string> Warnings() const noexcept;
        [[nodiscard]] const SyscallEntry* FindByReturnAddress(std::uintptr_t returnAddress) const noexcept;
        [[nodiscard]] const SyscallEntry* FindByFunctionName(std::string_view functionName) const noexcept;
        [[nodiscard]] const SyscallEntry* FindPrimaryBySyscallNumber(std::uint32_t syscallNumber) const noexcept;
        [[nodiscard]] std::vector<const SyscallEntry*> FindBySyscallNumber(std::uint32_t syscallNumber) const;
        [[nodiscard]] std::vector<ExpectedReturnCandidate> ExpectedReturnsForSyscall(std::uint32_t syscallNumber) const;

        void AddEntry(SyscallEntry entry);
        void AddWarning(std::string warning);
        void AddOwnedModule(HMODULE module);

    private:
        struct LibraryModuleDeleter
        {
            void operator()(std::remove_pointer_t<HMODULE>* module) const noexcept;
        };

        using UniqueLibraryModule = std::unique_ptr<std::remove_pointer_t<HMODULE>, LibraryModuleDeleter>;

        std::vector<SyscallEntry> m_entries{};
        std::vector<std::string> m_warnings{};
        std::vector<UniqueLibraryModule> m_ownedModules{};
        std::unordered_map<std::uintptr_t, std::size_t> m_returnAddressIndex{};
        std::unordered_multimap<std::uint32_t, std::size_t> m_syscallNumberIndex{};
    };
}
