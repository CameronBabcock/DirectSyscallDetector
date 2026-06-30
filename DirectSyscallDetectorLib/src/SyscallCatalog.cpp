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

#include "DirectSyscallDetector/SyscallCatalog.h"

#include "DirectSyscallDetector/GeneratedSyscallSignatures.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <optional>
#include <ranges>
#include <utility>

namespace DirectSyscallDetector
{
    namespace
    {
        struct ModuleSpec
        {
            const wchar_t* Name{};
        };

        struct ModuleLoadResult
        {
            HMODULE Module{};
            bool OwnsReference{};
        };

        struct DecodedSyscallStub
        {
            std::uint32_t Number{};
            std::uintptr_t SyscallAddress{};
            std::uintptr_t ExpectedReturnAddress{};
        };

        [[nodiscard]] bool IsReadablePeImage(HMODULE module) noexcept
        {
            if (nullptr == module)
            {
                return false;
            }

            const auto* dosHeader{ reinterpret_cast<const IMAGE_DOS_HEADER*>(module) };
            if (IMAGE_DOS_SIGNATURE != dosHeader->e_magic)
            {
                return false;
            }

            const auto* ntHeaders{ reinterpret_cast<const IMAGE_NT_HEADERS*>(
                reinterpret_cast<const std::uint8_t*>(module) + dosHeader->e_lfanew) };
            return IMAGE_NT_SIGNATURE == ntHeaders->Signature;
        }

        [[nodiscard]] std::optional<DecodedSyscallStub> DecodeSyscallStub(const std::uint8_t* functionAddress)
        {
            constexpr std::size_t ScanByteCount{ 96 };
            constexpr std::uint8_t MovEaxImmediate{ 0xB8 };
            constexpr std::uint8_t SyscallByte0{ 0x0F };
            constexpr std::uint8_t SyscallByte1{ 0x05 };

            std::optional<std::uint32_t> syscallNumber{};

            // Use the loaded image, not a static table. Syscall IDs move across
            // Windows builds, but the user-mode stubs still carry mov eax, id.
            for (std::size_t index = 0; index + sizeof(std::uint32_t) < ScanByteCount; ++index)
            {
                if (MovEaxImmediate == functionAddress[index])
                {
                    std::uint32_t number{};
                    std::memcpy(&number, functionAddress + index + 1, sizeof(number));
                    syscallNumber = number;
                    continue;
                }

                if (SyscallByte0 == functionAddress[index] && SyscallByte1 == functionAddress[index + 1] && syscallNumber.has_value())
                {
                    const auto syscallAddress{ reinterpret_cast<std::uintptr_t>(functionAddress + index) };
                    return DecodedSyscallStub{
                        .Number = *syscallNumber,
                        .SyscallAddress = syscallAddress,
                        .ExpectedReturnAddress = syscallAddress + 2
                    };
                }
            }

            return std::nullopt;
        }

        [[nodiscard]] bool IsForwardedExport(
            const DWORD functionRva,
            const IMAGE_DATA_DIRECTORY& exportDirectory) noexcept
        {
            return functionRva >= exportDirectory.VirtualAddress &&
                   functionRva < exportDirectory.VirtualAddress + exportDirectory.Size;
        }

        [[nodiscard]] ModuleLoadResult GetOrLoadModuleForCatalog(const wchar_t* moduleName) noexcept
        {
            HMODULE module{ GetModuleHandleW(moduleName) };
            if (nullptr != module)
            {
                return ModuleLoadResult{
                    .Module = module,
                    .OwnsReference = false
                };
            }

            module = LoadLibraryW(moduleName);
            return ModuleLoadResult{
                .Module = module,
                .OwnsReference = nullptr != module
            };
        }

        void ScanModuleExports(SyscallCatalog& catalog, const ModuleSpec& moduleSpec)
        {
            const ModuleLoadResult moduleLoad{ GetOrLoadModuleForCatalog(moduleSpec.Name) };
            HMODULE module{ moduleLoad.Module };
            if (nullptr == module)
            {
                catalog.AddWarning(std::format("could not load {}", NarrowModuleName(moduleSpec.Name)));
                return;
            }

            if (moduleLoad.OwnsReference)
            {
                catalog.AddOwnedModule(module);
            }

            if (false == IsReadablePeImage(module))
            {
                catalog.AddWarning(std::format("{} is not a readable PE image", NarrowModuleName(moduleSpec.Name)));
                return;
            }

            const auto* imageBase{ reinterpret_cast<const std::uint8_t*>(module) };
            const auto* dosHeader{ reinterpret_cast<const IMAGE_DOS_HEADER*>(imageBase) };
            const auto* ntHeaders{ reinterpret_cast<const IMAGE_NT_HEADERS*>(imageBase + dosHeader->e_lfanew) };
            const auto& exportDirectoryData{
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            };

            if (0 == exportDirectoryData.VirtualAddress || 0 == exportDirectoryData.Size)
            {
                catalog.AddWarning(std::format("{} has no export directory", NarrowModuleName(moduleSpec.Name)));
                return;
            }

            const auto* exportDirectory{ reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                imageBase + exportDirectoryData.VirtualAddress) };
            const auto* names{ reinterpret_cast<const DWORD*>(imageBase + exportDirectory->AddressOfNames) };
            const auto* ordinals{ reinterpret_cast<const WORD*>(imageBase + exportDirectory->AddressOfNameOrdinals) };
            const auto* functions{ reinterpret_cast<const DWORD*>(imageBase + exportDirectory->AddressOfFunctions) };

            // Each decoded export gives us two facts: the expected post-syscall
            // return address, and the PHNT signature to use when this ID is seen.
            for (DWORD index = 0; index < exportDirectory->NumberOfNames; ++index)
            {
                const char* functionName{ reinterpret_cast<const char*>(imageBase + names[index]) };
                const WORD ordinal{ ordinals[index] };
                const DWORD functionRva{ functions[ordinal] };

                if (0 == functionRva || IsForwardedExport(functionRva, exportDirectoryData))
                {
                    continue;
                }

                const auto* functionAddress{ imageBase + functionRva };
                const auto decodedStub{ DecodeSyscallStub(functionAddress) };
                if (false == decodedStub.has_value())
                {
                    continue;
                }

                catalog.AddEntry(SyscallEntry{
                    .Number = decodedStub->Number,
                    .ModuleName = moduleSpec.Name,
                    .FunctionName = functionName,
                    .FunctionAddress = reinterpret_cast<std::uintptr_t>(functionAddress),
                    .SyscallAddress = decodedStub->SyscallAddress,
                    .ExpectedReturnAddress = decodedStub->ExpectedReturnAddress,
                    .Signature = FindGeneratedSyscallSignature(functionName) });
            }
        }
    }

    HMODULE GetOrLoadModule(const wchar_t* moduleName) noexcept
    {
        HMODULE module{ GetModuleHandleW(moduleName) };
        if (nullptr != module)
        {
            return module;
        }

        return LoadLibraryW(moduleName);
    }

    std::string NarrowModuleName(const wchar_t* moduleName)
    {
        if (nullptr == moduleName)
        {
            return {};
        }

        std::string result{};
        while (L'\0' != *moduleName)
        {
            result.push_back(static_cast<char>(*moduleName));
            ++moduleName;
        }
        return result;
    }

    SyscallCatalog::~SyscallCatalog() = default;

    void SyscallCatalog::LibraryModuleDeleter::operator()(std::remove_pointer_t<HMODULE>* module) const noexcept
    {
        if (nullptr != module)
        {
            FreeLibrary(module);
        }
    }

    SyscallCatalog SyscallCatalog::BuildForCurrentProcess()
    {
        SyscallCatalog catalog{};

        constexpr std::array ModuleSpecs{
            ModuleSpec{ L"ntdll.dll" },
            ModuleSpec{ L"win32u.dll" }
        };

        for (const auto& moduleSpec : ModuleSpecs)
        {
            ScanModuleExports(catalog, moduleSpec);
        }

        return catalog;
    }

    std::span<const SyscallEntry> SyscallCatalog::Entries() const noexcept
    {
        return m_entries;
    }

    std::span<const std::string> SyscallCatalog::Warnings() const noexcept
    {
        return m_warnings;
    }

    const SyscallEntry* SyscallCatalog::FindByReturnAddress(const std::uintptr_t returnAddress) const noexcept
    {
        const auto found{ m_returnAddressIndex.find(returnAddress) };
        if (m_returnAddressIndex.end() == found)
        {
            return nullptr;
        }

        return &m_entries[found->second];
    }

    const SyscallEntry* SyscallCatalog::FindByFunctionName(const std::string_view functionName) const noexcept
    {
        const auto found{ std::ranges::find_if(
            m_entries,
            [functionName](const SyscallEntry& entry)
            {
                return entry.FunctionName == functionName;
            }) };

        if (m_entries.end() == found)
        {
            return nullptr;
        }

        return &*found;
    }

    const SyscallEntry* SyscallCatalog::FindPrimaryBySyscallNumber(const std::uint32_t syscallNumber) const noexcept
    {
        const SyscallEntry* fallbackEntry{};
        for (const auto& entry : m_entries)
        {
            if (entry.Number != syscallNumber)
            {
                continue;
            }

            if (nullptr == fallbackEntry)
            {
                fallbackEntry = &entry;
            }

            // Nt* and Zw* aliases often share the same stub. Prefer the Nt name
            // for diagnostics because that is what most user-mode readers expect.
            if (false == entry.FunctionName.starts_with("Zw"))
            {
                return &entry;
            }
        }

        return fallbackEntry;
    }

    std::vector<const SyscallEntry*> SyscallCatalog::FindBySyscallNumber(const std::uint32_t syscallNumber) const
    {
        std::vector<const SyscallEntry*> entries{};
        const auto range{ m_syscallNumberIndex.equal_range(syscallNumber) };
        for (auto iterator = range.first; iterator != range.second; ++iterator)
        {
            entries.push_back(&m_entries[iterator->second]);
        }
        return entries;
    }

    std::vector<ExpectedReturnCandidate> SyscallCatalog::ExpectedReturnsForSyscall(const std::uint32_t syscallNumber) const
    {
        std::vector<ExpectedReturnCandidate> candidates{};
        const auto entries{ FindBySyscallNumber(syscallNumber) };
        candidates.reserve(entries.size());

        for (const auto* entry : entries)
        {
            candidates.push_back(ExpectedReturnCandidate{
                .Number = entry->Number,
                .ModuleName = entry->ModuleName,
                .FunctionName = entry->FunctionName,
                .ExpectedReturnAddress = entry->ExpectedReturnAddress });
        }

        return candidates;
    }

    void SyscallCatalog::AddEntry(SyscallEntry entry)
    {
        const auto index{ m_entries.size() };
        m_entries.push_back(std::move(entry));
        m_returnAddressIndex.emplace(m_entries.back().ExpectedReturnAddress, index);
        m_syscallNumberIndex.emplace(m_entries.back().Number, index);
    }

    void SyscallCatalog::AddWarning(std::string warning)
    {
        m_warnings.push_back(std::move(warning));
    }

    void SyscallCatalog::AddOwnedModule(HMODULE module)
    {
        UniqueLibraryModule ownedModule{ module };
        m_ownedModules.push_back(std::move(ownedModule));
    }
}
