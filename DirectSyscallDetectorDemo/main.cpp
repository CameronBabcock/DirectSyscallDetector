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

#include "DirectSyscallDetector/DetectorSession.h"
#include "DirectSyscallDetector/GeneratedSyscallSignatures.h"
#include "DirectSyscallDetector/TestSyscalls.h"

#include <algorithm>
#include <cstdint>
#include <format>
#include <iostream>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>

namespace
{
    using namespace DirectSyscallDetector;

    using TFnNtAllocateVirtualMemory = std::remove_pointer_t<decltype(&NtAllocateVirtualMemory)>;
    using TFnNtProtectVirtualMemory = std::remove_pointer_t<decltype(&NtProtectVirtualMemory)>;
    using TFnNtFreeVirtualMemory = std::remove_pointer_t<decltype(&NtFreeVirtualMemory)>;

    struct DemoConstants
    {
        constexpr static int SetupFailureExitCode{ 2 };
        constexpr static SIZE_T BaselineAllocationSize{ 0x3000 };
        constexpr static SIZE_T RawAllocationSize{ 0x4000 };
        constexpr static SIZE_T ProtectAllocationSize{ 0x1000 };
        constexpr static ULONG AllocationType{ MEM_RESERVE | MEM_COMMIT };
        constexpr static ULONG ReadWriteProtection{ PAGE_READWRITE };
        constexpr static ULONG ReadOnlyProtection{ PAGE_READONLY };
    };

    class NativeProcedureTable final
    {
    public:
        explicit NativeProcedureTable(HMODULE ntdll) noexcept :
            m_pfnNtAllocateVirtualMemory{ ResolveProcedure<TFnNtAllocateVirtualMemory>(
                ntdll,
                "NtAllocateVirtualMemory") },
            m_pfnNtProtectVirtualMemory{ ResolveProcedure<TFnNtProtectVirtualMemory>(
                ntdll,
                "NtProtectVirtualMemory") },
            m_pfnNtFreeVirtualMemory{ ResolveProcedure<TFnNtFreeVirtualMemory>(
                ntdll,
                "NtFreeVirtualMemory") }
        {
        }

        [[nodiscard]] bool IsValid() const noexcept
        {
            return nullptr != m_pfnNtAllocateVirtualMemory &&
                   nullptr != m_pfnNtProtectVirtualMemory &&
                   nullptr != m_pfnNtFreeVirtualMemory;
        }

        [[nodiscard]] NTSTATUS AllocateVirtualMemory(
            PVOID* baseAddress,
            PSIZE_T regionSize,
            const ULONG allocationType,
            const ULONG pageProtection) const noexcept
        {
            return m_pfnNtAllocateVirtualMemory(
                NtCurrentProcess(),
                baseAddress,
                0,
                regionSize,
                allocationType,
                pageProtection);
        }

        [[nodiscard]] NTSTATUS ProtectVirtualMemory(
            PVOID* baseAddress,
            PSIZE_T regionSize,
            const ULONG newProtection,
            PULONG oldProtection) const noexcept
        {
            return m_pfnNtProtectVirtualMemory(
                NtCurrentProcess(),
                baseAddress,
                regionSize,
                newProtection,
                oldProtection);
        }

        [[nodiscard]] NTSTATUS FreeVirtualMemory(PVOID* baseAddress) const noexcept
        {
            SIZE_T freeSize{};
            return m_pfnNtFreeVirtualMemory(
                NtCurrentProcess(),
                baseAddress,
                &freeSize,
                MEM_RELEASE);
        }

    private:
        TFnNtAllocateVirtualMemory* m_pfnNtAllocateVirtualMemory{};
        TFnNtProtectVirtualMemory* m_pfnNtProtectVirtualMemory{};
        TFnNtFreeVirtualMemory* m_pfnNtFreeVirtualMemory{};
    };

    class NativeVirtualAllocation final
    {
    public:
        // Keep probe setup honest: every allocation is released even when an
        // expectation fails or a later setup step returns early.
        NativeVirtualAllocation(const NativeProcedureTable& nativeProcedures, const SIZE_T requestedSize) noexcept :
            m_pNativeProcedures{ &nativeProcedures },
            m_requestedSize{ requestedSize },
            m_regionSize{ requestedSize }
        {
        }

        ~NativeVirtualAllocation() noexcept
        {
            Reset();
        }

        NativeVirtualAllocation(const NativeVirtualAllocation&) = delete;
        NativeVirtualAllocation& operator=(const NativeVirtualAllocation&) = delete;

        NativeVirtualAllocation(NativeVirtualAllocation&&) = delete;
        NativeVirtualAllocation& operator=(NativeVirtualAllocation&&) = delete;

        [[nodiscard]] NTSTATUS Allocate(const ULONG allocationType, const ULONG pageProtection) noexcept
        {
            Reset();
            m_regionSize = m_requestedSize;
            return m_pNativeProcedures->AllocateVirtualMemory(
                &m_baseAddress,
                &m_regionSize,
                allocationType,
                pageProtection);
        }

        void Reset() noexcept
        {
            if (nullptr == m_baseAddress)
            {
                return;
            }

            const NTSTATUS freeStatus{ m_pNativeProcedures->FreeVirtualMemory(&m_baseAddress) };
            if (NT_SUCCESS(freeStatus))
            {
                m_regionSize = m_requestedSize;
            }
        }

        [[nodiscard]] PVOID* BaseAddressPointer() noexcept
        {
            return &m_baseAddress;
        }

        [[nodiscard]] PSIZE_T RegionSizePointer() noexcept
        {
            return &m_regionSize;
        }

    private:
        const NativeProcedureTable* const m_pNativeProcedures{};
        PVOID m_baseAddress{};
        const SIZE_T m_requestedSize{};
        SIZE_T m_regionSize{};
    };

    [[nodiscard]] std::string ToHex(const std::uint64_t value)
    {
        return std::format("0x{:016X}", value);
    }

    [[nodiscard]] std::string Narrow(const std::wstring& text)
    {
        std::string result{};
        result.reserve(text.size());
        for (const wchar_t value : text)
        {
            result.push_back(static_cast<char>(value));
        }
        return result;
    }

    void PrintCatalogEntry(const SyscallEntry* entry, const char* label)
    {
        if (nullptr == entry)
        {
            std::cout << "catalog " << label << ": missing\n";
            return;
        }

        std::cout
            << "catalog " << label
            << ": " << Narrow(entry->ModuleName) << '!' << entry->FunctionName
            << " syscall=0x" << std::format("{:04X}", entry->Number)
            << " syscallAddress=" << ToHex(entry->SyscallAddress)
            << " expectedReturn=" << ToHex(entry->ExpectedReturnAddress);

        if (entry->Signature)
        {
            std::cout << " signatureArgs=" << entry->Signature->ArgumentCount();
        }
        else
        {
            std::cout << " signatureArgs=missing";
        }

        std::cout << '\n';
    }

    void PrintEvent(const DetectionEvent& event)
    {
        std::cout << "\n[" << event.ProbeName << "] " << ToString(event.Verdict) << '\n';
        std::cout << "  probe status: 0x" << std::format("{:08X}", static_cast<unsigned long>(event.ProbeStatus)) << '\n';
        std::cout << "  query status: 0x" << std::format("{:08X}", static_cast<unsigned long>(event.QueryStatus)) << '\n';
        std::cout << "  syscall: 0x" << std::format("{:04X}", event.ObservedSyscallNumber);
        if (false == event.ObservedFunctionName.empty())
        {
            std::cout << " (" << Narrow(event.ObservedModuleName) << '!' << event.ObservedFunctionName << ')';
        }
        std::cout << '\n';
        std::cout << "  previous pc: " << ToHex(event.PreviousProgramCounter) << '\n';

        if (false == event.ReturnAddressOwnerFunctionName.empty())
        {
            std::cout
                << "  previous pc owner: " << Narrow(event.ReturnAddressOwnerModuleName)
                << '!' << event.ReturnAddressOwnerFunctionName << '\n';
        }

        std::cout << "  arguments: " << event.FormattedArguments << '\n';

        if (false == event.ExpectedReturnCandidates.empty())
        {
            std::cout << "  expected returns for syscall:\n";
            for (const auto& candidate : event.ExpectedReturnCandidates)
            {
                std::cout
                    << "    " << Narrow(candidate.ModuleName) << '!' << candidate.FunctionName
                    << " -> " << ToHex(candidate.ExpectedReturnAddress) << '\n';
            }
        }
    }

    [[nodiscard]] bool ExpectVerdict(
        const DetectionEvent& event,
        const DetectionVerdict expectedVerdict,
        const std::string_view label)
    {
        const bool passed{ event.Verdict == expectedVerdict };
        std::cout
            << "expect " << label << ": "
            << (passed ? "pass" : "fail")
            << " (wanted " << ToString(expectedVerdict)
            << ", got " << ToString(event.Verdict) << ")\n";
        return passed;
    }
}

int main()
{
#if !defined(_M_AMD64) || defined(_M_ARM64EC)
    std::cout << "This demo must be built as a native AMD64/x64 process.\n";
    return DemoConstants::SetupFailureExitCode;
#endif

    HMODULE ntdll{ GetOrLoadModule(L"ntdll.dll") };
    if (nullptr == ntdll)
    {
        std::cout << "could not load ntdll.dll\n";
        return DemoConstants::SetupFailureExitCode;
    }

    const NativeProcedureTable nativeProcedures{ ntdll };
    if (false == nativeProcedures.IsValid())
    {
        std::cout << "native procedure lookup failed\n";
        return DemoConstants::SetupFailureExitCode;
    }

    SyscallCatalog catalog{ SyscallCatalog::BuildForCurrentProcess() };
    std::cout << "catalog entries: " << catalog.Entries().size() << '\n';
    std::cout << "generated signatures: " << GeneratedSyscallSignatureCount() << '\n';
    for (const auto& warning : catalog.Warnings())
    {
        std::cout << "catalog warning: " << warning << '\n';
    }

    const SyscallEntry* allocateEntry{ catalog.FindByFunctionName("NtAllocateVirtualMemory") };
    const SyscallEntry* protectEntry{ catalog.FindByFunctionName("NtProtectVirtualMemory") };
    const SyscallEntry* queryTimeEntry{ catalog.FindByFunctionName("NtQuerySystemTime") };
    const bool hasWin32uEntry{ std::ranges::any_of(
        catalog.Entries(),
        [](const SyscallEntry& entry)
        {
            return L"win32u.dll" == entry.ModuleName;
        }) };

    PrintCatalogEntry(allocateEntry, "NtAllocateVirtualMemory");
    PrintCatalogEntry(protectEntry, "NtProtectVirtualMemory");
    PrintCatalogEntry(queryTimeEntry, "NtQuerySystemTime");
    std::cout << "catalog win32u.dll entries: " << (hasWin32uEntry ? "present" : "missing") << '\n';

    if (nullptr == allocateEntry || nullptr == protectEntry || nullptr == queryTimeEntry || false == hasWin32uEntry)
    {
        return DemoConstants::SetupFailureExitCode;
    }

    // The MASM probes are intentionally data-driven: syscall IDs and the gadget
    // address come from the catalog built from this process' loaded images.
    ConfigureTestSyscalls(
        allocateEntry->Number,
        protectEntry->Number,
        queryTimeEntry->SyscallAddress);

    DetectorSession session{ catalog };
    std::cout << "instrumentation callback install: 0x"
              << std::format("{:08X}", static_cast<unsigned long>(session.InstallStatus())) << '\n';
    if (false == session.IsInstalled())
    {
        return DemoConstants::SetupFailureExitCode;
    }

    NativeVirtualAllocation baselineAllocation{
        nativeProcedures,
        DemoConstants::BaselineAllocationSize
    };
    // Control case: the syscall returns through the matching ntdll stub.
    DetectionEvent baselineEvent{ session.RunProbe(
        "baseline ntdll!NtAllocateVirtualMemory",
        [&]() -> NTSTATUS
        {
            return nativeProcedures.AllocateVirtualMemory(
                baselineAllocation.BaseAddressPointer(),
                baselineAllocation.RegionSizePointer(),
                DemoConstants::AllocationType,
                DemoConstants::ReadWriteProtection);
        }) };
    PrintEvent(baselineEvent);

    NativeVirtualAllocation rawAllocation{
        nativeProcedures,
        DemoConstants::RawAllocationSize
    };
    // Raw case: the syscall instruction lives in our MASM helper, so the
    // recovered syscall ID is valid but the return PC is outside the catalog.
    DetectionEvent rawAllocateEvent{ session.RunProbe(
        "raw MASM NtAllocateVirtualMemory",
        [&]() -> NTSTATUS
        {
            return DsdDirectNtAllocateVirtualMemory(
                NtCurrentProcess(),
                rawAllocation.BaseAddressPointer(),
                0,
                rawAllocation.RegionSizePointer(),
                DemoConstants::AllocationType,
                DemoConstants::ReadWriteProtection);
        }) };
    PrintEvent(rawAllocateEvent);

    NativeVirtualAllocation rawProtectAllocation{
        nativeProcedures,
        DemoConstants::ProtectAllocationSize
    };
    const NTSTATUS rawProtectAllocateStatus{ rawProtectAllocation.Allocate(
        DemoConstants::AllocationType,
        DemoConstants::ReadWriteProtection) };
    std::cout << "\nraw protect setup allocate status: 0x"
              << std::format("{:08X}", static_cast<unsigned long>(rawProtectAllocateStatus)) << '\n';
    if (false == NT_SUCCESS(rawProtectAllocateStatus))
    {
        return DemoConstants::SetupFailureExitCode;
    }

    ULONG rawOldProtection{};
    DetectionEvent rawProtectEvent{ session.RunProbe(
        "raw MASM NtProtectVirtualMemory",
        [&]() -> NTSTATUS
        {
            return DsdDirectNtProtectVirtualMemory(
                NtCurrentProcess(),
                rawProtectAllocation.BaseAddressPointer(),
                rawProtectAllocation.RegionSizePointer(),
                DemoConstants::ReadOnlyProtection,
                &rawOldProtection);
        }) };
    PrintEvent(rawProtectEvent);

    NativeVirtualAllocation gadgetProtectAllocation{
        nativeProcedures,
        DemoConstants::ProtectAllocationSize
    };
    const NTSTATUS gadgetProtectAllocateStatus{ gadgetProtectAllocation.Allocate(
        DemoConstants::AllocationType,
        DemoConstants::ReadWriteProtection) };
    std::cout << "\ngadget protect setup allocate status: 0x"
              << std::format("{:08X}", static_cast<unsigned long>(gadgetProtectAllocateStatus)) << '\n';
    if (false == NT_SUCCESS(gadgetProtectAllocateStatus))
    {
        return DemoConstants::SetupFailureExitCode;
    }

    ULONG gadgetOldProtection{};
    // Gadget case: the syscall ID says NtProtectVirtualMemory, but the return
    // PC belongs to NtQuerySystemTime's stub.
    DetectionEvent gadgetEvent{ session.RunProbe(
        "ntdll syscall gadget for NtProtectVirtualMemory",
        [&]() -> NTSTATUS
        {
            return DsdGadgetNtProtectVirtualMemory(
                NtCurrentProcess(),
                gadgetProtectAllocation.BaseAddressPointer(),
                gadgetProtectAllocation.RegionSizePointer(),
                DemoConstants::ReadOnlyProtection,
                &gadgetOldProtection);
        }) };
    PrintEvent(gadgetEvent);

    bool passed{ true };
    passed = ExpectVerdict(baselineEvent, DetectionVerdict::Clean, "baseline ntdll allocate") && passed;
    passed = ExpectVerdict(rawAllocateEvent, DetectionVerdict::RawDirectSyscall, "raw allocate") && passed;
    passed = ExpectVerdict(rawProtectEvent, DetectionVerdict::RawDirectSyscall, "raw protect") && passed;
    passed = ExpectVerdict(gadgetEvent, DetectionVerdict::SyscallGadgetMismatch, "ntdll gadget protect") && passed;

    return passed ? 0 : 1;
}
