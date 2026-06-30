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
#include "DirectSyscallDetector/SyscallCatalog.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace DirectSyscallDetector
{
    struct CallbackRecord;

    enum class DetectionVerdict
    {
        Clean,
        RawDirectSyscall,
        SyscallGadgetMismatch,
        UnknownSyscall,
        CallbackNotObserved,
        QueryFailed,
        WorkerFailed
    };

    struct DetectionEvent
    {
        std::string ProbeName{};
        DetectionVerdict Verdict{ DetectionVerdict::CallbackNotObserved };
        NTSTATUS ProbeStatus{ STATUS_UNSUCCESSFUL };
        NTSTATUS QueryStatus{ STATUS_UNSUCCESSFUL };
        ULONG QueryReturnLength{};
        std::uint32_t ObservedSyscallNumber{};
        std::uint64_t FirstArgument{};
        std::uint64_t StackArgument5{};
        std::uint64_t StackArgument6{};
        std::uintptr_t PreviousProgramCounter{};
        std::string ObservedFunctionName{};
        std::wstring ObservedModuleName{};
        std::string ReturnAddressOwnerFunctionName{};
        std::wstring ReturnAddressOwnerModuleName{};
        std::uintptr_t ReturnAddressOwnerExpectedReturn{};
        std::vector<ExpectedReturnCandidate> ExpectedReturnCandidates{};
        std::string FormattedArguments{};
        bool CallbackObserved{};
        bool QuerySucceeded{};
        bool WorkerCompleted{};
    };

    class DetectorSession
    {
    public:
        explicit DetectorSession(const SyscallCatalog& catalog);
        ~DetectorSession();

        DetectorSession(const DetectorSession&) = delete;
        DetectorSession& operator=(const DetectorSession&) = delete;

        DetectorSession(DetectorSession&&) = delete;
        DetectorSession& operator=(DetectorSession&&) = delete;

        [[nodiscard]] bool IsInstalled() const noexcept;
        [[nodiscard]] NTSTATUS InstallStatus() const noexcept;
        [[nodiscard]] NTSTATUS ClearStatus() const noexcept;

        template <typename TProbe>
        [[nodiscard]] DetectionEvent RunProbe(std::string_view probeName, TProbe&& probe)
        {
            auto probeThunk = [](void* context) -> NTSTATUS
            {
                return (*static_cast<std::remove_reference_t<TProbe>*>(context))();
            };

            return RunProbeImpl(probeName, probeThunk, &probe);
        }

    private:
        using TFnProbeInvoker = NTSTATUS(__cdecl*)(void*);
        using TFnNtSetInformationProcess = std::remove_pointer_t<decltype(&NtSetInformationProcess)>;
        using TFnNtQueryInformationThread = std::remove_pointer_t<decltype(&NtQueryInformationThread)>;

        struct WorkerContext;
        struct MonitorContext;

        [[nodiscard]] DetectionEvent RunProbeImpl(std::string_view probeName, TFnProbeInvoker probeInvoker, void* probeContext);
        [[nodiscard]] DetectionEvent Classify(std::string_view probeName, NTSTATUS probeStatus, const THREAD_LAST_SYSCALL_INFORMATION& threadLastSyscall, NTSTATUS queryStatus, ULONG queryReturnLength, const CallbackRecord& callbackRecord) const;
        [[nodiscard]] NTSTATUS SetInstrumentationCallback(PVOID callback) const noexcept;
        [[nodiscard]] bool QueryThreadLastSyscall(HANDLE threadHandle, THREAD_LAST_SYSCALL_INFORMATION& info, NTSTATUS& status, ULONG& returnLength) const noexcept;

        static unsigned __stdcall WorkerThreadProc(void* parameter) noexcept;
        static unsigned __stdcall MonitorThreadProc(void* parameter) noexcept;

        const SyscallCatalog& m_catalog;
        HMODULE m_ntdll{};
        TFnNtSetInformationProcess* m_pfnNtSetInformationProcess{};
        TFnNtQueryInformationThread* m_pfnNtQueryInformationThread{};
        NTSTATUS m_installStatus{ STATUS_UNSUCCESSFUL };
        NTSTATUS m_clearStatus{ STATUS_UNSUCCESSFUL };
        bool m_installed{};
    };

    [[nodiscard]] std::string ToString(DetectionVerdict verdict);
}
