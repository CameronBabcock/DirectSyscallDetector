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

#include "CallbackRing.h"

#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <process.h>

extern "C" void DsdInstrumentationCallbackThunk();

namespace DirectSyscallDetector
{
    namespace
    {
        struct DetectorConstants
        {
            constexpr static DWORD ProbeTimeoutMilliseconds{ 5000 };
            constexpr static std::uint32_t QueryRetryCount{ 64 };
            constexpr static NTSTATUS StatusQueryFallbackFailed{ static_cast<NTSTATUS>(0xE0000001) };
            constexpr static NTSTATUS StatusThreadStartFailed{ static_cast<NTSTATUS>(0xE0000002) };
            constexpr static NTSTATUS StatusThreadOpenFailed{ static_cast<NTSTATUS>(0xE0000003) };
            constexpr static NTSTATUS StatusThreadSuspendFailed{ static_cast<NTSTATUS>(0xE0000004) };
        };

        struct ReadyCallbackSlot
        {
            CallbackSlot* Slot{};
            std::size_t Index{};
        };

        class UniqueHandle final
        {
        public:
            explicit UniqueHandle(HANDLE handle = nullptr) noexcept :
                m_handle{ handle }
            {
            }

            ~UniqueHandle()
            {
                Reset();
            }

            UniqueHandle(const UniqueHandle&) = delete;
            UniqueHandle& operator=(const UniqueHandle&) = delete;

            UniqueHandle(UniqueHandle&& other) noexcept :
                m_handle{ other.Release() }
            {
            }

            UniqueHandle& operator=(UniqueHandle&& other) noexcept
            {
                if (this != &other)
                {
                    Reset(other.Release());
                }
                return *this;
            }

            [[nodiscard]] HANDLE Get() const noexcept
            {
                return m_handle;
            }

            [[nodiscard]] bool IsValid() const noexcept
            {
                return nullptr != m_handle;
            }

            [[nodiscard]] HANDLE Release() noexcept
            {
                HANDLE handle{ m_handle };
                m_handle = nullptr;
                return handle;
            }

            void Reset(HANDLE handle = nullptr) noexcept
            {
                if (nullptr != m_handle)
                {
                    CloseHandle(m_handle);
                }
                m_handle = handle;
            }

        private:
            HANDLE m_handle{};
        };

        class ScopedThreadSuspension final
        {
        public:
            explicit ScopedThreadSuspension(HANDLE threadHandle) noexcept :
                m_threadHandle{ threadHandle },
                m_suspendCount{ SuspendThread(threadHandle) },
                m_suspended{ static_cast<DWORD>(-1) != m_suspendCount }
            {
            }

            ~ScopedThreadSuspension()
            {
                if (m_suspended)
                {
                    ResumeThread(m_threadHandle);
                }
            }

            ScopedThreadSuspension(const ScopedThreadSuspension&) = delete;
            ScopedThreadSuspension& operator=(const ScopedThreadSuspension&) = delete;

            ScopedThreadSuspension(ScopedThreadSuspension&&) = delete;
            ScopedThreadSuspension& operator=(ScopedThreadSuspension&&) = delete;

            [[nodiscard]] bool IsSuspended() const noexcept
            {
                return m_suspended;
            }

        private:
            HANDLE m_threadHandle{};
            DWORD m_suspendCount{ static_cast<DWORD>(-1) };
            bool m_suspended{};
        };

        [[nodiscard]] volatile LONG64* AsInterlocked64(volatile std::uint64_t& value) noexcept
        {
            return reinterpret_cast<volatile LONG64*>(&value);
        }

        void ClearCallbackSlot(CallbackSlot& slot) noexcept
        {
            InterlockedExchange(const_cast<volatile LONG*>(&slot.State), static_cast<LONG>(CallbackSlotState::Free));
        }

        void ReleaseAllCallbackSlots() noexcept
        {
            for (std::size_t index = 0; index < CallbackSlotCount; ++index)
            {
                ClearCallbackSlot(g_DsdCallbackSlots[index]);
            }
        }

        void ResetCallbackSlots() noexcept
        {
            for (std::size_t index = 0; index < CallbackSlotCount; ++index)
            {
                auto& slot{ g_DsdCallbackSlots[index] };
                ClearCallbackSlot(slot);
                InterlockedExchange64(AsInterlocked64(slot.ThreadId), 0);
                InterlockedExchange64(AsInterlocked64(slot.PreviousProgramCounter), 0);
                InterlockedExchange64(AsInterlocked64(slot.StackPointer), 0);
                InterlockedExchange64(AsInterlocked64(slot.StackArgument5), 0);
                InterlockedExchange64(AsInterlocked64(slot.StackArgument6), 0);
                InterlockedExchange64(AsInterlocked64(slot.Reserved1), 0);
                InterlockedExchange64(AsInterlocked64(slot.Reserved2), 0);
            }
        }

        void ResetCallbackState() noexcept
        {
            InterlockedExchange(const_cast<volatile LONG*>(&g_DsdCallbackArmed), 0);
            InterlockedExchange64(AsInterlocked64(g_DsdTargetThreadId), 0);
            ResetCallbackSlots();
        }

        [[nodiscard]] bool SpinUntilEquals(volatile LONG& value, const LONG desired, const DWORD timeoutMilliseconds) noexcept
        {
            const ULONGLONG deadline{ GetTickCount64() + timeoutMilliseconds };
            while (desired != value)
            {
                if (GetTickCount64() > deadline)
                {
                    return false;
                }
                YieldProcessor();
            }
            return true;
        }

        [[nodiscard]] std::optional<ReadyCallbackSlot> FindReadyCallbackSlot() noexcept
        {
            for (std::size_t index = 0; index < CallbackSlotCount; ++index)
            {
                if (static_cast<LONG>(CallbackSlotState::Ready) == g_DsdCallbackSlots[index].State)
                {
                    return ReadyCallbackSlot{
                        .Slot = &g_DsdCallbackSlots[index],
                        .Index = index
                    };
                }
            }

            return std::nullopt;
        }

        [[nodiscard]] std::optional<ReadyCallbackSlot> WaitForReadyCallbackSlot(
            volatile LONG& workerDone,
            const DWORD timeoutMilliseconds) noexcept
        {
            const ULONGLONG deadline{ GetTickCount64() + timeoutMilliseconds };
            while (0 == workerDone)
            {
                auto readySlot{ FindReadyCallbackSlot() };
                if (readySlot.has_value())
                {
                    return readySlot;
                }

                if (GetTickCount64() > deadline)
                {
                    return std::nullopt;
                }
                YieldProcessor();
            }

            return FindReadyCallbackSlot();
        }

        [[nodiscard]] UniqueHandle BeginThread(unsigned(__stdcall* startAddress)(void*), void* context, unsigned* threadId)
        {
            const auto rawHandle{ _beginthreadex(nullptr, 0, startAddress, context, 0, threadId) };
            return UniqueHandle{ reinterpret_cast<HANDLE>(rawHandle) };
        }

        [[nodiscard]] CallbackRecord CopyCallbackRecord(const ReadyCallbackSlot& readySlot) noexcept
        {
            const auto& slot{ *readySlot.Slot };
            return CallbackRecord{
                .SlotIndex = readySlot.Index,
                .ThreadId = static_cast<DWORD>(slot.ThreadId),
                .PreviousProgramCounter = static_cast<std::uintptr_t>(slot.PreviousProgramCounter),
                .StackPointer = slot.StackPointer,
                .StackArgument5 = slot.StackArgument5,
                .StackArgument6 = slot.StackArgument6
            };
        }
    }

    struct DetectorSession::WorkerContext
    {
        TFnProbeInvoker ProbeInvoker{};
        void* ProbeContext{};
        volatile LONG Started{};
        volatile LONG Go{};
        volatile LONG Done{};
        NTSTATUS ProbeStatus{ STATUS_UNSUCCESSFUL };
    };

    struct DetectorSession::MonitorContext
    {
        const DetectorSession* Session{};
        WorkerContext* Worker{};
        HANDLE WorkerThread{};
        DWORD WorkerThreadId{};
        std::string ProbeName{};
        DetectionEvent Event{};
        volatile LONG Done{};
    };

    DetectorSession::DetectorSession(const SyscallCatalog& catalog) :
        m_catalog{ catalog },
        m_ntdll{ GetOrLoadModule(L"ntdll.dll") }
    {
        m_pfnNtSetInformationProcess = ResolveProcedure<TFnNtSetInformationProcess>(
            m_ntdll,
            "NtSetInformationProcess");
        m_pfnNtQueryInformationThread = ResolveProcedure<TFnNtQueryInformationThread>(
            m_ntdll,
            "NtQueryInformationThread");

        if (nullptr == m_pfnNtSetInformationProcess || nullptr == m_pfnNtQueryInformationThread)
        {
            m_installStatus = STATUS_PROCEDURE_NOT_FOUND;
            return;
        }

        m_installStatus = SetInstrumentationCallback(reinterpret_cast<PVOID>(&DsdInstrumentationCallbackThunk));
        m_installed = NT_SUCCESS(m_installStatus);
    }

    DetectorSession::~DetectorSession()
    {
        ResetCallbackState();
        if (m_installed)
        {
            m_clearStatus = SetInstrumentationCallback(nullptr);
            m_installed = false;
        }
    }

    bool DetectorSession::IsInstalled() const noexcept
    {
        return m_installed;
    }

    NTSTATUS DetectorSession::InstallStatus() const noexcept
    {
        return m_installStatus;
    }

    NTSTATUS DetectorSession::ClearStatus() const noexcept
    {
        return m_clearStatus;
    }

    DetectionEvent DetectorSession::RunProbeImpl(
        const std::string_view probeName,
        const TFnProbeInvoker probeInvoker,
        void* probeContext)
    {
        DetectionEvent event{};
        event.ProbeName = std::string{ probeName };

        if (false == m_installed)
        {
            event.Verdict = DetectionVerdict::WorkerFailed;
            event.QueryStatus = m_installStatus;
            return event;
        }

        ResetCallbackState();

        WorkerContext worker{
            .ProbeInvoker = probeInvoker,
            .ProbeContext = probeContext
        };

        unsigned workerThreadId{};
        UniqueHandle workerThread{ BeginThread(&DetectorSession::WorkerThreadProc, &worker, &workerThreadId) };
        if (false == workerThread.IsValid())
        {
            event.Verdict = DetectionVerdict::WorkerFailed;
            event.QueryStatus = DetectorConstants::StatusThreadStartFailed;
            return event;
        }

        if (false == SpinUntilEquals(worker.Started, 1, DetectorConstants::ProbeTimeoutMilliseconds))
        {
            event.Verdict = DetectionVerdict::WorkerFailed;
            return event;
        }

        MonitorContext monitor{
            .Session = this,
            .Worker = &worker,
            .WorkerThread = workerThread.Get(),
            .WorkerThreadId = workerThreadId,
            .ProbeName = std::string{ probeName }
        };

        // Single-flight by design: one armed worker enters the syscall, the
        // MASM callback publishes a slot, and this monitor queries the paused
        // worker from the outside. Native APIs stay out of the callback thunk.
        unsigned monitorThreadId{};
        UniqueHandle monitorThread{ BeginThread(&DetectorSession::MonitorThreadProc, &monitor, &monitorThreadId) };
        if (false == monitorThread.IsValid())
        {
            InterlockedExchange(const_cast<volatile LONG*>(&worker.Go), 1);
            WaitForSingleObject(workerThread.Get(), DetectorConstants::ProbeTimeoutMilliseconds);
            event.Verdict = DetectionVerdict::WorkerFailed;
            event.QueryStatus = DetectorConstants::StatusThreadStartFailed;
            return event;
        }

        InterlockedExchange(const_cast<volatile LONG*>(&g_DsdCallbackArmed), 1);
        InterlockedExchange(const_cast<volatile LONG*>(&worker.Go), 1);

        if (WAIT_TIMEOUT == WaitForSingleObject(monitorThread.Get(), DetectorConstants::ProbeTimeoutMilliseconds))
        {
            InterlockedExchange(const_cast<volatile LONG*>(&g_DsdCallbackArmed), 0);
            ReleaseAllCallbackSlots();
            WaitForSingleObject(monitorThread.Get(), INFINITE);
        }

        if (WAIT_TIMEOUT == WaitForSingleObject(workerThread.Get(), DetectorConstants::ProbeTimeoutMilliseconds))
        {
            ReleaseAllCallbackSlots();
            WaitForSingleObject(workerThread.Get(), INFINITE);
        }

        event = std::move(monitor.Event);
        event.WorkerCompleted = 0 != worker.Done;
        event.ProbeStatus = worker.ProbeStatus;
        return event;
    }

    DetectionEvent DetectorSession::Classify(
        const std::string_view probeName,
        const NTSTATUS probeStatus,
        const THREAD_LAST_SYSCALL_INFORMATION& threadLastSyscall,
        const NTSTATUS queryStatus,
        const ULONG queryReturnLength,
        const CallbackRecord& callbackRecord) const
    {
        DetectionEvent event{};
        event.ProbeName = std::string{ probeName };
        event.ProbeStatus = probeStatus;
        event.QueryStatus = queryStatus;
        event.QueryReturnLength = queryReturnLength;
        event.QuerySucceeded = NT_SUCCESS(queryStatus);
        event.CallbackObserved = true;
        event.ObservedSyscallNumber = threadLastSyscall.SystemCallNumber;
        event.FirstArgument = reinterpret_cast<std::uint64_t>(threadLastSyscall.FirstArgument);
        event.StackArgument5 = callbackRecord.StackArgument5;
        event.StackArgument6 = callbackRecord.StackArgument6;
        event.PreviousProgramCounter = callbackRecord.PreviousProgramCounter;
        event.ExpectedReturnCandidates = m_catalog.ExpectedReturnsForSyscall(event.ObservedSyscallNumber);

        const SyscallEntry* returnAddressOwner{ m_catalog.FindByReturnAddress(event.PreviousProgramCounter) };
        const SyscallEntry* observedEntry{ m_catalog.FindPrimaryBySyscallNumber(event.ObservedSyscallNumber) };

        // The recovered syscall ID decides which syscall ran. The previous PC
        // decides whether it returned through the expected stub, a gadget, or
        // raw code outside the catalog.
        if (nullptr != observedEntry)
        {
            event.ObservedFunctionName = observedEntry->FunctionName;
            event.ObservedModuleName = observedEntry->ModuleName;

            ArgumentSnapshot snapshot{
                .FirstArgument = event.FirstArgument,
                .StackArgument5 = event.StackArgument5,
                .StackArgument6 = event.StackArgument6,
                .HasStackArgument5 = observedEntry->Signature && observedEntry->Signature->ArgumentCount() >= 5,
                .HasStackArgument6 = observedEntry->Signature && observedEntry->Signature->ArgumentCount() >= 6
            };

            if (observedEntry->Signature)
            {
                event.FormattedArguments = observedEntry->Signature->FormatArguments(snapshot);
            }
        }

        if (nullptr != returnAddressOwner)
        {
            event.ReturnAddressOwnerFunctionName = returnAddressOwner->FunctionName;
            event.ReturnAddressOwnerModuleName = returnAddressOwner->ModuleName;
            event.ReturnAddressOwnerExpectedReturn = returnAddressOwner->ExpectedReturnAddress;
        }

        if (false == NT_SUCCESS(queryStatus))
        {
            event.Verdict = DetectionVerdict::QueryFailed;
        }
        else if (nullptr == observedEntry)
        {
            event.Verdict = DetectionVerdict::UnknownSyscall;
        }
        else if (nullptr == returnAddressOwner)
        {
            event.Verdict = DetectionVerdict::RawDirectSyscall;
        }
        else if (returnAddressOwner->Number != event.ObservedSyscallNumber)
        {
            event.Verdict = DetectionVerdict::SyscallGadgetMismatch;
        }
        else
        {
            event.Verdict = DetectionVerdict::Clean;
        }

        if (event.FormattedArguments.empty())
        {
            event.FormattedArguments = std::format("FirstArgument=0x{:016X}", event.FirstArgument);
        }

        return event;
    }

    NTSTATUS DetectorSession::SetInstrumentationCallback(PVOID callback) const noexcept
    {
        PVOID rawCallback{ callback };
        NTSTATUS status{ m_pfnNtSetInformationProcess(
            NtCurrentProcess(),
            ProcessInstrumentationCallback,
            &rawCallback,
            sizeof(rawCallback)) };

        if (NT_SUCCESS(status))
        {
            return status;
        }

        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION callbackInfo{};
        callbackInfo.Callback = callback;
        return m_pfnNtSetInformationProcess(
            NtCurrentProcess(),
            ProcessInstrumentationCallback,
            &callbackInfo,
            sizeof(callbackInfo));
    }

    bool DetectorSession::QueryThreadLastSyscall(
        const HANDLE threadHandle,
        THREAD_LAST_SYSCALL_INFORMATION& info,
        NTSTATUS& status,
        ULONG& returnLength) const noexcept
    {
        status = m_pfnNtQueryInformationThread(
            threadHandle,
            ThreadLastSystemCall,
            &info,
            sizeof(info),
            &returnLength);

        if (NT_SUCCESS(status))
        {
            return true;
        }

        // Some systems expose the older, shorter ThreadLastSystemCall layout.
        // Preserve the useful fields instead of failing the probe outright.
        struct ThreadLastSyscallInformationV1
        {
            PVOID FirstArgument{};
            USHORT SystemCallNumber{};
            USHORT Reserved0{};
            ULONG Reserved1{};
        };

        ThreadLastSyscallInformationV1 fallbackInfo{};
        returnLength = 0;
        status = m_pfnNtQueryInformationThread(
            threadHandle,
            ThreadLastSystemCall,
            &fallbackInfo,
            sizeof(fallbackInfo),
            &returnLength);

        if (false == NT_SUCCESS(status))
        {
            return false;
        }

        info = {};
        info.FirstArgument = fallbackInfo.FirstArgument;
        info.SystemCallNumber = fallbackInfo.SystemCallNumber;
        return true;
    }

    unsigned DetectorSession::WorkerThreadProc(void* parameter) noexcept
    {
        auto& worker{ *static_cast<WorkerContext*>(parameter) };

        InterlockedExchange64(AsInterlocked64(g_DsdTargetThreadId), static_cast<LONG64>(GetCurrentThreadId()));
        InterlockedExchange(const_cast<volatile LONG*>(&worker.Started), 1);

        while (0 == worker.Go)
        {
            YieldProcessor();
        }

        worker.ProbeStatus = worker.ProbeInvoker(worker.ProbeContext);
        InterlockedExchange(const_cast<volatile LONG*>(&worker.Done), 1);
        return static_cast<unsigned>(worker.ProbeStatus);
    }

    unsigned DetectorSession::MonitorThreadProc(void* parameter) noexcept
    {
        auto& monitor{ *static_cast<MonitorContext*>(parameter) };

        auto readySlot{ WaitForReadyCallbackSlot(
            monitor.Worker->Done,
            DetectorConstants::ProbeTimeoutMilliseconds) };

        if (false == readySlot.has_value())
        {
            InterlockedExchange(const_cast<volatile LONG*>(&g_DsdCallbackArmed), 0);
            ReleaseAllCallbackSlots();

            monitor.Event.ProbeName = monitor.ProbeName;
            monitor.Event.Verdict = DetectionVerdict::CallbackNotObserved;
            monitor.Event.ProbeStatus = monitor.Worker->ProbeStatus;
            monitor.Event.CallbackObserved = false;
            InterlockedExchange(const_cast<volatile LONG*>(&monitor.Done), 1);
            return 1;
        }

        const CallbackRecord callbackRecord{ CopyCallbackRecord(*readySlot) };
        UniqueHandle openedThread{};
        HANDLE threadHandle{};
        if (callbackRecord.ThreadId == monitor.WorkerThreadId)
        {
            threadHandle = monitor.WorkerThread;
        }
        else
        {
            constexpr DWORD ThreadAccessMask{ THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME };
            openedThread.Reset(OpenThread(ThreadAccessMask, FALSE, callbackRecord.ThreadId));
            threadHandle = openedThread.Get();
        }

        THREAD_LAST_SYSCALL_INFORMATION threadLastSyscall{};
        NTSTATUS queryStatus{ DetectorConstants::StatusQueryFallbackFailed };
        ULONG queryReturnLength{};

        if (nullptr == threadHandle)
        {
            queryStatus = DetectorConstants::StatusThreadOpenFailed;
        }
        else
        {
            // Suspending here gives NtQueryInformationThread a stable target
            // while the callback is spinning on its slot state.
            ScopedThreadSuspension threadSuspension{ threadHandle };
            if (false == threadSuspension.IsSuspended())
            {
                queryStatus = DetectorConstants::StatusThreadSuspendFailed;
            }
            else
            {
                for (std::uint32_t attempt = 0; attempt < DetectorConstants::QueryRetryCount; ++attempt)
                {
                    if (monitor.Session->QueryThreadLastSyscall(
                            threadHandle,
                            threadLastSyscall,
                            queryStatus,
                            queryReturnLength))
                    {
                        break;
                    }

                    YieldProcessor();
                    SwitchToThread();
                }
            }
            ClearCallbackSlot(*readySlot->Slot);
        }

        monitor.Event = monitor.Session->Classify(
            monitor.ProbeName,
            monitor.Worker->ProbeStatus,
            threadLastSyscall,
            queryStatus,
            queryReturnLength,
            callbackRecord);

        InterlockedExchange(const_cast<volatile LONG*>(&g_DsdCallbackArmed), 0);
        ClearCallbackSlot(*readySlot->Slot);
        InterlockedExchange(const_cast<volatile LONG*>(&monitor.Done), 1);
        return 0;
    }

    std::string ToString(const DetectionVerdict verdict)
    {
        switch (verdict)
        {
        case DetectionVerdict::Clean:
            return "clean";
        case DetectionVerdict::RawDirectSyscall:
            return "raw direct syscall";
        case DetectionVerdict::SyscallGadgetMismatch:
            return "syscall-return mismatch";
        case DetectionVerdict::UnknownSyscall:
            return "unknown syscall";
        case DetectionVerdict::CallbackNotObserved:
            return "callback not observed";
        case DetectionVerdict::QueryFailed:
            return "query failed";
        case DetectionVerdict::WorkerFailed:
            return "worker failed";
        default:
            return "unrecognized";
        }
    }
}
