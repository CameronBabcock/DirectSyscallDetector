#define WIN32_LEAN_AND_MEAN
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

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

using NtStatus = LONG;

extern "C" void AllocPicCallbackThunk();
extern "C" NtStatus DirectNtAllocateVirtualMemory(
    HANDLE process,
    PVOID *base_address,
    ULONG_PTR zero_bits,
    PSIZE_T region_size,
    ULONG allocation_type,
    ULONG protect);
extern "C" void DirectNtAllocateVirtualMemoryReturn();

extern "C" volatile std::uint32_t g_AllocSyscallNumber = 0;

extern "C" __declspec(align(64)) volatile LONG g_AllocBegin = 0;
extern "C" __declspec(align(64)) volatile LONG g_AllocWorkerStarted = 0;
extern "C" __declspec(align(64)) volatile LONG g_AllocWorkerDone = 0;
extern "C" __declspec(align(64)) volatile LONG g_AllocMonitorDone = 0;
extern "C" __declspec(align(64)) volatile LONG g_AllocCbReady = 0;
extern "C" __declspec(align(64)) volatile LONG g_AllocCbAck = 0;

extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbCount = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbDirectHits = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbPrevPc = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbRax = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbRcx = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbRdx = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbR8 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbR9 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbRsp = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbStackArg5 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbStackArg6 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbBaseValue = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbRegionValue = 0;
extern "C" __declspec(align(64)) volatile std::uint32_t g_AllocCbDecodedSyscall = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbHome1 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbHome2 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbHome3 = 0;
extern "C" __declspec(align(64)) volatile std::uint64_t g_AllocCbHome4 = 0;

using NtSetInformationProcessFn = NtStatus(NTAPI *)(HANDLE, ULONG, PVOID, ULONG);
using NtQueryInformationThreadFn = NtStatus(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtFreeVirtualMemoryFn = NtStatus(NTAPI *)(HANDLE, PVOID *, PSIZE_T, ULONG);

constexpr NtStatus StatusSuccess = 0;
constexpr ULONG ProcessInstrumentationCallback = 0x28;
constexpr ULONG ThreadLastSystemCall = 21;

struct PicInfo16 {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};

struct ThreadLastSyscallInfo {
    PVOID FirstArgument;
    USHORT SystemCallNumber;
    USHORT Reserved0;
    ULONG Reserved1;
};

static_assert(sizeof(ThreadLastSyscallInfo) == 0x10);

struct SharedState {
    NtQueryInformationThreadFn NtQueryInformationThread = nullptr;
    HANDLE WorkerThread = nullptr;
    volatile LONG WorkerStatus = 0x55555555;
    volatile LONG LastQueryStatus = 0x55555555;
    volatile LONG LastReturnLength = 0;
    volatile LONG QueryAttempts = 0;
    volatile LONG MonitorSawCallbackSnapshot = 0;
    volatile LONG MonitorSawThreadLastSyscall = 0;
    ThreadLastSyscallInfo LastSyscall = {};
    volatile std::uint64_t WorkerBase = 0;
    volatile std::uint64_t WorkerSize = 0;
};

static SharedState g_State;

static void spin_until(volatile LONG *value, LONG desired)
{
    while (*value != desired) {
        YieldProcessor();
    }
}

static bool extract_syscall_number(void *ntdll_stub, std::uint32_t *syscall_number)
{
    const auto *bytes = static_cast<const std::uint8_t *>(ntdll_stub);

    for (std::size_t i = 0; i < 32; ++i) {
        if (bytes[i] != 0xB8) {
            continue;
        }

        bool has_syscall = false;
        for (std::size_t j = i + 5; j + 1 < 32; ++j) {
            if (bytes[j] == 0x0F && bytes[j + 1] == 0x05) {
                has_syscall = true;
                break;
            }
        }

        if (!has_syscall) {
            continue;
        }

        std::memcpy(syscall_number, bytes + i + 1, sizeof(*syscall_number));
        return true;
    }

    return false;
}

static NtStatus set_process_instrumentation_callback(NtSetInformationProcessFn nt_set, PVOID callback)
{
    PVOID raw_callback = callback;
    NtStatus status = nt_set(
        GetCurrentProcess(),
        ProcessInstrumentationCallback,
        &raw_callback,
        sizeof(raw_callback));

    if (status == StatusSuccess) {
        return status;
    }

    PicInfo16 info{};
    info.Callback = callback;
    return nt_set(
        GetCurrentProcess(),
        ProcessInstrumentationCallback,
        &info,
        sizeof(info));
}

static DWORD WINAPI worker_thread(void *)
{
    InterlockedExchange(const_cast<LONG *>(&g_AllocWorkerStarted), 1);
    spin_until(&g_AllocBegin, 1);

    PVOID base = nullptr;
    SIZE_T region_size = 0x3000;

    NtStatus status = DirectNtAllocateVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &base,
        0,
        &region_size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (status == StatusSuccess && base) {
        *static_cast<volatile std::uint32_t *>(base) = 0xA110CA7E;
    }

    g_State.WorkerBase = reinterpret_cast<std::uint64_t>(base);
    g_State.WorkerSize = static_cast<std::uint64_t>(region_size);
    InterlockedExchange(const_cast<LONG *>(&g_State.WorkerStatus), status);
    InterlockedExchange(const_cast<LONG *>(&g_AllocWorkerDone), 1);
    return static_cast<DWORD>(status);
}

static DWORD WINAPI monitor_thread(void *)
{
    spin_until(&g_AllocWorkerStarted, 1);
    InterlockedExchange(const_cast<LONG *>(&g_AllocBegin), 1);

    constexpr std::uint32_t CallbackSpinLimit = 100000000;
    std::uint32_t spins = 0;
    while (g_AllocCbReady == 0 && spins++ < CallbackSpinLimit) {
        YieldProcessor();
    }

    if (g_AllocCbReady != 0) {
        if (g_AllocCbPrevPc == reinterpret_cast<std::uint64_t>(&DirectNtAllocateVirtualMemoryReturn) &&
            g_AllocCbDecodedSyscall == (g_AllocSyscallNumber & 0xffffu) &&
            g_AllocCbStackArg5 == (MEM_RESERVE | MEM_COMMIT) &&
            g_AllocCbStackArg6 == PAGE_READWRITE) {
            InterlockedExchange(const_cast<LONG *>(&g_State.MonitorSawCallbackSnapshot), 1);
        }

        ThreadLastSyscallInfo info{};

        for (std::uint32_t i = 0; i < 8; ++i) {
            ULONG return_length = 0;
            NtStatus status = g_State.NtQueryInformationThread(
                g_State.WorkerThread,
                ThreadLastSystemCall,
                &info,
                sizeof(info),
                &return_length);

            InterlockedIncrement(const_cast<LONG *>(&g_State.QueryAttempts));
            InterlockedExchange(const_cast<LONG *>(&g_State.LastQueryStatus), status);
            InterlockedExchange(const_cast<LONG *>(&g_State.LastReturnLength), static_cast<LONG>(return_length));

            if (status == StatusSuccess) {
                g_State.LastSyscall = info;
                if (info.SystemCallNumber == (g_AllocSyscallNumber & 0xffffu) &&
                    info.FirstArgument == reinterpret_cast<HANDLE>(-1)) {
                    InterlockedExchange(const_cast<LONG *>(&g_State.MonitorSawThreadLastSyscall), 1);
                    break;
                }
            }

            YieldProcessor();
        }
    }

    InterlockedExchange(const_cast<LONG *>(&g_AllocCbAck), 1);
    InterlockedExchange(const_cast<LONG *>(&g_AllocMonitorDone), 1);
    return g_State.MonitorSawCallbackSnapshot ? 0 : 1;
}

static void print_status(const char *name, NtStatus status)
{
    std::printf("%-38s 0x%08lx\n", name, static_cast<unsigned long>(status));
}

static void print_u64(const char *name, std::uint64_t value)
{
    std::printf("%-38s 0x%016llx\n", name, static_cast<unsigned long long>(value));
}

int main()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        std::puts("GetModuleHandleW(ntdll.dll) failed");
        return 2;
    }

    auto nt_set = reinterpret_cast<NtSetInformationProcessFn>(
        GetProcAddress(ntdll, "NtSetInformationProcess"));
    auto nt_query_thread = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
    auto nt_free = reinterpret_cast<NtFreeVirtualMemoryFn>(
        GetProcAddress(ntdll, "NtFreeVirtualMemory"));
    void *nt_allocate = reinterpret_cast<void *>(
        GetProcAddress(ntdll, "NtAllocateVirtualMemory"));

    if (!nt_set || !nt_query_thread || !nt_free || !nt_allocate) {
        std::puts("native API lookup failed");
        return 2;
    }

    std::uint32_t syscall_number = 0;
    if (!extract_syscall_number(nt_allocate, &syscall_number)) {
        std::puts("could not extract NtAllocateVirtualMemory syscall number from ntdll stub");
        return 2;
    }

    g_AllocSyscallNumber = syscall_number;
    g_State.NtQueryInformationThread = nt_query_thread;

    NtStatus set_status = set_process_instrumentation_callback(
        nt_set,
        reinterpret_cast<PVOID>(&AllocPicCallbackThunk));

    g_State.WorkerThread = CreateThread(nullptr, 0, worker_thread, nullptr, 0, nullptr);
    HANDLE monitor = CreateThread(nullptr, 0, monitor_thread, nullptr, 0, nullptr);

    if (!g_State.WorkerThread || !monitor) {
        std::puts("CreateThread failed");
        set_process_instrumentation_callback(nt_set, nullptr);
        return 2;
    }

    while (g_AllocWorkerDone == 0 || g_AllocMonitorDone == 0) {
        YieldProcessor();
    }

    NtStatus clear_status = set_process_instrumentation_callback(nt_set, nullptr);

    NtStatus free_status = 0x55555555;
    if (g_State.WorkerBase != 0) {
        PVOID base = reinterpret_cast<PVOID>(g_State.WorkerBase);
        SIZE_T free_size = 0;
        free_status = nt_free(GetCurrentProcess(), &base, &free_size, MEM_RELEASE);
    }

    CloseHandle(monitor);
    CloseHandle(g_State.WorkerThread);

    const bool callback_prev_pc_match =
        g_AllocCbPrevPc == reinterpret_cast<std::uint64_t>(&DirectNtAllocateVirtualMemoryReturn);
    const bool callback_decoded_syscall_match =
        g_AllocCbDecodedSyscall == (g_AllocSyscallNumber & 0xffffu);
    const bool callback_arg1_match =
        g_AllocCbRcx == reinterpret_cast<std::uint64_t>(reinterpret_cast<HANDLE>(-1));
    const bool callback_arg2_pointer_nonzero = g_AllocCbRdx != 0;
    const bool callback_arg3_match = g_AllocCbR8 == 0;
    const bool callback_arg4_pointer_nonzero = g_AllocCbR9 != 0;
    const bool callback_arg5_match = g_AllocCbStackArg5 == (MEM_RESERVE | MEM_COMMIT);
    const bool callback_arg6_match = g_AllocCbStackArg6 == PAGE_READWRITE;
    const bool callback_base_matches_worker = g_AllocCbBaseValue != 0 && g_AllocCbBaseValue == g_State.WorkerBase;

    std::printf("ntdll!NtAllocateVirtualMemory        %p\n", nt_allocate);
    std::printf("direct syscall stub                  %p\n", reinterpret_cast<void *>(&DirectNtAllocateVirtualMemory));
    std::printf("direct syscall return label          %p\n", reinterpret_cast<void *>(&DirectNtAllocateVirtualMemoryReturn));
    std::printf("pic callback                         %p\n", reinterpret_cast<void *>(&AllocPicCallbackThunk));
    std::printf("expected syscall number              0x%04x\n", syscall_number & 0xffffu);
    print_status("set callback status", set_status);
    print_status("clear callback status", clear_status);
    print_status("worker direct allocate status", g_State.WorkerStatus);
    print_status("free status", free_status);
    std::printf("worker allocated base                %p\n", reinterpret_cast<void *>(g_State.WorkerBase));
    print_u64("worker region size", g_State.WorkerSize);
    std::printf("callback ready                       %ld\n", g_AllocCbReady);
    std::printf("callback ack                         %ld\n", g_AllocCbAck);
    print_u64("callback count", g_AllocCbCount);
    print_u64("callback direct hits", g_AllocCbDirectHits);
    print_u64("callback previous pc", g_AllocCbPrevPc);
    std::printf("%-38s 0x%04x\n", "callback decoded syscall", g_AllocCbDecodedSyscall);
    print_u64("callback return rax", g_AllocCbRax);
    print_u64("callback arg1 rcx/process", g_AllocCbRcx);
    print_u64("callback arg2 rdx/base ptr", g_AllocCbRdx);
    print_u64("callback arg2 deref/base", g_AllocCbBaseValue);
    print_u64("callback arg3 r8/zero bits", g_AllocCbR8);
    print_u64("callback arg4 r9/size ptr", g_AllocCbR9);
    print_u64("callback arg4 deref/size", g_AllocCbRegionValue);
    print_u64("callback home slot 1", g_AllocCbHome1);
    print_u64("callback home slot 2", g_AllocCbHome2);
    print_u64("callback home slot 3", g_AllocCbHome3);
    print_u64("callback home slot 4", g_AllocCbHome4);
    print_u64("callback arg5 stack/alloc type", g_AllocCbStackArg5);
    print_u64("callback arg6 stack/protect", g_AllocCbStackArg6);
    std::printf("callback prev-pc match               %u\n", callback_prev_pc_match ? 1u : 0u);
    std::printf("callback decoded syscall match       %u\n", callback_decoded_syscall_match ? 1u : 0u);
    std::printf("callback arg1 match                  %u\n", callback_arg1_match ? 1u : 0u);
    std::printf("callback arg2 pointer nonzero        %u\n", callback_arg2_pointer_nonzero ? 1u : 0u);
    std::printf("callback arg3 match                  %u\n", callback_arg3_match ? 1u : 0u);
    std::printf("callback arg4 pointer nonzero        %u\n", callback_arg4_pointer_nonzero ? 1u : 0u);
    std::printf("callback arg5 match                  %u\n", callback_arg5_match ? 1u : 0u);
    std::printf("callback arg6 match                  %u\n", callback_arg6_match ? 1u : 0u);
    std::printf("callback base matches worker         %u\n", callback_base_matches_worker ? 1u : 0u);
    std::printf("monitor callback-snapshot detected   %ld\n", g_State.MonitorSawCallbackSnapshot);
    print_status("last ThreadLastSystemCall status", g_State.LastQueryStatus);
    std::printf("ThreadLastSystemCall attempts        %ld\n", g_State.QueryAttempts);
    std::printf("ThreadLastSystemCall return length   %ld\n", g_State.LastReturnLength);
    std::printf("ThreadLastSystemCall detected        %ld\n", g_State.MonitorSawThreadLastSyscall);
    std::printf("ThreadLastSystemCall first argument  %p\n", g_State.LastSyscall.FirstArgument);
    std::printf("ThreadLastSystemCall number          0x%04x\n", g_State.LastSyscall.SystemCallNumber);

    return (g_AllocCbDirectHits != 0 &&
            callback_decoded_syscall_match &&
            callback_arg5_match &&
            callback_arg6_match) ? 0 : 1;
}
