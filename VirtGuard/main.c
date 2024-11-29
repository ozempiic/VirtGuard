#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    HANDLE ProcessHandle;
    PVOID *BaseAddress;
    ULONG_PTR ZeroBits;
    SIZE_T *RegionSize;
    ULONG AllocationType;
    ULONG Protect;
} NTAVMArgs;

typedef struct {
    NTAVMArgs NtAllocateVirtualMemoryArgs;
} STATE;

enum { NTALLOCATEVIRTUALMEMORY_ENUM };

STATE state;
DWORD enumState;
PVOID g_Veh = NULL;

void printContextDebug(const CONTEXT *ctx) {
    printf("[Debug] CONTEXT:\n");
    printf("  RIP: 0x%llx\n", ctx->Rip);
    printf("  RAX: 0x%llx\n", ctx->Rax);
    printf("  RDX: 0x%llx\n", ctx->Rdx);
    printf("  R10: 0x%llx\n", ctx->R10);
    printf("  R8:  0x%llx\n", ctx->R8);
    printf("  R9:  0x%llx\n", ctx->R9);
    printf("  Dr0: 0x%llx\n", ctx->Dr0);
    printf("  Dr7: 0x%llx\n", ctx->Dr7);
    printf("  EFlags: 0x%llx\n", ctx->EFlags);
}

ULONG64 setDr7Bits(ULONG64 currDr7, int startingBitPos, int numberOfBitsToModify, ULONG64 newDr7) {
    ULONG64 mask = (1ULL << numberOfBitsToModify) - 1ULL;
    ULONG64 result = (currDr7 & ~(mask << startingBitPos)) | (newDr7 << startingBitPos);
    printf("[Debug] setDr7Bits: currDr7=0x%llx, newDr7=0x%llx, result=0x%llx\n", currDr7, newDr7, result);
    return result;
}

BOOL setHwBp(PVOID pAddress, int drx) {
    CONTEXT threadCtx = {0};
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &threadCtx)) {
        printf("[Error] GetThreadContext failed\n");
        return FALSE;
    }

    printf("[Debug] Setting hardware breakpoint at 0x%p, DR%d\n", pAddress, drx);
    printContextDebug(&threadCtx);

    switch (drx) {
        case 0: if (!threadCtx.Dr0) threadCtx.Dr0 = (ULONG64)pAddress; break;
        case 1: if (!threadCtx.Dr1) threadCtx.Dr1 = (ULONG64)pAddress; break;
        case 2: if (!threadCtx.Dr2) threadCtx.Dr2 = (ULONG64)pAddress; break;
        case 3: if (!threadCtx.Dr3) threadCtx.Dr3 = (ULONG64)pAddress; break;
        default: return FALSE;
    }

    threadCtx.Dr7 = setDr7Bits(threadCtx.Dr7, drx * 2, 1, 1);

    if (!SetThreadContext(GetCurrentThread(), &threadCtx)) {
        printf("[Error] SetThreadContext failed\n");
        return FALSE;
    }

    printf("[Debug] Hardware breakpoint set successfully\n");
    return TRUE;
}

BOOL removeHwBp(int drx) {
    CONTEXT threadCtx = {0};
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &threadCtx)) {
        printf("[Error] GetThreadContext failed\n");
        return FALSE;
    }

    printf("[Debug] Removing hardware breakpoint DR%d\n", drx);
    printContextDebug(&threadCtx);

    switch (drx) {
        case 0: threadCtx.Dr0 = 0; break;
        case 1: threadCtx.Dr1 = 0; break;
        case 2: threadCtx.Dr2 = 0; break;
        case 3: threadCtx.Dr3 = 0; break;
        default: return FALSE;
    }

    threadCtx.Dr7 = setDr7Bits(threadCtx.Dr7, drx * 2, 1, 0);

    if (!SetThreadContext(GetCurrentThread(), &threadCtx)) {
        printf("[Error] SetThreadContext failed\n");
        return FALSE;
    }

    printf("[Debug] Hardware breakpoint removed successfully\n");
    return TRUE;
}

BOOL initVeh(PVECTORED_EXCEPTION_HANDLER excepHandler) {
    if (!g_Veh) {
        g_Veh = AddVectoredExceptionHandler(1, excepHandler);
    }
    printf("[Debug] VEH initialized: %p\n", g_Veh);
    return g_Veh != NULL;
}

PVOID findSyscall(PVOID fnAddr) {
    BYTE syscallPattern[] = {0x0f, 0x05};
    for (SIZE_T i = 0; i < 23; i += 2) {
        if (!memcmp((BYTE *)fnAddr + i, syscallPattern, sizeof(syscallPattern))) {
            printf("[Debug] Syscall found at offset 0x%zx\n", i);
            return (PBYTE)fnAddr + i;
        }
    }
    printf("[Error] Syscall not found\n");
    return NULL;
}

LONG __stdcall exceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    printf("[Debug] Exception caught, code: 0x%x\n", pExceptionInfo->ExceptionRecord->ExceptionCode);

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        ULONG_PTR exceptionRip = (ULONG_PTR)pExceptionInfo->ContextRecord->Rip;

        if (pExceptionInfo->ContextRecord->Dr7 & 1) {
            if (exceptionRip == pExceptionInfo->ContextRecord->Dr0) {
                CONTEXT *ctx = pExceptionInfo->ContextRecord;
                printf("[Debug] Single-step exception at RIP: 0x%llx\n", ctx->Rip);
                printContextDebug(ctx);

                switch (enumState) {
                    case NTALLOCATEVIRTUALMEMORY_ENUM:
                        printf("[Debug] Handling NtAllocateVirtualMemory\n");
                        ctx->R10 = (ULONG_PTR)state.NtAllocateVirtualMemoryArgs.ProcessHandle;
                        ctx->Rdx = (ULONG_PTR)state.NtAllocateVirtualMemoryArgs.BaseAddress;
                        ctx->R8 = (ULONG_PTR)state.NtAllocateVirtualMemoryArgs.ZeroBits;
                        ctx->R9 = (ULONG_PTR)state.NtAllocateVirtualMemoryArgs.RegionSize;

                        *(ULONG_PTR *)(ctx->Rsp + 5 * sizeof(PVOID)) = state.NtAllocateVirtualMemoryArgs.AllocationType;
                        *(ULONG_PTR *)(ctx->Rsp + 6 * sizeof(PVOID)) = state.NtAllocateVirtualMemoryArgs.Protect;

                        break;

                    default:
                        printf("[Debug] Unknown enum state\n");
                        ctx->Rip += 1;
                        break;
                }
            }
        }

        pExceptionInfo->ContextRecord->EFlags |= (1 << 16); 
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

typedef NTSTATUS(WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);

int main() {
    printf("[Debug] Initializing VEH\n");
    if (!initVeh(exceptionHandler)) {
        printf("[Error] VEH initialization failed\n");
        return -1;
    }

    HMODULE ntdll = GetModuleHandleA("ntdll");
    PVOID procAddr = (PVOID)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

    printf("[Debug] NtAllocateVirtualMemory address: %p\n", procAddr);

    enumState = NTALLOCATEVIRTUALMEMORY_ENUM;
    PVOID syscallAddr = findSyscall(procAddr);

    if (!syscallAddr || !setHwBp(syscallAddr, 0)) {
        printf("[Error] Failed to set hardware breakpoint\n");
        return -1;
    }

    SIZE_T regSize = 512;
    PVOID allocAddr = NULL;

    state.NtAllocateVirtualMemoryArgs.ProcessHandle = GetCurrentProcess();
    state.NtAllocateVirtualMemoryArgs.RegionSize = &regSize;
    state.NtAllocateVirtualMemoryArgs.BaseAddress = &allocAddr;
    state.NtAllocateVirtualMemoryArgs.AllocationType = MEM_COMMIT | MEM_RESERVE;
    state.NtAllocateVirtualMemoryArgs.Protect = PAGE_EXECUTE_READWRITE;

    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)procAddr;

    printf("[Debug] Calling NtAllocateVirtualMemory\n");
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(), &allocAddr, 0, &regSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    printf("[NtAllocateVirtualMemory] Allocated At 0x%p, Status: %x\n", allocAddr, status);
    getchar();
    return 0;
}