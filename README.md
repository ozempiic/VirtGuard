# Introduction

This project demonstrates a sophisticated technique involving memory allocation, vectored exception handling (VEH), hardware breakpoints, and system call interception. The goal of this code is to allocate virtual memory using `NtAllocateVirtualMemory` while monitoring its execution with hardware breakpoints and handling exceptions related to system calls.

# Overview of Key Concepts

- **Hardware Breakpoints**: Hardware breakpoints are used for debugging purposes. They allow the program to pause at specific memory addresses during execution. These are set through debug registers (DR0-DR3).

- **Vectored Exception Handling (VEH)**: VEH allows registering a custom exception handler, which can intercept exceptions like single-step execution for debugging or other runtime exceptions.

- **System Call Interception**: The code hooks into `NtAllocateVirtualMemory`, a function used for allocating memory in a process, to observe its behavior and possibly modify its execution.

- **Context Debugging**: The context of the thread (including registers) is captured and printed to aid debugging when exceptions are triggered.

# Code Breakdown

## Global Variables and Data Structures

```c
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
```

- **`NTAVMArgs`**: A structure that holds arguments required to call `NtAllocateVirtualMemory`. These include the process handle, base address, region size, allocation type, and protection flags.

- **`STATE`**: A structure to hold the state of the `NtAllocateVirtualMemory` arguments. It is useful for maintaining the state during exception handling.

- **`enumState`**: A simple enumeration that tracks the current state of the code (in this case, the state is specifically for `NtAllocateVirtualMemory`).

- **`g_Veh`**: A pointer to the exception handler for VEH. It is used to store the exception handler callback.

## Helper Functions

#### `printContextDebug`

This function prints the contents of the `CONTEXT` structure, which holds the state of the registers during a thread's execution.

```c
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

```

- **Purpose**: This function is useful for debugging, especially when handling exceptions and breakpoints. It helps to inspect the state of the CPU registers, which can provide insights into the program's execution flow.


### `setDr7Bits`

This function modifies specific bits in the `Dr7` register, which controls the behavior of the hardware breakpoints.

```c
ULONG64 setDr7Bits(ULONG64 currDr7, int startingBitPos, int numberOfBitsToModify, ULONG64 newDr7) {
    ULONG64 mask = (1ULL << numberOfBitsToModify) - 1ULL;
    ULONG64 result = (currDr7 & ~(mask << startingBitPos)) | (newDr7 << startingBitPos);
    printf("[Debug] setDr7Bits: currDr7=0x%llx, newDr7=0x%llx, result=0x%llx\n", currDr7, newDr7, result);
    return result;
}
```

- **Purpose**: The `Dr7` register is crucial for controlling hardware breakpoints. This function helps set specific bits in `Dr7` to enable or disable breakpoints on the given debug register (`Dr0-Dr3`).

## Core Functions

### `setHwBp`

This function sets a hardware breakpoint at a specified address, using one of the debug registers (`DR0-DR3`).

```c
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
```

- **Purpose**: This function sets a hardware breakpoint at a specified memory address. It uses the `GetThreadContext` function to retrieve the current context of the thread, modifies the relevant debug register (`Dr0-Dr3`), and then uses `SetThreadContext` to apply the changes.


### `removeHwBp`

This function removes a hardware breakpoint by resetting the corresponding debug register (`Dr0-Dr3`).

```c
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
```

- **Purpose**: This function removes a hardware breakpoint by clearing the corresponding debug register and updating the `Dr7` register.


### `initVeh`

This function initializes the Vectored Exception Handler (VEH), which allows the program to handle exceptions such as single-step execution.

```c
BOOL initVeh(PVECTORED_EXCEPTION_HANDLER excepHandler) {
    if (!g_Veh) {
        g_Veh = AddVectoredExceptionHandler(1, excepHandler);
    }
    printf("[Debug] VEH initialized: %p\n", g_Veh);
    return g_Veh != NULL;
}
```

- **Purpose**: The function registers an exception handler that will be called whenever a specific exception occurs (like a single-step exception). This helps in intercepting and managing exceptions at a low level.

### `findSyscall`

The purpose of the `findSyscall` function is to locate a system call instruction (specifically `syscall` in x86-64 assembly) within a given function's memory address space. It searches for the byte pattern that corresponds to the `syscall` instruction and returns the address where this pattern is found.

```c
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
```

- **Purpose:** The function is designed to locate the `syscall` instruction within a given function's memory address range. It helps in detecting where system calls are made in a binary, useful for debugging, reverse engineering, or security monitoring purposes.

# Exception Handler

### `exceptionHandler`

This function handles exceptions, specifically targeting single-step exceptions (`EXCEPTION_SINGLE_STEP`).

```c
LONG __stdcall exceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    printf("[Debug] Exception caught, code: 0x%x\n", pExceptionInfo->ExceptionRecord->ExceptionCode);

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        ULONG_PTR exceptionRip = (ULONG_PTR)pExceptionInfo->ContextRecord->Rip;

        if (pExceptionInfo->ContextRecord->Dr7 & 1) {
            if (exceptionRip == pExceptionInfo->ContextRecord->Dr0) {
                CONTEXT *ctx = pExceptionInfo->ContextRecord;
                printf("[Debug] Single-step exception at RIP: 0x%llx\n", exceptionRip);
                removeHwBp(0);  // Remove hardware breakpoint after triggering
            }
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}
```


- **Purpose**: The handler manages exceptions, printing the exception code and checking if it's a single-step exception. If so, it processes the exception, such as removing breakpoints or printing additional information.

# Conclusion

This code demonstrates advanced techniques in virtual memory allocation, hardware breakpoint manipulation, exception handling, and system call interception. It provides a foundation for debugging and observing program execution at a very low level, which can be useful for tasks like reverse engineering or malware analysis. By using hardware breakpoints and VEH, it is possible to monitor specific addresses or system calls without modifying the program's source code.


