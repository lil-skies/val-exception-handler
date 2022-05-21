#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <windef.h>
#include <winbase.h>
#include <winreg.h>
#include <objbase.h>
#include <intsafe.h>

#include <synchapi.h>
#include <heapapi.h>

//#include <ndk/exfuncs.h>
#include <ndk/iofuncs.h>
#include <ndk/kefuncs.h>
#include <ndk/ldrfuncs.h>
#include <ndk/mmfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/psfuncs.h>
#include <ndk/rtlfuncs.h>
#include <ndk/setypes.h>
#include <ndk/sefuncs.h>
#include <ndk/umfuncs.h>
#include "pseh2.h"

#pragma once
#ifndef _NTINTSAFE_H_INCLUDED_
#define _NTINTSAFE_H_INCLUDED_

/* Include the sdk version */
#include <intsafe.h>

/* We don't want this one */
#undef _INTSAFE_H_INCLUDED_

#endif // !_NTINTSAFE_H_INCLUDED_

#ifdef _PPC_
#define SWAPD(x) ((((x)&0xff)<<24)|(((x)&0xff00)<<8)|(((x)>>8)&0xff00)|(((x)>>24)&0xff))
#define SWAPW(x) ((((x)&0xff)<<8)|(((x)>>8)&0xff))
#define SWAPQ(x) ((SWAPD((x)&0xffffffff) << 32) | (SWAPD((x)>>32)))
#else
#define SWAPD(x) (x)
#define SWAPW(x) (x)
#define SWAPQ(x) (x)
#endif

#define ROUND_DOWN(n, align) \
     (((ULONG_PTR)(n)) & ~((align) - 1l))

#define ROUND_UP(n, align) \
     ROUND_DOWN(((ULONG_PTR)(n)) + (align) - 1, (align))

#define RVA(m, b) ((VOID*)((ULONG_PTR)(b) + (ULONG_PTR)(m)))

extern VOID* MmHighestUserAddress;

NTSTATUS
NTAPI
RtlpSafeCopyMemory(
    _Out_writes_bytes_all_(Length) VOID UNALIGNED* Destination,
    _In_reads_bytes_(Length) CONST VOID UNALIGNED* Source,
    _In_ SIZE_T Length);

VOID
NTAPI
RtlpGetStackLimits(PULONG_PTR LowLimit,
    PULONG_PTR HighLimit);

PEXCEPTION_REGISTRATION_RECORD
NTAPI
RtlpGetExceptionList(VOID);

VOID
NTAPI
RtlpSetHeapParameters(IN PRTL_HEAP_PARAMETERS Parameters);

VOID
NTAPI
RtlpSetExceptionList(PEXCEPTION_REGISTRATION_RECORD NewExceptionList);

BOOL
NTAPI
RtlCallVectoredExceptionHandlers(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT Context
);

VOID
NTAPI
RtlCallVectoredContinueHandlers(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT Context
);

#ifdef _M_IX86
typedef struct _DISPATCHER_CONTEXT
{
    PEXCEPTION_REGISTRATION_RECORD RegistrationPointer;
} DISPATCHER_CONTEXT, * PDISPATCHER_CONTEXT;
#endif

/* These provide support for sharing code between User and Kernel RTL */
VOID*
NTAPI
RtlpAllocateMemory(
    SIZE_T Bytes,
    ULONG Tag);

VOID
NTAPI
RtlpFreeMemory(
    VOID* Mem,
    ULONG Tag);

KPROCESSOR_MODE
NTAPI
RtlpGetMode(VOID);

BOOL
NTAPI
RtlpCaptureStackLimits(
    IN ULONG_PTR Ebp,
    IN ULONG_PTR* StackBegin,
    IN ULONG_PTR* StackEnd
);

NTSTATUS
NTAPI
RtlDeleteHeapLock(IN OUT PHEAP_LOCK Lock);

NTSTATUS
NTAPI
RtlEnterHeapLock(IN OUT PHEAP_LOCK Lock, IN BOOL Exclusive);

BOOL
NTAPI
RtlTryEnterHeapLock(IN OUT PHEAP_LOCK Lock, IN BOOL Exclusive);

NTSTATUS
NTAPI
RtlInitializeHeapLock(IN OUT PHEAP_LOCK* Lock);

NTSTATUS
NTAPI
RtlLeaveHeapLock(IN OUT PHEAP_LOCK Lock);

BOOL
NTAPI
RtlpCheckForActiveDebugger(VOID);

BOOL
NTAPI
RtlpHandleDpcStackException(IN PEXCEPTION_REGISTRATION_RECORD RegistrationFrame,
    IN ULONG_PTR RegistrationFrameEnd,
    IN OUT PULONG_PTR StackLow,
    IN OUT PULONG_PTR StackHigh);

#define RtlpAllocateStringMemory RtlpAllocateMemory
#define RtlpFreeStringMemory     RtlpFreeMemory

ULONG
NTAPI
RtlGetTickCount(VOID);
#define NtGetTickCount RtlGetTickCount

BOOL
NTAPI
RtlpSetInDbgPrint(
    VOID
);

VOID
NTAPI
RtlpClearInDbgPrint(
    VOID
);

/* i386/except.S */

#ifdef _M_IX86
EXCEPTION_DISPOSITION
NTAPI
RtlpExecuteHandlerForException(PEXCEPTION_RECORD ExceptionRecord,
    PEXCEPTION_REGISTRATION_RECORD RegistrationFrame,
    PCONTEXT Context,
    VOID* DispatcherContext,
    PEXCEPTION_ROUTINE ExceptionHandler);
#endif

EXCEPTION_DISPOSITION
NTAPI
RtlpExecuteHandlerForUnwind(PEXCEPTION_RECORD ExceptionRecord,
    PEXCEPTION_REGISTRATION_RECORD RegistrationFrame,
    PCONTEXT Context,
    VOID* DispatcherContext,
    PEXCEPTION_ROUTINE ExceptionHandler);

VOID
NTAPI
RtlpCheckLogException(IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN VOID* ContextData,
    IN ULONG Size);

VOID
NTAPI
RtlpCaptureContext(OUT PCONTEXT ContextRecord);

//
// Debug Service calls
//
ULONG
NTAPI
DebugService(
    IN ULONG Service,
    IN VOID* Argument1,
    IN VOID* Argument2,
    IN VOID* Argument3,
    IN VOID* Argument4
);

VOID
NTAPI
DebugService2(
    IN VOID* Argument1,
    IN VOID* Argument2,
    IN ULONG Service
);

/* Tags for the String Allocators */
#define TAG_USTR        'RTSU'
#define TAG_ASTR        'RTSA'
#define TAG_OSTR        'RTSO'

/* Timer Queue */

extern HANDLE TimerThreadHandle;

NTSTATUS
RtlpInitializeTimerThread(VOID);

/* bitmap64.c */
typedef struct _RTL_BITMAP64
{
    ULONG64 SizeOfBitMap;
    PULONG64 Buffer;
} RTL_BITMAP64, * PRTL_BITMAP64;

typedef struct _RTL_BITMAP_RUN64
{
    ULONG64 StartingIndex;
    ULONG64 NumberOfBits;
} RTL_BITMAP_RUN64, * PRTL_BITMAP_RUN64;

/* nls.c */
WCHAR
NTAPI
RtlpUpcaseUnicodeChar(IN WCHAR Source);

WCHAR
NTAPI
RtlpDowncaseUnicodeChar(IN WCHAR Source);

/* ReactOS only */
VOID
NTAPI
LdrpInitializeProcessCompat(VOID* pProcessActctx, VOID** pOldShimData);

VOID*
NTAPI
RtlpDebugBufferCommit(_Inout_ PRTL_DEBUG_INFORMATION Buffer,
    _In_ SIZE_T Size);


/* EOF */
