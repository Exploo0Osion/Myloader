#pragma once
#pragma intrinsic(memset, memcpy, memcmp)
#include <winternl.h>
#include <intrin.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "structs.h"

#ifndef IS_ADDR_SAFE
#define IS_ADDR_SAFE(ptr, base, size) \
    ((ULONG_PTR)(ptr) >= (ULONG_PTR)(base) && (ULONG_PTR)(ptr) < ((ULONG_PTR)(base) + (size)))
#endif

#define rand MyRand
#define srand MySrand

/*--------------------------------------------------------------------
  External ASM functions
--------------------------------------------------------------------*/
extern VOID Gate(WORD wSystemCall, PVOID pSyscallInst, PVOID pClean, PVOID pThunk);
extern PVOID SpoofCall(PSPOOFER pConfig);
extern PVOID SyscallWrapper();

/*--------------------------------------------------------------------
  Globals (defined in src/globals.c)
--------------------------------------------------------------------*/
extern unsigned long g_seed;

extern PVOID g_ntdllBase;
extern PVOID g_kernel32Base;
extern PVOID g_kernelBaseAddr;
extern SW3_SYSCALL_LIST g_SyscallList;

extern PVOID g_pRandomSyscallGadget;
extern PVOID g_pStackGadget;
extern PVOID g_pThunkGadget;
extern PVOID frame_Root_Ntdll;
extern PVOID frame_Mid_Kernel; 
extern PVOID kernelFrameModuleBase; 
extern PVOID g_pRtlUserThreadStart;
extern PVOID g_pBaseThreadInitThunk;
extern DWORD g_RtlFrameSize;
extern DWORD g_BaseFrameSize;
extern DWORD g_RbpPushOffset;
extern DWORD g_RbpFrameOffset;
extern DWORD g_StackGadgetSize;

/*--------------------------------------------------------------------
  Debug helpers
--------------------------------------------------------------------*/
void Debug_PrintStatus(const char* apiName, NTSTATUS status);
BOOL Debug_SelfCheck();
void Debug_CheckStructOffsets();
BOOL Debug_ValidateGadgets();

/*--------------------------------------------------------------------
  SysWhispers3 / hashing
--------------------------------------------------------------------*/
DWORD64 djb2(PBYTE str);
DWORD64 djb2_w(PCWSTR str);
DWORD SW3_HashSyscall(PCSTR FunctionName);
BOOL SW3_PopulateSyscallList(PVOID ntdllBase);
DWORD SW3_GetSyscallNumber(DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(DWORD FunctionHash);
PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash);

/*--------------------------------------------------------------------
  PE helpers / exports
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
VOID VxInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
PVOID VxGetProcAddress(PVOID hModule, DWORD dwHash);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
void MySrand(unsigned long seed);
int MyRand();
/*--------------------------------------------------------------------
  Gadgets / unwind / stack spoofing
--------------------------------------------------------------------*/
PVOID GetSyscallGadget(PVOID pModuleBase);
PVOID GetStackGadget(PVOID pModuleBase, PDWORD outSize);
PVOID GetThunkGadget(PVOID pModuleBase);
PRUNTIME_FUNCTION VxLookupFunctionEntry(DWORD64 ControlPc, PVOID ImageBase);
DWORD CalculateStackFrameSize(PVOID moduleBase, PVOID functionAddress);
DWORD GetFrameSizeForAddress(PVOID address,PVOID moduleBase);
DWORD FindRbpPushOffset(PVOID functionAddress, PVOID moduleBase);
PVOID FindSuitableFrame(PVOID moduleBase);
BOOL IsForwarder(PVOID pModuleBase, PVOID pFuncAddress);
NTSTATUS InvokeSpoofedSyscall(PVX_TABLE_ENTRY pEntry, UINT64 argCount, ...);

/*--------------------------------------------------------------------
  Payloads
--------------------------------------------------------------------*/
BOOL ModuleStompPayload(PVX_TABLE pVxTable);

