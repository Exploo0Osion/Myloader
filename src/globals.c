#include "myloader.h"

unsigned long g_seed = 1;

PVOID g_ntdllBase = NULL;
PVOID g_kernel32Base = NULL;
PVOID g_kernelBaseAddr= NULL;
SW3_SYSCALL_LIST g_SyscallList = { 0 };

PVOID g_pRandomSyscallGadget = NULL;
PVOID g_pStackGadget = NULL;
PVOID g_pThunkGadget = NULL;
PVOID frame_Root_Ntdll = NULL;
PVOID frame_Mid_Kernel = NULL; 
PVOID kernelFrameModuleBase = NULL; 


PVOID g_pRtlUserThreadStart = NULL;
PVOID g_pBaseThreadInitThunk = NULL;
DWORD g_FirstFrameOffset = 0;
DWORD g_SecondFrameOffset = 0;
DWORD g_RtlFrameSize = 0;
DWORD g_BaseFrameSize = 0;
DWORD g_RbpPushOffset = 0;
DWORD g_RbpFrameOffset = 0;
DWORD g_StackGadgetSize = 0;
DWORD g_JmpRbxGadgetFrameSize = 0;

