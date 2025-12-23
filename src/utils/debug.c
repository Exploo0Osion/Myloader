#include "myloader.h"

void Debug_PrintStatus(const char* apiName, NTSTATUS status) {
    if (NT_SUCCESS(status)) {
        LOG("%s Success! Status: 0x%08X", apiName, status);
    }
    else {
        ERR("%s FAILED! Status: 0x%08X", apiName, status);
        // 常见错误码解析
        if (status == 0xC0000005) ERR("  -> STATUS_ACCESS_VIOLATION (内存访问冲突)");
        if (status == 0xC0000022) ERR("  -> STATUS_ACCESS_DENIED (权限不足)");
        if (status == 0xC0000008) ERR("  -> STATUS_INVALID_HANDLE (无效句柄)");
    }
}

BOOL Debug_SelfCheck() {
    printf("\n=== [DEBUG] 开始自检 ===\n");

    if (!g_ntdllBase) { ERR("ntdll.dll 基址未找到!"); return FALSE; }
    LOG("ntdll Base: %p", g_ntdllBase);
    if (!g_kernel32Base) { ERR("kernel32.dll 基址未找到!"); return FALSE; }
    LOG("kernel32 Base: %p", g_kernel32Base);

    if (!g_pRandomSyscallGadget) { ERR("Syscall Gadget 未找到!"); return FALSE; }
    LOG("Syscall Gadget: %p", g_pRandomSyscallGadget);
    
    if (!g_pStackGadget) { WARN("Stack Clean Gadget (add rsp) 未找到，已回退到 Syscall Gadget (可能导致栈不平衡)"); }
    else LOG("Stack Clean Gadget: %p", g_pStackGadget);

    if (!g_pThunkGadget) { WARN("Thunk Gadget (jmp rbx) 未找到，已回退"); }
    else LOG("Thunk Gadget: %p", g_pThunkGadget);

    if (!g_pRtlUserThreadStart) { ERR("RtlUserThreadStart 未找到"); return FALSE; }
    if (!g_pBaseThreadInitThunk) { ERR("BaseThreadInitThunk 未找到"); return FALSE; }

    LOG("RtlUserThreadStart Frame Size: 0x%X", g_RtlFrameSize);
    LOG("BaseThreadInitThunk Frame Size: 0x%X", g_BaseFrameSize);
    LOG("RBP Push Offset: 0x%X", g_RbpPushOffset);

    if (g_RtlFrameSize == 0 || g_BaseFrameSize == 0) {
        ERR("严重错误: 栈帧大小计算失败 (值为0)。SilentMoonwalk 无法构造伪造栈帧。");
        ERR("原因可能是: 此版本的 Windows DLL 结构有所改变，或者 ParseUnwindInfo 函数逻辑未能覆盖所有情况。");
        return FALSE;
    }

    if (g_RbpPushOffset == 0) {
        WARN("警告: RBP Push Offset 为 0。这可能意味着目标函数没有使用 RBP 寻址，欺骗可能会被检测到或失败。");
    }

    printf("=== [DEBUG] 自检完成 ===\n\n");
    return TRUE;
}

void Debug_CheckStructOffsets() {
    printf("\n=== [DIAGNOSTIC] 结构体偏移量检查 (请与 ASM 比对) ===\n");
    
    printf("SPOOFER Total Size: 0x%X\n", (DWORD)sizeof(SPOOFER));

    printf("[+] KernelBaseAddress           : +0x%X\n", (DWORD)offsetof(SPOOFER, KernelBaseAddress));
    printf("[+] FirstFrameFunctionPointer   : +0x%X\n", (DWORD)offsetof(SPOOFER, FirstFrameFunctionPointer));
    printf("[+] JmpRbxGadget                : +0x%X\n", (DWORD)offsetof(SPOOFER, JmpRbxGadget));
    printf("[+] AddRspXGadget               : +0x%X\n", (DWORD)offsetof(SPOOFER, AddRspXGadget));

    printf("[+] RtlUserThreadStartFrameSize : +0x%X\n", (DWORD)offsetof(SPOOFER, RtlUserThreadStartFrameSize));
    printf("[+] StackOffsetWhereRbpIsPushed : +0x%X (ASM 应为 +80h)\n", (DWORD)offsetof(SPOOFER, StackOffsetWhereRbpIsPushed));

    printf("[+] RbpFrameOffset              : +0x%X (ASM 应为 +88h)\n", (DWORD)offsetof(SPOOFER, RbpFrameOffset));
    printf("[+] JmpRbxGadgetRef             : +0x%X (ASM 应为 +90h)\n", (DWORD)offsetof(SPOOFER, JmpRbxGadgetRef));
    printf("[+] SpoofFunctionPointer        : +0x%X\n", (DWORD)offsetof(SPOOFER, SpoofFunctionPointer));
    printf("[+] ReturnAddress               : +0x%X\n", (DWORD)offsetof(SPOOFER, ReturnAddress));
    printf("[+] Nargs                       : +0x%X\n", (DWORD)offsetof(SPOOFER, Nargs));
    
    printf("=========================================================\n\n");
}

BOOL Debug_ValidateGadgets() {
    printf("=== [DIAGNOSTIC] Gadget 有效性检查 ===\n");
    
    if (!g_pRandomSyscallGadget) { ERR("Syscall Gadget 为 NULL!"); return FALSE; }
    if ((ULONG_PTR)g_pRandomSyscallGadget < 0x700000000000) WARN("Syscall Gadget 地址看起来很奇怪: %p", g_pRandomSyscallGadget);

    if (!g_pStackGadget) { ERR("Stack Gadget (add rsp) 为 NULL!"); return FALSE; }
    printf("[+] Stack Gadget: %p\n", g_pStackGadget);

    if (!g_pThunkGadget) { ERR("Thunk Gadget (jmp [rbx]) 为 NULL!"); return FALSE; }
    printf("[+] Thunk Gadget: %p\n", g_pThunkGadget);
    
    if (g_RbpFrameOffset == 0) { 
        WARN("RbpFrameOffset 为 0 (意味着 mov rbp, rsp)。这是允许的，但确认一下是否符合预期。"); 
    } else {
        printf("[+] RbpFrameOffset: 0x%X (检测到的动态偏移)\n", g_RbpFrameOffset);
    }

    return TRUE;
}
