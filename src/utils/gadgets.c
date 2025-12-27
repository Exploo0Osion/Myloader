#include "myloader.h"

// [保留] 辅助函数
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB)__readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

// 查找函数入口
PRUNTIME_FUNCTION VxLookupFunctionEntry(DWORD64 ControlPc, PVOID ImageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PRUNTIME_FUNCTION pFirstEntry = (PRUNTIME_FUNCTION)((PBYTE)ImageBase + pDataDir->VirtualAddress);
    PRUNTIME_FUNCTION pEndEntry = pFirstEntry + (pDataDir->Size / sizeof(RUNTIME_FUNCTION));

    for (PRUNTIME_FUNCTION pEntry = pFirstEntry; pEntry < pEndEntry; pEntry++) {
        if (ControlPc >= (DWORD64)ImageBase + pEntry->BeginAddress && 
            ControlPc < (DWORD64)ImageBase + pEntry->EndAddress) {
            return pEntry;
        }
    }
    return NULL;
}
DWORD FindCallSiteOffset(PVOID funcAddr, PVOID moduleBase) {
    PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)funcAddr, moduleBase);
    if (!rf) return 0x10; // 找不到 Unwind Info，回退到默认

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    
    DWORD64 start = (DWORD64)moduleBase + rf->BeginAddress;
    DWORD64 end = (DWORD64)moduleBase + rf->EndAddress;
    
    // 简单的反汇编扫描
    for (DWORD64 ptr = start; ptr < end - 5; ptr++) {
        BYTE b1 = *(BYTE*)ptr;
        BYTE b2 = *(BYTE*)(ptr+1);

        // 1. 匹配 E8 xx xx xx xx (CALL rel32)
        if (b1 == 0xE8) {
            return (DWORD)(ptr + 5 - start);
        }

        // 2. 匹配 FF 15 xx xx xx xx (CALL [RIP+x]) - 常用于系统 API 调用
        if (b1 == 0xFF && b2 == 0x15) {
            return (DWORD)(ptr + 6 - start);
        }
    }

    return 0x10; // 没找到 Call，回退到硬编码偏移
}
//栈大小计算函数 (RSP-Based)
DWORD CalculateFunctionStackSize(PVOID funcAddr, PVOID moduleBase) {
    PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)funcAddr, moduleBase);
    if (!rf) return 0;

    DWORD64 imageBase = (DWORD64)moduleBase;
    PUNWIND_INFO info = (PUNWIND_INFO)(imageBase + rf->UnwindData);
    
    DWORD totalStackSize = 0;
    
    for (UBYTE i = 0; i < info->CountOfCodes; i++) {
        UNWIND_CODE code = info->UnwindCode[i];
        UBYTE op = code.UnwindOp;
        UBYTE opInfo = code.OpInfo;

        switch (op) {
            case UWOP_PUSH_NONVOL:     // push reg
                totalStackSize += 8;
                break;
            case UWOP_ALLOC_LARGE:     // sub rsp, X
                if (opInfo == 0) {
                    i++; 
                    totalStackSize += (info->UnwindCode[i].FrameOffset * 8);
                } else {
                    i += 2;
                    DWORD size = *(DWORD*)&info->UnwindCode[i-1]; 
                    totalStackSize += size;
                }
                break;
            case UWOP_ALLOC_SMALL:     // sub rsp, X
                totalStackSize += (opInfo + 1) * 8;
                break;
            case UWOP_PUSH_MACH_FRAME:
                totalStackSize += (opInfo ? 0x28 : 0x20);
                break;
            // 跳过不影响 RSP 的指令
            case UWOP_SAVE_NONVOL: i++; break;
            case UWOP_SAVE_NONVOL_BIG: i += 2; break;
            case UWOP_SAVE_XMM128: i++; break;
            case UWOP_SAVE_XMM128BIG: i += 2; break;
            case UWOP_SET_FPREG: break; 
        }
    }
    return totalStackSize;
}

// 查找 Gadget (AddRsp)
PVOID FindAddRspGadget(PVOID pModuleBase, DWORD* outSize) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
	PBYTE start = (PBYTE)pModuleBase + pNt->OptionalHeader.BaseOfCode;
	DWORD size = pNt->OptionalHeader.SizeOfCode;
	for (DWORD i = 0; i + 4 < size; i++) {
		if (start[i] == 0x48 && start[i + 1] == 0x83 && start[i + 2] == 0xC4 && start[i + 4] == 0xC3){
			BYTE gadgetSize = start[i + 3];
            // NtCreateThreadEx 需要 0x58 空间，我们留点余量，找个 0x68 或更大的
            if (gadgetSize % 8 == 0 && gadgetSize >= 0x68) {
                if (outSize) {
                    *outSize = (DWORD)gadgetSize;
                }
                //LOG("[+] Found viable Stack Gadget: add rsp, 0x%X", gadgetSize);
                return (PVOID)(start + i);
            }
		}
	}
	return NULL;
}
PVOID GetSyscallGadget(PVOID pModuleBase) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
	PBYTE start = (PBYTE)pModuleBase + pNt->OptionalHeader.BaseOfCode;
	DWORD size = pNt->OptionalHeader.SizeOfCode;
	for (DWORD i = 0; i < size; i++) {
		if (start[i] == 0x0F && start[i + 1] == 0x05 && start[i + 2] == 0xC3)
			return (PVOID)(start + i);
	}
	return NULL;
}
//查找 Jmp [RBX]
PVOID FindJmpRbxGadget(PVOID moduleBase,DWORD *size) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)moduleBase + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    DWORD64 txtStart = (DWORD64)moduleBase + pSection->VirtualAddress;
    DWORD64 txtSize = pSection->Misc.VirtualSize;
    
    for (DWORD64 ptr = txtStart; ptr < txtStart + txtSize; ptr++) {
        // FF 23 (jmp [rbx])
        if (*(BYTE*)ptr == 0xFF && *(BYTE*)(ptr+1) == 0x23) {
            DWORD stacksize = CalculateFunctionStackSize((PVOID)ptr, moduleBase);
			*size = (DWORD)stacksize;
            return (PVOID)ptr; // 必须是 Leaf Function
        }
    }
    return NULL;
}