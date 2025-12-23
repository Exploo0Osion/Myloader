#include "myloader.h"

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

BOOL IsForwarder(PVOID pModuleBase, PVOID pFuncAddress) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    ULONG_PTR start = (ULONG_PTR)pModuleBase + pDataDir->VirtualAddress;
    ULONG_PTR end = start + pDataDir->Size;
    
    return ((ULONG_PTR)pFuncAddress >= start && (ULONG_PTR)pFuncAddress < end);
}

PRUNTIME_FUNCTION VxLookupFunctionEntry(DWORD64 ControlPc, PVOID ImageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pDos->e_lfanew);
    
    // 1. 获取异常目录 (Exception Directory)
    PIMAGE_DATA_DIRECTORY pDataDir = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pDataDir->VirtualAddress == 0 || pDataDir->Size == 0)
        return NULL;

    // 2. 获取 Runtime Function 表的起始位置
    PRUNTIME_FUNCTION pFunctionTable = (PRUNTIME_FUNCTION)((PBYTE)ImageBase + pDataDir->VirtualAddress);
    
    // 3. 计算条目数量
    DWORD dwCount = pDataDir->Size / sizeof(RUNTIME_FUNCTION);
    if (dwCount == 0) return NULL;

    // 4. 计算相对于基址的 RVA (ControlPc - ImageBase)
    DWORD dwRelControlPc = (DWORD)(ControlPc - (DWORD64)ImageBase);

    // 5. 二分查找 (Binary Search) - 标准 Windows 实现方式
    // 因为 .pdata 是按 BeginAddress 排序的
    LONG low = 0;
    LONG high = dwCount - 1;
    LONG mid = 0;
    PRUNTIME_FUNCTION pEntry = NULL;

    while (low <= high) {
        mid = (low + high) / 2;
        pEntry = &pFunctionTable[mid];

        // 检查 ControlPc 是否在当前函数的范围内 [Begin, End)
        if (dwRelControlPc < pEntry->BeginAddress) {
            high = mid - 1;
        }
        else if (dwRelControlPc >= pEntry->EndAddress) {
            low = mid + 1;
        }
        else {
            // 找到了！dwRelControlPc >= BeginAddress && dwRelControlPc < EndAddress
            return pEntry;
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

PVOID GetStackGadget(PVOID pModuleBase, PDWORD outSize) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
	PBYTE start = (PBYTE)pModuleBase + pNt->OptionalHeader.BaseOfCode;
	DWORD size = pNt->OptionalHeader.SizeOfCode;
	for (DWORD i = 0; i + 4 < size; i++) {
		if (start[i] == 0x48 && start[i + 1] == 0x83 && start[i + 2] == 0xC4 && start[i + 4] == 0xC3){
			BYTE gadgetSize = start[i + 3];
            // NtCreateThreadEx 需要 0x58 空间，我们留点余量，找个 0x68 或更大的
            if (gadgetSize >= 0x68) {
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

PVOID GetThunkGadget(PVOID pModuleBase) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBase;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pDos->e_lfanew);
	PBYTE start = (PBYTE)pModuleBase + pNt->OptionalHeader.BaseOfCode;
	DWORD size = pNt->OptionalHeader.SizeOfCode;
	for (DWORD i = 0; i + 1 < size; i++) {
		if (start[i] == 0xFF && start[i + 1] == 0x23){
			PVOID candidateGadget = (PVOID)(start + i);
			DWORD frameSize = GetFrameSizeForAddress(candidateGadget,pModuleBase);
			if (frameSize == 0) return candidateGadget;
		}
	}
	return NULL;
}

static DWORD ParseUnwindInfo(PVOID moduleBase, PUNWIND_INFO info) {
	DWORD stackSize = 0;
	UBYTE index = 0;
	if (!info) return 0;
	PUNWIND_CODE code = info->UnwindCode;
	while (index < info->CountOfCodes) {
		switch (code->UnwindOp) {
		case UWOP_PUSH_NONVOL:
			stackSize += 8;
			break;
		case UWOP_ALLOC_SMALL:
			stackSize += 8 * (code->OpInfo + 1);
			break;
		case UWOP_ALLOC_LARGE: {
			index++;
			code++;
			DWORD allocSize = code->FrameOffset;
			if ((code - 1)->OpInfo == 0) {
				allocSize *= 8;
			}
			else {
				index++;
				code++;
				allocSize += code->FrameOffset << 16;
			}
			stackSize += allocSize;
			break;
		}
		case UWOP_SET_FPREG:
			stackSize += 16 * info->FrameOffset;
			break;
		default:
			break;
		}
		code++;
		index++;
	}
	if (info->Flags & 0x4) { // UNW_FLAG_CHAININFO
		index = info->CountOfCodes;
		if (index & 1) index++;
		PRUNTIME_FUNCTION chained = (PRUNTIME_FUNCTION)(&info->UnwindCode[index]);
		PUNWIND_INFO chainedInfo = (PUNWIND_INFO)((ULONG_PTR)moduleBase + chained->UnwindData);
		stackSize += ParseUnwindInfo(moduleBase, chainedInfo);
	}
	return stackSize;
}

DWORD CalculateStackFrameSize(PVOID moduleBase, PVOID functionAddress) {
	if (!moduleBase || !functionAddress) return 0;
	DWORD64 imageBase = (DWORD64)moduleBase;
	PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)functionAddress, moduleBase);
	if (!rf) return 0;
	PUNWIND_INFO info = (PUNWIND_INFO)(imageBase + rf->UnwindData);
	return ParseUnwindInfo((PVOID)imageBase, info);
}

DWORD GetFrameSizeForAddress(PVOID address,PVOID moduleBase) {
	DWORD64 imageBase = (DWORD64)moduleBase;
	PRUNTIME_FUNCTION rf =VxLookupFunctionEntry((DWORD64)address, moduleBase);
	if (!rf) return 0;
	PUNWIND_INFO info = (PUNWIND_INFO)(imageBase + rf->UnwindData);
	return ParseUnwindInfo((PVOID)imageBase, info);
}

DWORD FindRbpPushOffset(PVOID functionAddress, PVOID moduleBase) {
	if (!moduleBase || !functionAddress) return 0;
	DWORD64 imageBase =(DWORD64) moduleBase;
	PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)functionAddress, moduleBase);
	if (!rf) return 0;
	PUNWIND_INFO info = (PUNWIND_INFO)(imageBase + rf->UnwindData);

	DWORD stackOffset = 0;
	BOOL sawSetFp = FALSE;
	UBYTE index = 0;
	PUNWIND_CODE code = info->UnwindCode;
	while (index < info->CountOfCodes) {
		switch (code->UnwindOp) {
		case UWOP_SET_FPREG:
			sawSetFp = TRUE;
			stackOffset += 16 * info->FrameOffset;
			break;
		case UWOP_PUSH_NONVOL:
			if (code->OpInfo == RBP && sawSetFp) {
				return stackOffset;
			}
			stackOffset += 8;
			break;
		case UWOP_ALLOC_SMALL:
			stackOffset += 8 * (code->OpInfo + 1);
			break;
		case UWOP_ALLOC_LARGE: {
			index++;
			code++;
			DWORD allocSize = code->FrameOffset;
			if ((code - 1)->OpInfo == 0) {
				allocSize *= 8;
			}
			else {
				index++;
				code++;
				allocSize += code->FrameOffset << 16;
			}
			stackOffset += allocSize;
			break;
		}
		default:
			break;
		}
		code++;
		index++;
	}
	if (info->Flags & 0x4) {
		index = info->CountOfCodes;
		if (index & 1) index++;
		PRUNTIME_FUNCTION chained = (PRUNTIME_FUNCTION)(&info->UnwindCode[index]);
		PUNWIND_INFO chainedInfo = (PUNWIND_INFO)((ULONG_PTR)imageBase + chained->UnwindData);
		return stackOffset + ParseUnwindInfo((PVOID)imageBase, chainedInfo);
	}
	return 0;
}

PVOID FindSuitableFrame(PVOID moduleBase) {
    PIMAGE_EXPORT_DIRECTORY exportDir = NULL;
    if (!GetImageExportDirectory(moduleBase, &exportDir)) return NULL;

    PDWORD names = (PDWORD)((PBYTE)moduleBase + exportDir->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)moduleBase + exportDir->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)((PBYTE)moduleBase + exportDir->AddressOfFunctions);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        PCHAR funcName = (PCHAR)((PBYTE)moduleBase + names[i]);
        PVOID funcAddr = (PBYTE)moduleBase + functions[ordinals[i]];
        
        DWORD64 imageBase = (DWORD64)moduleBase;
		if (IsForwarder(moduleBase, funcAddr)) continue;
        PRUNTIME_FUNCTION rf = VxLookupFunctionEntry((DWORD64)funcAddr,moduleBase);
        
        if (rf) {
            PUNWIND_INFO info = (PUNWIND_INFO)(imageBase + rf->UnwindData);
            // 1. 使用 RBP 作为帧指针 (FrameRegister == 5)
            if (info->FrameRegister != 5) {
                continue;
            }

            // 2. 提取 FrameOffset (UnwindInfo 中的 offset 是以 16 字节为单位的)
            // 如果 FrameOffset == 0，说明 mov rbp, rsp
            // 如果 FrameOffset != 0，说明 lea rbp, [rsp + Offset*16]
            DWORD currentFrameOffset = info->FrameOffset * 16;

            // 检查是否包含 UWOP_SET_FPREG
            BOOL hasSetFpReg = FALSE;
            UBYTE idx = 0;
            while (idx < info->CountOfCodes) {
                UBYTE op = info->UnwindCode[idx].UnwindOp;
                if (op == UWOP_SET_FPREG) {
                    hasSetFpReg = TRUE;
                    break;
                }
                // 跳过操作数
                if (op == UWOP_ALLOC_LARGE) {
                    idx++;
                    if (info->UnwindCode[idx-1].OpInfo == 0) idx++;
                    else idx += 2;
                }
                else if (op == UWOP_SAVE_NONVOL || op == UWOP_SAVE_XMM128) {
                    idx++;
                }
                else if (op == UWOP_SAVE_NONVOL_BIG || op == UWOP_SAVE_XMM128BIG) {
                    idx += 2;
                }
                idx++;
            }

            if (hasSetFpReg) {
                // 找到哪里 push 了 RBP
                DWORD pushOffset = FindRbpPushOffset(funcAddr,moduleBase);
                
                // 只要找到了 push offset，我们就认为这个 gadget 可用
                if (pushOffset != 0) {
                   // LOG("[+] Found Gadget Frame: %s @ %p (RBP Offset: 0x%X)", funcName, funcAddr, currentFrameOffset);    
                    g_RbpFrameOffset = currentFrameOffset;
                    return funcAddr;
                }
            }
        }
    }
    return NULL;
}
