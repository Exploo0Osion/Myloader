#include "myloader.h"

void MySrand(unsigned long seed) { g_seed = seed; }
int MyRand() {
    g_seed = g_seed * 1103515245 + 12345;
    return (unsigned int)(g_seed / 65536) % 32768;
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x3141592653589793;
	INT c;
	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;
	return dwHash;
}

DWORD64 djb2_w(PCWSTR str) {
    DWORD64 dwHash = 0x3141592653589793;
    WCHAR c;
    while (c = *str++) {
        if (c >= L'a' && c <= L'z') c -= 0x20;
        dwHash = ((dwHash << 0x5) + dwHash) + c;
    }
    return dwHash;
}

VOID VxInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString) {
        SIZE_T len = 0;
        while (SourceString[len]) len++;
        DestinationString->Length = (USHORT)(len * sizeof(WCHAR));
        DestinationString->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
        DestinationString->Buffer = (PWSTR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}

// 获取函数地址的辅助函数 (GetProcAddress 的简单实现)
PVOID VxGetProcAddress(PVOID hModule, DWORD dwHash) {
    PIMAGE_EXPORT_DIRECTORY pExportDir = NULL;
    if (!GetImageExportDirectory(hModule, &pExportDir)) return NULL;
    
    PDWORD names = (PDWORD)((PBYTE)hModule + pExportDir->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)hModule + pExportDir->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)((PBYTE)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((PBYTE)hModule + names[i]);
        if (djb2((PBYTE)name) == dwHash) {
            return (PBYTE)hModule + functions[ordinals[i]];
        }
    }
    return NULL;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = (char*)dest;
	const char* s = (const char*)src;
	if (d < s) while (len--) *d++ = *s++;
	else {
		char* lasts = (char*)s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--) *lastd-- = *lasts--;
	}
	return dest;
}


BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}


