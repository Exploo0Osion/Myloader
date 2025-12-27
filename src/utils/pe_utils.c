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
PVOID GetProcAddressByName(PVOID pModuleBase, DWORD64 dwHash) {
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pModuleBase, &pImageExportDirectory)) return NULL;

    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[i]);
        if (djb2((PBYTE)pczFunctionName)==dwHash) {
            return (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];
        }
    }
    return NULL;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}


