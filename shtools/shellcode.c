// shellcode.c
#include <Windows.h>

#pragma runtime_checks( "", off )
#pragma optimize( "", off )
#pragma code_seg(".text$A") 


extern PVOID GetKernel32();
extern PVOID GetApi(PVOID hModule, DWORD dwHash);


#define HASH_LOADLIBRARYA   0xEC0E4E8E
#define HASH_MESSAGEBOXA    0xBC4DA2A8

// 函数指针定义
typedef HMODULE (WINAPI * LOADLIBRARYA)(LPCSTR);
typedef int     (WINAPI * MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

void EntryPoint() {
    // A. 通过汇编获取 Kernel32 基址
    HMODULE hKernel32 = (HMODULE)GetKernel32();
    if (!hKernel32) return;
    // B. 通过汇编解析 API (LoadLibraryA)
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)GetApi(hKernel32, HASH_LOADLIBRARYA);
    if (!pLoadLibraryA) return;
    char szUser32[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    HMODULE hUser32 = pLoadLibraryA(szUser32);
    
    if (hUser32) {
        MESSAGEBOXA pMessageBoxA = (MESSAGEBOXA)GetApi(hUser32, HASH_MESSAGEBOXA);
        
        if (pMessageBoxA) {
            char szContent[] = { 'H','e','l','l','o',' ','A','S','M', 0 };
            char szTitle[]   = { 'M','i','x','e','d', 0 };
            do {
                pMessageBoxA(NULL, szContent, szTitle, 0);
            } while (1);
        }
    }
}