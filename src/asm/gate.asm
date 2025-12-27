; SilentMoonwalk Desync Spoofer + SysWhispers3
; FIXED: 0xC0000409 Fix (Using R12 Anchor) + Stack Alignment + Syscall Return

.data
PUBLIC g_wSystemCall
PUBLIC g_qSyscallIns
PUBLIC g_qClean
PUBLIC g_qThunk

g_wSystemCall   WORD    0
g_qSyscallIns   QWORD   0
g_qClean        QWORD   0
g_qThunk        QWORD   0

.data?

SPOOFER STRUCT
    KernelBaseAddress               QWORD ?
    KernelBaseAddressEnd            QWORD ?
    RtlUserThreadStartAddress       QWORD ?
    BaseThreadInitThunkAddress      QWORD ?
    FirstFrameFunctionPointer       QWORD ?
    SecondFrameFunctionPointer      QWORD ?
    JmpRbxGadget                    QWORD ?
    AddRspXGadget                   QWORD ?
    FirstFrameSize                  QWORD ?
    FirstFrameRandomOffset          QWORD ?
    SecondFrameSize                 QWORD ?
    SecondFrameRandomOffset         QWORD ?
    JmpRbxGadgetFrameSize           QWORD ?
    AddRspXGadgetFrameSize          QWORD ?
    RtlUserThreadStartFrameSize     QWORD ?
    BaseThreadInitThunkFrameSize    QWORD ?
    StackOffsetWhereRbpIsPushed     QWORD ?
    RbpFrameOffset                  QWORD ?
    JmpRbxGadgetRef                 QWORD ?
    SpoofFunctionPointer            QWORD ?
    ReturnAddress                   QWORD ?
    Nargs                           QWORD ?
    Arg01                           QWORD ?
    Arg02                           QWORD ?
    Arg03                           QWORD ?
    Arg04                           QWORD ?
    Arg05                           QWORD ?
    Arg06                           QWORD ?
    Arg07                           QWORD ?
    Arg08                           QWORD ?
    Arg09                           QWORD ?
    Arg10                           QWORD ?
    Arg11                           QWORD ?
    Arg12                           QWORD ?
SPOOFER ENDS

.code
PUBLIC Gate
PUBLIC Descent
PUBLIC SyscallWrapper
PUBLIC SpoofCall
PUBLIC get_current_rsp

Gate PROC
    mov g_wSystemCall, cx
    mov g_qSyscallIns, rdx
    mov g_qClean, r8
    mov g_qThunk, r9
    ret
Gate ENDP

SyscallWrapper PROC
    mov r10, rcx
    mov eax, 0
    mov ax, g_wSystemCall
    jmp g_qSyscallIns
SyscallWrapper ENDP

Descent PROC
    jmp SyscallWrapper
Descent ENDP

get_current_rsp proc
    mov rax, rsp
    add rax, 8
    ret
get_current_rsp endp

; ------------------------------------------------------------------
; Desynchronization Spoofer
; ------------------------------------------------------------------
SpoofCall proc
    ; 1. 备份原始 RSP 到 R11
    mov     r11, rsp
    mov     [r11+08h], rbp
    mov     [r11+10h], rbx
    mov     [r11+18h], r12
    mov     [r11+20h], rdi ; 新增
    mov     [r11+28h], rsi ; 新增
    mov     [r11+30h], r13 ; 新增
    mov     [r11+38h], r14 ; 新增
    mov     [r11+40h], r15 ; 新增，特别重要，因为下面用到了 R15

    mov     r12, r11  
    
    ; 3. 准备 JMP [RBX] 跳转回来的目标
    lea     rax, restore
    push    rax             ; [栈底] restore 地址
    lea     rbx, [rsp]      ; RBX 指向 restore

    ; ==========================================================
    ; RSP-Based 栈伪造构建
    ; ==========================================================

    ; 1. 压入 0 (作为 RtlUserThreadStart 的返回地址，终止栈回溯)
    push    0

    ; 2. 构建 FirstFrame (RtlUserThreadStart)
    sub     rsp, [rcx].SPOOFER.FirstFrameSize       ; 分配栈空间
    push    [rcx].SPOOFER.FirstFrameFunctionPointer ; 压入函数地址 (作为 BaseThreadInitThunk 的返回地址)
    mov     rax, [rcx].SPOOFER.FirstFrameRandomOffset
    add     qword ptr [rsp], rax                    ; 加上偏移，指向函数体内

    ; 3. 构建 SecondFrame (BaseThreadInitThunk)
    sub     rsp, [rcx].SPOOFER.SecondFrameSize      ; 分配栈空间
    push    [rcx].SPOOFER.SecondFrameFunctionPointer; 压入函数地址 (作为 JmpRbxGadget 的返回地址)
    mov     rax, [rcx].SPOOFER.SecondFrameRandomOffset
    add     qword ptr [rsp], rax                    ; 加上偏移

    ; 4. 构建 JmpRbxFrame (如果有)
    sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize

    ; 5. 为 JmpRbxGadget 预留返回地址位置
    sub     rsp, 8
    mov     rax, [rcx].SPOOFER.JmpRbxGadget
    mov     [rsp], rax

    ; 6. 构建 AddRspFrame (Syscall 的 Shadow Space)
    mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
    sub     rsp, rax

    ; 7. 填入 Syscall 的返回地址 (指向 AddRspGadget)
    mov     r10, [rcx].SPOOFER.AddRspXGadget
    mov     [rsp], r10
    mov     rax, [rcx].SPOOFER.SpoofFunctionPointer
    jmp     parameter_handler
    jmp execute
SpoofCall endp

restore proc
    ; 使用 R12 恢复堆栈,R12 始终保存着最开始的 RSP。
    mov     rsp, r12
    mov     r15, [rsp+40h]
    mov     r14, [rsp+38h]
    mov     r13, [rsp+30h]
    mov     rsi, [rsp+28h]
    mov     rdi, [rsp+20h]
    mov     r12, [rsp+18h]
    mov     rbx, [rsp+10h]
    mov     rbp, [rsp+08h]

    ret
restore endp

parameter_handler proc
    cmp     [rcx].SPOOFER.Nargs, 8
    je      handle_eight
    cmp     [rcx].SPOOFER.Nargs, 9
    je      handle_nine
    cmp     [rcx].SPOOFER.Nargs, 10
    je      handle_ten
    cmp     [rcx].SPOOFER.Nargs, 11
    je      handle_eleven
    cmp     [rcx].SPOOFER.Nargs, 12
    je      handle_twelve
    cmp     [rcx].SPOOFER.Nargs, 7
    je      handle_seven
    cmp     [rcx].SPOOFER.Nargs, 6
    je      handle_six
    cmp     [rcx].SPOOFER.Nargs, 5
    je      handle_five
    cmp     [rcx].SPOOFER.Nargs, 4
    je      handle_four
    cmp     [rcx].SPOOFER.Nargs, 3
    je      handle_three
    cmp     [rcx].SPOOFER.Nargs, 2
    je      handle_two
    cmp     [rcx].SPOOFER.Nargs, 1
    je      handle_one
    cmp     [rcx].SPOOFER.Nargs, 0
    je      handle_none
parameter_handler endp

handle_eight proc
    mov     r15, [rcx].SPOOFER.Arg08
    mov     [rsp+40h], r15
    jmp     handle_seven
handle_eight endp
handle_nine proc
    mov     r15, [rcx].SPOOFER.Arg09
    mov     [rsp+48h], r15
    jmp     handle_eight
handle_nine endp
handle_ten proc
    mov     r15, [rcx].SPOOFER.Arg10
    mov     [rsp+50h], r15
    jmp     handle_nine
handle_ten endp
handle_eleven proc
    mov     r15, [rcx].SPOOFER.Arg11
    mov     [rsp+58h], r15
    jmp     handle_ten
handle_eleven endp
handle_twelve proc
    mov     r15, [rcx].SPOOFER.Arg12
    mov     [rsp+60h], r15
    jmp     handle_eleven
handle_twelve endp
handle_seven proc
    mov     r15, [rcx].SPOOFER.Arg07
    mov     [rsp+38h], r15
    jmp     handle_six
handle_seven endp
handle_six proc
    mov     r15, [rcx].SPOOFER.Arg06
    mov     [rsp+30h], r15
    jmp     handle_five
handle_six endp
handle_five proc
    mov     r15, [rcx].SPOOFER.Arg05
    mov     [rsp+28h], r15
    jmp     handle_four
handle_five endp
handle_four proc
    mov     r9, [rcx].SPOOFER.Arg04
    jmp     handle_three
handle_four endp
handle_three proc
    mov     r8, [rcx].SPOOFER.Arg03
    jmp     handle_two
handle_three endp
handle_two proc
    mov     rdx, [rcx].SPOOFER.Arg02
    jmp     handle_one
handle_two endp
handle_one proc
    mov     rcx, [rcx].SPOOFER.Arg01
    jmp     handle_none
handle_one endp

handle_none proc
    jmp     execute
handle_none endp

execute proc
    jmp     qword ptr rax
execute endp

END