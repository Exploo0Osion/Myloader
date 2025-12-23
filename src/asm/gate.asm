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

    ; 2. 保存 Callee-Saved 寄存器到 Shadow Space (调用者分配给我们的空间)
    mov     [r11+08h], rbp
    mov     [r11+10h], rbx
    
    ; 使用 R12 保存原始 RSP
    mov     [r11+18h], r12
    mov     r12, r11  

    ; 3. 应用动态 RBP 偏移 
    mov     rbp, r11
    add     rbp, [rcx].SPOOFER.RbpFrameOffset
    
    ; 4. 准备 JMP [RBX] 
    lea     rax, restore
    push    rax             ; [栈底] restore 地址
    lea     rbx, [rsp] 

    ; ----------------------------------------------------------
    ; 构建伪造帧 (Fake Frames)
    ; ----------------------------------------------------------
    push    [rcx].SPOOFER.FirstFrameFunctionPointer
    mov     rax, [rcx].SPOOFER.FirstFrameRandomOffset
    add     qword ptr [rsp], rax

    mov     rax, [rcx].SPOOFER.ReturnAddress
    sub     rax, [rcx].SPOOFER.FirstFrameSize

    sub     rsp, [rcx].SPOOFER.SecondFrameSize
    mov     r10, [rcx].SPOOFER.StackOffsetWhereRbpIsPushed
    mov     [rsp+r10], rax

    push    [rcx].SPOOFER.SecondFrameFunctionPointer
    mov     rax, [rcx].SPOOFER.SecondFrameRandomOffset
    add     qword ptr [rsp], rax

    ; ----------------------------------------------------------
    ; 构造执行流 (Execution Flow) - 保持之前的修复
    ; ----------------------------------------------------------
    
    ; 1) Thunk 帧 (JmpRbx)
    sub     rsp, [rcx].SPOOFER.JmpRbxGadgetFrameSize
    push    [rcx].SPOOFER.JmpRbxGadgetRef 

    ; 2) Stack Pivot 帧 (AddRsp)
    mov     rax, [rcx].SPOOFER.AddRspXGadgetFrameSize
    sub     rsp, rax

    ; 8 字节对齐
    sub     rsp, 8

    ; 填入 Syscall 的返回地址 (AddRspXGadget)
    mov     r10, [rcx].SPOOFER.AddRspXGadget
    mov     [rsp], r10

    ; 填入 AddRsp 的返回地址 (JmpRbxGadget)
    mov     r10, rsp
    add     r10, 8
    add     r10, rax    ; rax = AddRspXGadgetFrameSize
    
    mov     rax, [rcx].SPOOFER.JmpRbxGadget
    mov     [r10], rax

    ; 3. 准备调用 SyscallWrapper
    mov     rax, [rcx].SPOOFER.SpoofFunctionPointer
    jmp     parameter_handler
    jmp     execute
SpoofCall endp

restore proc
    ; 使用 R12 恢复堆栈,R12 始终保存着最开始的 RSP。
    mov     rsp, r12
    ; 恢复寄存器
    mov     r12, [rsp+18h] 
    mov     rbx, [rsp+10h]
    mov     rbp, [rsp+08h]
    ret
restore endp

parameter_handler proc
    mov     r9, rax
    mov     rax, 8
    mov     r8, [rcx].SPOOFER.Nargs
    mul     r8
    xchg    r9, rax
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
    push    r15
    mov     r15, [rcx].SPOOFER.Arg08
    mov     [rsp+48h], r15
    pop     r15
    jmp     handle_seven
handle_eight endp
handle_nine proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg09
    mov     [rsp+50h], r15
    pop     r15
    jmp     handle_eight
handle_nine endp
handle_ten proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg10
    mov     [rsp+58h], r15
    pop     r15
    jmp     handle_nine
handle_ten endp
handle_eleven proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg11
    mov     [rsp+60h], r15
    pop     r15
    jmp     handle_ten
handle_eleven endp
handle_twelve proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg12
    mov     [rsp+68h], r15
    pop     r15
    jmp     handle_eleven
handle_twelve endp
handle_seven proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg07
    mov     [rsp+40h], r15
    pop     r15
    jmp     handle_six
handle_seven endp
handle_six proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg06
    mov     [rsp+38h], r15
    pop     r15
    jmp     handle_five
handle_six endp
handle_five proc
    push    r15
    mov     r15, [rcx].SPOOFER.Arg05
    mov     [rsp+30h], r15
    pop     r15
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