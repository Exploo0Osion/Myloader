; utils.asm
; 编译: ml64 /c utils.asm

.code

GetKernel32 PROC
    xor rax, rax
    mov rax, gs:[60h]           ; PEB
    mov rax, [rax + 18h]        ; PEB->Ldr
    mov rax, [rax + 20h]        ; InMemoryOrderModuleList
    mov rax, [rax]              ; 第1个 (Program)
    mov rax, [rax]              ; 第2个 (ntdll)
    mov rax, [rax]              ; 第3个 (kernel32)
    mov rax, [rax + 20h] 
    ret
GetKernel32 ENDP

GetApi PROC
    push rbx
    push rdi
    push rsi
    
    mov rbx, rcx                ; RBX = Base
    mov eax, [rbx + 3Ch]        ; e_lfanew
    add rax, rbx                ; NT Headers
    mov eax, [rax + 88h]        ; Export Directory RVA
    test eax, eax
    jz _not_found
    add rax, rbx                ; Export Directory

    mov r8d, [rax + 20h]        ; AddressOfNames
    add r8, rbx
    mov r9d, [rax + 24h]        ; AddressOfNameOrdinals
    add r9, rbx
    mov r10d,[rax + 1Ch]        ; AddressOfFunctions
    add r10, rbx
    
    mov ecx, [rax + 18h]        ; NumberOfNames
    xor rdi, rdi                ; Index

_loop:
    test ecx, ecx
    jz _not_found
    
    mov esi, [r8 + rdi * 4]     ; Name RVA
    add rsi, rbx                ; Name String
    
    ; --- Hash Calculation (ROR 13) ---
    xor rax, rax
    push rdx                    ; Save target hash
    xor rdx, rdx                ; Current hash = 0
    
_hash_char:
    lodsb
    test al, al
    jz _hash_end
    ror edx, 13
    add edx, eax
    jmp _hash_char
    
_hash_end:
    mov eax, edx                ; EAX = Calculated Hash
    pop rdx                     ; Restore target hash
    
    cmp eax, edx
    je _found
    
    inc rdi
    dec ecx
    jmp _loop

_found:
    movzx ecx, word ptr [r9 + rdi * 2]  ; Ordinal
    mov eax, [r10 + rcx * 4]            ; Function RVA
    add rax, rbx                        ; Function Address
    jmp _done

_not_found:
    xor rax, rax

_done:
    pop rsi
    pop rdi
    pop rbx
    ret
GetApi ENDP

END