##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/generic'


module MetasploitModule

  CachedSize = 1

  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Generic x86 Debug Trap',
      'Description'   => 'Generate a debug trap in the target process',
      'Author'        => 'robert <robertmetasploit[at]gmail.com>',
      'Platform'	=> %w{ bsd bsdi linux osx solaris win },
      'License'       => MSF_LICENSE,
      'Arch'		=> ARCH_X86,
      'Payload'	=>
        {
          'Payload' =>
              "\xcc"
        }
      ))
  end
end
