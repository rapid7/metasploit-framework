##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 8

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Command, Generic Command Execution',
        'Description' => 'Executes the supplied command',
        'Author' => 'juan vazquez',
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::None,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'generic',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )

    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute' ]),
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    return datastore['CMD'] || ''
  end
end
