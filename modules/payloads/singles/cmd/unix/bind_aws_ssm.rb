##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 70

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Bind SSM (via AWS API)',
        'Description' => 'Creates an interactive shell using AWS SSM',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindAwsSsm,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'generic',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    ''
  end
end
