##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 0

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix SSH Shell, Bind Instance Connect (via AWS API)',
        'Description' => 'Creates an SSH shell using AWS Instance Connect',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'References' => [['URL', 'https://www.sempervictus.com/single-post/a-serial-case-of-air-on-the-side-channel']],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_ALL,
        'Handler' => Msf::Handler::BindAwsInstanceConnect,
        'Session' => Msf::Sessions::AwsInstanceConnectCommandShellBind,
        'DefaultOptions' => { 'CommandShellCleanupCommand' => 'exit' },
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  def on_session(session)
    super

    session.arch.clear  # undo the ARCH_ALL amalgamation
  end
end
