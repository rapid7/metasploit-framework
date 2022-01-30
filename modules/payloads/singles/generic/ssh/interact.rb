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
        'Name' => 'Interact with Established SSH Connection',
        'Description' => 'Interacts with a shell on an established SSH connection',
        'Author' => 'Spencer McIntyre',
        'License' => MSF_LICENSE,
        'Platform' => '',
        'Arch' => ARCH_ALL,
        'Handler' => Msf::Handler::Generic,
        'Session' => Msf::Sessions::SshCommandShellBind,
        'PayloadType' => 'ssh_interact',
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
