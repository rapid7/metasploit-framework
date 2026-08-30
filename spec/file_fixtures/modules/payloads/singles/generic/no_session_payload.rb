##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule

  CachedSize = 12

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'mock payload which gives no session',
        'Description' => 'mock payload which gives no session',
        'Author' => ['unknown'],
        'License' => MSF_LICENSE,
        'Platform' => ['unix'],
        'Arch' => ARCH_CMD,
        # 'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )

    register_options(
      [
        Msf::OptString.new('REQUIRED_PAYLOAD_OPTION', [true, 'A required option for this payload', '123-123'], regex: /\d{3}-\d{3}/)
      ]
    )
  end

  def wait_for_session(_t = wfs_delay)
    # noop
  end

  def generate
    'mock payload'
  end
end
