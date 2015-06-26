##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/meeterpeter_x86_bsd'
require 'msf/base/sessions/meeterpeter_options'

module Metasploit3

  CachedSize = 0

  include Msf::Payload::Bsd
  include Msf::Payload::Single
  include Msf::Sessions::meeterpeterOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'FreeBSD meeterpeter Service, Bind TCP',
      'Description'   => 'Stub payload for interacting with a meeterpeter Service',
      'Author'        => 'hdm',
      'License'       => BSD_LICENSE,
      'Platform'      => 'bsd',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::meeterpeter_x86_BSD,
      'Payload'       =>
        {
          'Offsets' => {},
          'Payload' => ""
        }
      ))
  end

end
