##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Host Header Injection Detection',
      'Description' => 'Checks if the host is vulnerable to Host header injection',
      'Author'      =>
        [
          'Jay Turla', # @shipcod3
          'Medz Barao' # @godflux
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2016-10073'], # validate, an instance of a described attack approach from the original reference
          ['URL', 'http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html']
        ]
    ))

    register_options(
      [
        OptString.new('TARGETHOST', [true, 'The redirector target', 'evil.com'])
      ])
  end

  def run_host(ip)
    begin
      target_host = "#{datastore['TARGETHOST']}"
      res = send_request_raw(
        'uri'          => '/',
        'method'       => 'GET',
        'headers'      => {
          'Host'             => target_host,
          'X-Forwarded-Host' => target_host
        }
      )

      unless res
        vprint_error("#{peer} did not reply to our request")
        return
      end

      if res.headers.include?(target_host) || res.body.include?(target_host)
        print_good("#{peer} is vulnerable to HTTP Host header injection")
        report_vuln(
          host: ip,
          port: rport,
          proto: 'tcp',
          sname: ssl ? 'https' : 'http',
          name: 'HTTP Host header injection',
          refs: self.references
        )
      else
        vprint_error("#{peer} returned #{res.code} #{res.message}")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
