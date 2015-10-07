##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP Host-Header Injection Detection',
      'Description' => 'Checks if the host is vulnerable to Host-Header Injection',
      'Author'       =>
        [
          'Jay Turla <@shipcod3>',
          'Medz Barao <@godflux>'
        ],
      'License'     => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html']
        ]
    ))

    register_options(
      [
        OptString.new('TARGETHOST',[true, "The redirector target", "evil.com"]),
      ],self.class)
  end

  def run_host(target_host)

    begin
      p = "#{datastore['TARGETHOST']}"
      res = send_request_raw({
        'uri'          => '/',
        'method'       => 'GET',
        'headers'      => {
          'host' => p,
          'x-forwarded-host' => p,
        }
      })

      unless res
        vprint_error("#{rhost}:#{rport} did not reply to our request")
        return
      end

      if res.headers =~ /#{p}/ || res.body =~ /#{p}/
        print_good("#{rhost}:#{rport} is vulnerable to HTTP Host-Header Injection")
        report_vuln(
          :host   => rhost,
          :port   => rport,
          :proto  => 'tcp',
          :sname  => (ssl ? 'https' : 'http'),
          :info   => "Vulnerable to HTTP Host-Header Injection",
        )
      else
        vprint_error("#{rhost}:#{rport} returned #{res.code} #{res.message}")
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
