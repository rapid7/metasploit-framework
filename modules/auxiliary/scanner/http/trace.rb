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

  def initialize
    super(
      'Name'        => 'HTTP Cross-Site Tracing Detection',
      'Description' => 'Checks if the host is vulnerable to Cross-Site Tracing (XST)',
      'Author'       =>
        [
          'Jay Turla <@shipcod3>' , #Cross-Site Tracing (XST) Checker
          'CG' #HTTP TRACE Detection
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(target_host)

    begin
      res = send_request_raw({
        'version'      => '1.0',
        'uri'          => '/<script>alert(1337)</script>', #XST Payload
        'method'       => 'TRACE',
      })

      if res.nil?
        vprint_error("no repsonse for #{target_host}")
      elsif res.code == 200 and res.body =~/>alert\(1337\)/
        vprint_status("#{target_host}:#{rport}-->#{res.code}")
        print_good("Response Headers:\n #{res.headers}")
        print_good("Response Body:\n #{res.body}")
        print_good("#{target_host}:#{rport} is vulnerable to Cross-Site Tracing")
        report_vuln(
          :host   => target_host,
          :port   => rport,
          :proto => 'tcp',
          :sname  => (ssl ? 'https' : 'http'),
          :type   => 'service.http.method.trace',
          :info   => "TRACE method is enabled for this service and is vulnerable to Cross-Site Tracing",
        )
      elsif res.code == 405 #Method Not Allowed (Apache)
        vprint_error("Received #{res.code} Method Not Allowed for #{target_host}:#{rport}")
      elsif res.code == 501 #Not Implemented (IIS)
        vprint_error("Received #{res.code} TRACE is not enabled for #{target_host}:#{rport}")
      else
        vprint_status("#{res.code}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
