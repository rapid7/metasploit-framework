##
# This module requires Metasploit: http//metasploit.com/download
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
      'Name'        => 'HTTP TRACE Detection',
      'Description' => 'Test if TRACE is actually enabled.  405 (Apache) 501(IIS) if its disabled, 200 if it is',
      'Author'       => ['CG'],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(target_host)

    begin
      res = send_request_raw({
        'version'      => '1.0',
        'uri'          => '/',
        'method'       => 'TRACE',
        'headers' =>
        {
          'Cookie' => "did you echo me back?",
        },
      }, 10)

      if res.nil?
        print_error("no repsonse for #{target_host}")
      elsif (res.code == 200)
        print_good("#{target_host}:#{rport}-->#{res.code}")
        print_good("Response Headers:\n #{res.headers}")
        print_good("Response Body:\n #{res.body}")
        print_good("TRACE appears to be enabled on #{target_host}:#{rport} \n")
        report_note(
          :host   => target_host,
          :port   => rport,
          :proto => 'tcp',
          :sname  => (ssl ? 'https' : 'http'),
          :type   => 'service.http.method.trace',
          :data   => "TRACE method is enabled for this service",
          :update => :unique_data
        )
      elsif (res.code == 501)#Not Implemented
        print_error("Received #{res.code} TRACE is not enabled for #{target_host}:#{rport}") #IIS
      elsif (res.code == 405)#Method Not Allowed
        print_error("Received #{res.code} TRACE is not enabled for #{target_host}:#{rport}") #Apache
      else
        print_status("#{res.code}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
