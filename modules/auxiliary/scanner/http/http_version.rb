##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP Version Detection',
      'Description' => 'Display version information about each system.',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_wmap_options({
        'OrderID' => 0,
        'Require' => {},
      })
  end

  # Fingerprint a single host
  def run_host(ip)
    begin
      connect
      res = send_request_raw({ 'uri' => '/', 'method' => 'GET' })
      fp = http_fingerprint(:response => res)
      print_good("#{ip}:#{rport} #{fp}") if fp
      report_service(:host => rhost, :port => rport, :sname => (ssl ? 'https' : 'http'), :info => fp)
    rescue ::Timeout::Error, ::Errno::EPIPE
    ensure
      disconnect
    end
  end
end
