##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

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

    register_options([
      OptString.new('TARGETURI', [true, 'The URI to use', '/'])
    ])

    register_advanced_options([
      OptString.new('HTTP_METHOD', [true, 'HTTP Method to use', 'GET']),
      OptString.new('PROTOCOL', [false, 'Protocol to use', 'HTTP'])
    ])
  end

  # Fingerprint a single host
  def run_host(ip)
    begin
      connect
      uri = normalize_uri(target_uri.path)
      res = send_request_raw({
          'method'  => datastore['HTTP_METHOD'],
          'uri'     => uri,
          'proto'   => datastore['PROTOCOL']
      })
      fp = http_fingerprint(:response => res)
      print_status("#{ip}:#{rport} #{fp}") if fp
    rescue ::Timeout::Error, ::Errno::EPIPE
    ensure
      disconnect
    end
  end

end
