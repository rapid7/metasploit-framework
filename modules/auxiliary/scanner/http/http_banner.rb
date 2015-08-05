##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP Banner Detection',
      'Description' => %q{ This module shows HTTP Banner returned by webserver. If you have loaded a database plugin and connected to a database this module will record the info so you can list all banners. },
      'Author'      =>  'Manuel Mancera (sinkmanu)',
      'References'  =>
      [
        ['URL', 'http://tools.ietf.org/html/rfc4229']
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptString.new('HTTP_METHOD', [ true, 'HTTP Method to use', 'GET']),
      OptString.new('PROTOCOL', [ false, 'Protocol to use', 'HTTP']),
      OptString.new('TARGETURI', [ true, 'The URI to use', '/'])
    ])
  end

  def timeout
    datastore['TIMEOUT']
  end

  def run_host(ip)
    print_status "Trying #{peer}"
    uri = normalize_uri(target_uri.path)

    res = send_request_raw({
      'method'  => datastore['HTTP_METHOD'],
      'uri'     => uri,
      'proto'   => datastore['PROTOCOL']
    })

    if res
      banner = res.headers['Server']
      unless banner.nil?
        print_good "Found: #{banner}"
        report_service(
          :host => ip,
          :port => rport,
          :name => "http",
          :info => "#{banner}"
        )
      end
    end
  end
end
