##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rexml/document'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chromecast Web Server Scanner',
      'Description' => %q{
        This module scans for the Chromecast web server on port 8008/TCP.

        To be used with other Chromecast modules such as chromecast_youtube.
      },
      'Author' => ['wvu'],
      'References' => [
        ['URL', 'https://www.google.com/chrome/devices/chromecast/']
      ],
      'License' => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(8008)
    ])
  end

  def run_host(ip)
    res = send_request_raw(
      'method' => 'GET',
      'uri' => '/ssdp/device-desc.xml',
      'agent' => Rex::Text.rand_text_english(rand(42) + 1)
    )

    return unless (res && res.code == 200)

    name = REXML::Document.new(res.body).elements['//friendlyName']

    if name
      print_good("#{peer} - #{name.text}")
      report_service(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :name => 'chromecast',
        :info => name.text
      )
    end
  end

end
