##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chromecast Web Server Scanner',
      'Description' => %q{
        This module scans for the Chromecast web server on port 8008/TCP, and
        can be used to discover devices which can be targeted by other Chromecast
        modules, such as chromecast_youtube.
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
      'uri' => '/setup/eureka_info',
      'agent' => Rex::Text.rand_text_english(rand(42) + 1)
    )

    return unless (res && res.code == 200)

    json = res.get_json_document
    name, ssid = json['name'], json['ssid']

    if name && ssid
      print_good(%Q{#{peer} - Chromecast "#{name}" is connected to #{ssid}})
      report_service(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :name => 'http',
        :info => %Q{Chromecast "#{name}" connected to #{ssid}}
      )
    end
  end
end
