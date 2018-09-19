##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chromecast Wifi Enumeration',
      'Description' => %q{
        This module enumerates wireless access points through Chromecast.
      },
      'Author' => ['wvu'],
      'References' => [
        ['URL', 'http://www.google.com/intl/en/chrome/devices/chromecast/index.html'] # vendor website
      ],
      'License' => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(8008)
    ])
  end

  def run_host(ip)
    res = scan

    return unless res && res.code == 200

    waps_table = Rex::Text::Table.new(
      'Header' => "Wireless Access Points from #{ip}",
      'Columns' => [
        'BSSID',
        'PWR',
        'ENC',
        'CIPHER',
        'AUTH',
        'ESSID'
      ],
      'SortIndex' => -1
    )

    res.get_json_document.each do |wap|
      waps_table << [
        wap['bssid'],
        wap['signal_level'],
        enc(wap),
        cipher(wap),
        auth(wap),
        wap['ssid'] + (wap['wpa_id'] ? ' (*)' : '')
      ]
    end

    unless waps_table.rows.empty?
      print_line(waps_table.to_s)
      report_note(
        :host => ip,
        :port => rport,
        :proto => 'tcp',
        :type => 'chromecast.wifi',
        :data => waps_table.to_csv
      )
    end
  end

  def scan
    send_request_raw(
      'method' => 'POST',
      'uri' => '/setup/scan_wifi',
      'agent' => Rex::Text.rand_text_english(rand(42) + 1)
    )
    send_request_raw(
      'method' => 'GET',
      'uri' => '/setup/scan_results',
      'agent' => Rex::Text.rand_text_english(rand(42) + 1)
    )
  end

  def enc(wap)
    case wap['wpa_auth']
    when 1
      'OPN'
    when 2
      'WEP'
    when 5
      'WPA'
    when 0, 7
      'WPA2'
    else
      wap['wpa_auth']
    end
  end

  def cipher(wap)
    case wap['wpa_cipher']
    when 1
      ''
    when 2
      'WEP'
    when 3
      'TKIP'
    when 4
      'CCMP'
    else
      wap['wpa_cipher']
    end
  end

  def auth(wap)
    case wap['wpa_auth']
    when 0
      'MGT'
    when 5, 7
      'PSK'
    else
      ''
    end
  end
end
