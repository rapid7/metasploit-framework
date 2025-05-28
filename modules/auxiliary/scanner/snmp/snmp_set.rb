##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SNMP Set Module',
        'Description' => %q{
          This module, similar to snmpset tool, uses the SNMP SET request
          to set information on a network entity. A OID (numeric notation)
          and a value are required. Target device must permit write access.
        },
        'References' => [
          [ 'URL', 'https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol' ],
          [ 'URL', 'http://www.net-snmp.org/docs/man/snmpset.html' ],
          [ 'URL', 'http://www.oid-info.com/' ],
        ],
        'Author' => 'Matteo Cantoni <goony[at]nothink.org>',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('OID', [ true, 'The object identifier (numeric notation)']),
      OptString.new('OIDVALUE', [ true, 'The value to set']),
    ])
  end

  def run_host(ip)
    oid = datastore['OID'].to_s
    oidvalue = datastore['OIDVALUE'].to_s
    comm = datastore['COMMUNITY'].to_s

    snmp = connect_snmp

    print_status("Try to connect to #{ip}...")

    # get request
    check = snmp.get_value(oid)

    if check.to_s =~ /Null/
      check = '\'\''
    end

    print_status("Check initial value : OID #{oid} => #{check}")

    # set request
    varbind = SNMP::VarBind.new(oid, SNMP::OctetString.new(oidvalue))
    resp = snmp.set(varbind)

    if resp.error_status == :noError

      print_status("Set new value : OID #{oid} => #{oidvalue}")

      # get request
      check = snmp.get_value(oid)

      if check.to_s =~ /Null/
        check = '\'\''
      end

      print_status("Check new value : OID #{oid} => #{check}")

    else
      print_status("#{ip} - OID not writable or does not provide WRITE access with community '#{comm}'")
    end
  rescue ::SNMP::RequestTimeout
    print_error("#{ip} - SNMP request timeout with community '#{comm}'.")
  rescue ::Rex::ConnectionError
    print_error("#{ip} - 'Connection Refused'")
  rescue SNMP::UnsupportedVersion
    print_error("#{ip} - Unsupported SNMP version specified. Select from '1' or '2c'.")
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
  ensure
    disconnect_snmp
  end
end
