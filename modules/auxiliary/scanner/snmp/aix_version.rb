##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'English'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'AIX SNMP Scanner',
      'Description' => 'AIX SNMP scanner auxiliary module.',
      'Author' => [
        'Ramon de C Valle',
        'Adriano Lima <adriano[at]risesecurity.org>',
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )
  end

  def run_host(ip)
    snmp = connect_snmp

    value = snmp.get_value('sysDescr.0')

    unless value =~ /AIX/
      print_error("#{ip} system is not AIX: #{value}")
      return
    end

    value = value.split("\n")
    description = value[0].strip
    value = value[2].split(':')

    value = value[1].strip
    value = value.split('.')

    value[0] = value[0].to_i
    value[1] = value[1].to_i
    value[2] = value[2].to_i
    value[3] = value[3].to_i

    version = "#{value[0]}.#{value[1]}.#{value[2]}.#{value[3]}"

    report_note(
      host: ip,
      proto: 'udp',
      sname: 'snmp',
      port: datastore['RPORT'],
      type: 'AIX',
      data: { version: version }
    )

    status = "#{ip} (#{description}) is running: "
    status << "IBM AIX Version #{value[0]}.#{value[1]}.#{value[3]} "
    status << "(#{version})"

    print_status(status)
  rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout
    # No need to make noise about timeouts
  rescue ::SNMP::UnsupportedVersion => e
    vprint_error(e.message)
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("#{ip} #{e.class}, #{e.message}")
  ensure
    disconnect_snmp
  end
end
