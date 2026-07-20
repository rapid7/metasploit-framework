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
      'Name' => 'SNMP Windows SMB Share Enumeration',
      'Description' => 'This module will use LanManager OID values to enumerate SMB shares on a Windows system via SNMP',
      'Author' => ['tebo[at]attackresearch.com'],
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

    share_tbl = [
      '1.3.6.1.4.1.77.1.2.27.1.1',
      '1.3.6.1.4.1.77.1.2.27.1.2',
      '1.3.6.1.4.1.77.1.2.27.1.3'
    ]

    @shares = []
    if snmp.get_value('sysDescr.0') =~ /Windows/

      snmp.walk(share_tbl) do |entry|
        @shares << entry.collect(&:value)
      end
    end

    disconnect_snmp

    return if @shares.empty?

    print_good("#{ip} #{@shares.map { |x| "\n\t#{x[0]} - #{x[2]} (#{x[1]})" }.join}")
    report_note(
      host: ip,
      proto: 'udp',
      port: datastore['RPORT'],
      sname: 'snmp',
      type: 'smb.shares',
      data: { shares: @shares },
      update: :unique_data
    )
  rescue SNMP::ParseError
    print_error("#{ip} Encountered an SNMP parsing error while trying to enumerate the host.")
  rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout => e
    vprint_error("#{ip} #{e.message}")
  rescue ::SNMP::UnsupportedVersion => e
    vprint_error("#{ip} #{e.message}")
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("#{ip} Unknown error: #{e.class} #{e}")
  ensure
    disconnect_snmp
  end
end
