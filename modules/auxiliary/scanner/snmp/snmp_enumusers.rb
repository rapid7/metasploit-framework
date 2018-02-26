##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include SNMP

  def initialize
    super(
      'Name'        => 'SNMP Windows Username Enumeration',
      'Description' => '
        This module will use LanManager/psProcessUsername OID values to
        enumerate local user accounts on a Windows/Solaris system via SNMP
      ',
      'Author'      => ['tebo[at]attackresearch.com'],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    peer = "#{ip}:#{rport}"
    begin
      snmp = connect_snmp

      sys_desc = snmp.get_value('sysDescr.0')
      if sys_desc.blank? || sys_desc.to_s == 'Null'
        vprint_error("#{peer} No sysDescr received")
        return
      end
      sys_desc = sys_desc.split(/[\r\n]/).join(' ')

      sys_desc_map = {
        /Windows/ => '1.3.6.1.4.1.77.1.2.25',
        /Sun/ => '1.3.6.1.4.1.42.3.12.1.8'
      }

      matching_oids = sys_desc_map.select { |re, _| sys_desc =~ re }.values
      if matching_oids.empty?
        vprint_warning("#{peer} Skipping unsupported sysDescr: '#{sys_desc}'")
        return
      end
      users = []

      matching_oids.each do |oid|
        snmp.walk(oid) do |row|
          row.each { |val| users << val.value.to_s }
        end
      end
      unless users.empty?
        users.sort!
        users.uniq!
        print_good("#{peer} Found #{users.size} users: #{users.join(', ')}")
      end

      report_note(
        host: rhost,
        port: rport,
        proto: 'udp',
        sname: 'snmp',
        update: :unique_data,
        type: 'snmp.users',
        data: users
      )
    rescue ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
      # too noisy for a scanner
    ensure
      disconnect_snmp
    end
  end
end
