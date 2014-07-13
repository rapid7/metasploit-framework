##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::SNMPClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'SNMP Windows Username Enumeration',
      'Description' => "This module will use LanManager/psProcessUsername OID values to enumerate local user accounts on a Windows/Solaris system via SNMP",
      'Author'      => ['tebo[at]attackresearch.com'],
      'License'     => MSF_LICENSE
    )

  end

  def run_host(ip)
    begin
      snmp = connect_snmp

      if snmp.get_value('sysDescr.0') =~ /Windows/

        @users = []
        snmp.walk("1.3.6.1.4.1.77.1.2.25") do |row|
          row.each { |val| @users << val.value.to_s }
        end

        print_good("#{ip} Found Users: #{@users.sort.join(", ")} ")

      end
      if snmp.get_value('sysDescr.0') =~ /Sun/

        @users = []
        snmp.walk("1.3.6.1.4.1.42.3.12.1.8") do |row|
          row.each { |val| @users << val.value.to_s }
        end

        print_good("#{ip} Found Users: #{@users.sort.uniq.join(", ")} ")
      end

      disconnect_snmp

      report_note(
        :host => rhost,
        :port => datastore['RPORT'],
        :proto => 'udp',
        :sname => 'snmp',
        :update => :unique_data,
        :type => 'snmp.users',
        :data => @users
      )


    rescue ::SNMP::UnsupportedVersion
    rescue ::SNMP::RequestTimeout
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Unknown error: #{e.class} #{e}")
    end

  end

end
