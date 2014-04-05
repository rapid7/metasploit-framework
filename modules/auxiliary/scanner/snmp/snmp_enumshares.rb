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
      'Name'        => 'SNMP Windows SMB Share Enumeration',
      'Description' => "This module will use LanManager OID values to enumerate SMB shares on a Windows system via SNMP",
      'Author'      => ['tebo[at]attackresearch.com'],
      'License'     => MSF_LICENSE
    )

  end

  def run_host(ip)
    begin
      snmp = connect_snmp

      share_tbl = ["1.3.6.1.4.1.77.1.2.27.1.1",
            "1.3.6.1.4.1.77.1.2.27.1.2",
            "1.3.6.1.4.1.77.1.2.27.1.3"]

      @shares = []
      if snmp.get_value('sysDescr.0') =~ /Windows/

        snmp.walk(share_tbl) do |entry|
          @shares << entry.collect{|x|x.value}
        end
      end

      disconnect_snmp

      if not @shares.empty?
        print_good("#{ip} #{@shares.map{|x| "\n\t#{x[0]} - #{x[2]} (#{x[1]})" }.join}") #"
        report_note(
          :host => ip,
          :proto => 'udp',
          :port => datastore['RPORT'],
          :sname => 'snmp',
          :type => 'smb.shares',
          :data => { :shares => @shares },
          :update => :unique_data
        )
      end

    rescue ::Rex::ConnectionError, ::SNMP::RequestTimeout, ::SNMP::UnsupportedVersion
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("#{ip} Unknown error: #{e.class} #{e}")
    ensure
      disconnect_snmp
    end

  end

end
