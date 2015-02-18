##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::SIP

  def initialize
    super(
      'Name'        => 'Viproy SIP Options Module',
      'Version'     => '1',
      'Description' => 'Options Discovery Module for SIP Services',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('TO',   [ true, "The destination username to probe at each host", "100"]),
      OptString.new('FROM',   [ true, "The source username to probe at each host", "100"]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      OptString.new('RPORTS', [true, 'Port Range (5060-5065)', "5060"]),
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
    ], self.class)
  end

  def run_host(dest_addr)
    rports = Rex::Socket.portspec_crack(datastore['RPORTS'])
    rports.each { |rport|
      sockinfo={}
      sockinfo["listen_addr"] = datastore['CHOST']
      sockinfo["listen_port"] = datastore['CPORT']
      sockinfo["dest_addr"] = dest_addr
      sockinfo["dest_port"] = rport
      sockinfo["proto"] = datastore['PROTO'].downcase
      sockinfo["vendor"] = datastore['VENDOR'].downcase
      sockinfo["macaddress"] = datastore['MACADDRESS']

      # sending options
      sipsocket_start(sockinfo)
      sipsocket_connect
      results = send_options(
        'realm'		  => datastore['REALM'],
        'from'    	=> datastore['FROM'],
        'to'    	  => datastore['TO']
      )
      printresults(results)
      sipsocket_stop
    }
  end
end
