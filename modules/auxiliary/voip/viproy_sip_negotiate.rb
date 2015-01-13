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
      'Name'        => 'Viproy SIP Negotiate Module',
      'Version'     => '1',
      'Description' => 'Negotiate Discovery Module for SIP Services',
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
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
    ], self.class)
  end

  def run_host(dest_addr)
    rports = Rex::Socket.portspec_crack(datastore['RPORTS'])
    rports.each { |rport|
      sockinfo={}
      # Protocol parameters
      sockinfo["proto"] = datastore['PROTO'].downcase
      sockinfo["vendor"] = datastore['VENDOR'].downcase
      sockinfo["macaddress"] = datastore['MACADDRESS']

      # Socket parameters
      sockinfo["listen_addr"] = datastore['CHOST']
      sockinfo["listen_port"] = datastore['CPORT']
      sockinfo["dest_addr"] =datastore['RHOST']
      sockinfo["dest_port"] = rport

      sipsocket_start(sockinfo)
      sipsocket_connect

      results = send_negotiate(
        'realm'		  => datastore['REALM'],
        'from'    	=> datastore['FROM'],
        'to'    	  => datastore['TO']
      )

      printresults(results)
      sipsocket_stop
    }
  end
end