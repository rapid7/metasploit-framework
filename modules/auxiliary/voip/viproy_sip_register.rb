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
      'Name'        => 'Viproy SIP Register Module',
      'Version'     => '1',
      'Description' => 'Register Discovery Module for SIP Services',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('USERNAME',   [ false, "The login username to probe at each host"]),
      OptString.new('PASSWORD',   [ false, "The login password to probe at each host"]),
      OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
      OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
      OptBool.new('LOGIN', [false, 'Login Using Credentials', false]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      Opt::RPORT(5060),
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptBool.new('DEREGISTER', [false, 'De-Register After Successful Login', false]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      OptBool.new('USEREQFROM',   [ false, "FROM will be cloned from USERNAME", true]),
    ], self.class)
  end

  def run_host(dest_addr)
    # Login parameters
    user = datastore['USERNAME']
    password = datastore['PASSWORD']
    realm = datastore['REALM']
    from = datastore['FROM']
    to = datastore['TO']

    sockinfo={}
    # Protocol parameters
    sockinfo["proto"] = datastore['PROTO'].downcase
    sockinfo["vendor"] = datastore['VENDOR'].downcase
    sockinfo["macaddress"] = datastore['MACADDRESS']

    # Socket parameters
    sockinfo["listen_addr"] = datastore['CHOST']
    sockinfo["listen_port"] = datastore['CPORT']
    sockinfo["dest_addr"] =datastore['RHOST']
    sockinfo["dest_port"] = datastore['RPORT']

    sipsocket_start(sockinfo)
    sipsocket_connect

    if vendor == 'mslync'
      results = send_negotiate(
          'realm'		  => datastore['REALM'],
          'from'    	=> datastore['FROM'],
          'to'    	  => datastore['TO']
      )
      printresults(results) if datastore['DEBUG'] == true
    end

    results = send_register(
        'login'  	    => datastore['LOGIN'],
        'user'      	=> user,
        'password'	  => password,
        'realm'		    => realm,
        'from'    	  => from,
        'to'    	    => to
    )

    context = {
        "method"    => "register",
        "user"      => user,
        "password"  => password
    }

    printresults(results,context)

    # Sending de-register
    if datastore['DEREGISTER'] ==true
      #De-Registering User
      send_register(
          'login'  	  => datastore['LOGIN'],
          'user'     	=> user,
          'password'	=> password,
          'realm'     => realm,
          'from'    	=> from,
          'to'    	  => to,
          'expire'    => 0
      )
    end

    sipsocket_stop
  end
end

