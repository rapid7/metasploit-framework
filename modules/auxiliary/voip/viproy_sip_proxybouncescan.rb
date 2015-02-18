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
      'Name'        => 'Viproy UDP SIP Proxy Bounce Scanner',
      'Version'     => '1',
      'Description' => 'UDP based SIP Proxy bounce scanner module',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )
    deregister_options('RPORT', 'RHOST', 'THREADS' )
    register_options(
    [
      OptString.new('RPORTS', [true, 'Port Range for Proxy Bounce Scan', "5060-5065"]),
      OptAddressRange.new('RHOSTS', [true, 'IP Range for Proxy Bounce Scan']),
      OptAddress.new('SIP_SERVER_IP',   [true, 'Vulnerable SIP Server IP']),
      OptInt.new('SIP_SERVER_PORT',   [true, 'Vulnerable SIP Server Port',5060]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),

    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('TO',   [ true, "The destination username to probe at each host", "100"]),
      OptString.new('FROM',   [ true, "The source username to probe at each host", "100"]),
    ], self.class)
  end

  def run
    sockinfo={}
    # Protocol parameters
    sockinfo["proto"] = datastore['PROTO'].downcase
    sockinfo["macaddress"] = datastore['MACADDRESS']

    # Socket parameters
    sockinfo["listen_addr"] = datastore['CHOST']
    sockinfo["listen_port"] = datastore['CPORT']
    sockinfo["dest_addr"] = datastore['SIP_SERVER_IP']
    sockinfo["dest_port"] = datastore['SIP_SERVER_PORT']

    rhosts = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
    rports = Rex::Socket.portspec_crack(datastore['RPORTS'])

    sipsocket_start(sockinfo)
    sipsocket_connect

    rhosts.each do |rhost|
      rports.each do |rport|
        results = send_options(
          'realm'		  => "#{rhost}:#{rport}",
          'from'    	=> datastore['FROM'],
          'to'    	  => datastore['TO']
        )
        rdata = results["rdata"]

        if results["status"] == :received and ! (rdata['resp_msg'] =~ /timeout/)
          if rdata["contact"]
          report = "#{rdata["contact"].gsub("sip:","")} is Open\n"
          else
          report = "#{rhost}:#{rport} is Open\n"
          end
          report <<"    Server \t: #{rdata['server']}\n" if rdata['server']
          report <<"    User-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
          print_good(report)

          printresults(results) if datastore['DEBUG'] == true
        else
          vprint_status("#{rhost}:#{rport} is Close/Filtered\n")
        end
      end
    end

    sipsocket_stop

  end
end
