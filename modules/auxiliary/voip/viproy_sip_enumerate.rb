##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::SIP
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'Viproy SIP Enumerator Module',
      'Version'     => '1',
      'Description' => 'Enumeration Module for SIP Services',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOSTS','USER_AS_PASS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS')

    register_options(
    [
      OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
      OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
      OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
      OptString.new('METHOD',   [ true, "Method for Brute Force (SUBSCRIBE,REGISTER,INVITE,OPTIONS)", "SUBSCRIBE"]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      Opt::RHOST,
      Opt::RPORT(5060),
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
      OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptBool.new('USER_AS_FROM_and_TO', [true, 'Use the Username for From and To fields', true]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
    ], self.class)
  end

  def run
    if datastore['METHOD'] =~ /[SUBSCRIBE|REGISTER|INVITE]/
      method = datastore['METHOD']
    else
      print_error("Brute Force METHOD must be defined")
    end

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

    reported_users=[]

    if datastore['NUMERIC_USERS'] == true
      exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
      exts.each { |ext|
        ext=ext.to_s
        from=to=ext if datastore['USER_AS_FROM_and_TO']
        reported_users = do_login(ext,from,to,dest_addr,method,reported_users)
      }
    else
      if datastore['USER_FILE'].nil?
        print_error("User wordlist is not provided.")
        return
      end
      each_user_pass { |user, password|
        from=to=user if datastore['USER_AS_FROM_and_TO']
        reported_users = do_login(user,from,to,dest_addr,method,reported_users)
      }
    end

    sipsocket_stop
  end

  def do_login(user,from,to,dest_addr,method,reported_users)
    realm = datastore['REALM']
    cred={
      'login'     => false,
      'user'      => user,
      'password'  => nil,
      'realm'     => realm,
      'from'      => from,
      'to'        => to
    }

    print_debug("Enumeration method is #{method}.") if datastore['DEBUG']
    case method
    when "REGISTER"
      results = send_register(cred)
      possible = /^200/
    when "SUBSCRIBE"
      results = send_subscribe(cred)
      possible = /^40[0-3]|^40[5-9]|^200/
    when "OPTIONS"
      results = send_options(cred)
      possible = /^40[0-3]|^40[5-9]/
    when "INVITE"
      results = send_invite(cred)
      possible = /^40[0-3]|^40[5-9]|^200/
    end

    rdata = results["rdata"]
    if rdata != nil and rdata['resp'] =~ possible
      user=rdata['from'].split("@")[0]

      if ! reported_users.include?(user)
        print_good("User #{user} is Valid (Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")})")
        vprint_status("Warning: #{rdata['warning']}") if rdata['warning']
        reported_users << user
      end
    else
      vprint_status("User #{user} is Invalid (#{rdata['resp_msg'].split(" ")[1,5].join(" ")})") if rdata !=nil
      vprint_status("\tWarning \t\t: #{rdata['warning']}\n") if ! rdata.nil? and rdata['warning']
    end

    printresults(results) if datastore['DEBUG'] == true

    return reported_users
  end
end
