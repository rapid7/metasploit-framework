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
      OptString.new('RPORTS', [true, 'Port Range (5060-5065)', "5060"]),
    ], self.class)

    register_advanced_options(
    [
      Opt::CHOST,
      Opt::CPORT(5065),
      OptString.new('USERAGENT',   [ false, "SIP user agent" ]),
      OptString.new('REALM',   [ false, "The login realm to probe at each host", nil]),
      OptString.new('DEREGISTER', [false, 'De-Register the user (AFTER, BEFORE, BOTH, ONLY)']),
      OptString.new('MACADDRESS',   [ false, "MAC Address for Vendor", "000000000000"]),
      OptString.new('VENDOR',   [ true, "Vendor (GENERIC|CISCODEVICE|CISCOGENERIC|MSLYNC)", "GENERIC"]),
      OptString.new('CISCODEVICE',   [ true, "Cisco device type for authentication (585, 7940)", "7940"]),
      OptBool.new('DEBUG',   [ false, "Debug Level", false]),
      OptBool.new('USEREQFROM',   [ false, "FROM will be cloned from USERNAME", true]),
    ], self.class)
  end

  def run_host(dest_addr)
    rports = Rex::Socket.portspec_crack(datastore['RPORTS'])
    rports.each { |rport|
      # Login parameters
      user = datastore['USERNAME']
      password = datastore['PASSWORD']
      realms = datastore['REALM']
      from = datastore['FROM']
      to = datastore['TO']
      login = datastore['LOGIN']
      deregister = datastore['DEREGISTER'].upcase if datastore['DEREGISTER']

      sockinfo={}
      # Protocol parameters
      sockinfo["proto"] = datastore['PROTO'].downcase
      sockinfo["vendor"] = datastore['VENDOR'].downcase
      sockinfo["macaddress"] = datastore['MACADDRESS']

      # Socket parameters
      sockinfo["listen_addr"] = datastore['CHOST']
      sockinfo["listen_port"] = datastore['CPORT']
      sockinfo["dest_addr"] = dest_addr
      sockinfo["dest_port"] = rport

      sipsocket_start(sockinfo)
      sipsocket_connect

      if realms == nil
        rcount = 1
        realm = nil
      else
        rcount = realms.split(" ").length
        realm = ""
      end

      rcount.times do |i|
        if realm != nil
          realm = realms.split(" ")[i]
        end

        context = {
            "method" => "register",
            "user" => user,
            "password" => password
        }

        case deregister
          when "ONLY"
            # Sending de-register
            deregister(login, user, password, realm, from, to, context)
            return
          when /BEFORE|BOTH/
            # Sending de-register
            deregister(login, user, password, realm, from, to, context)
        end

        if vendor == 'mslync'
          results = send_negotiate(
              'realm' => datastore['REALM'],
              'from' => datastore['FROM'],
              'to' => datastore['TO']
          )
          printresults(results) if datastore['DEBUG'] == true
        end

        print_debug("Register request is sending.") if datastore["DEBUG"]

        results = send_register(
            'login' => login,
            'user' => user,
            'password' => password,
            'realm' => realm,
            'from' => from,
            'to' => to
        )

        if rcount > 1
          #printing the realms which receive different responses
          rdata = results["rdata"]
          smsg = rdata['resp_msg'].split(" ")[1,5].join(" ")
          if smsg != "403 Forbidden"
            print_status("#{dest_addr}:#{dest_port} #{realm} => #{smsg}")
          end
        else
          printresults(results, context)
        end


        # Sending de-register
        deregister(login, user, password, realm, from, to, context) if deregister =~ /AFTER|BOTH/
      end

      sipsocket_stop
    }
  end
  def deregister(login,user,password,realm,from,to,context)
    vprint_status("De-register request is sending.")
    # Sending de-register
    results = send_register(
        'login'     => login,
        'user'      => user,
        'password'  => password,
        'realm'     => realm,
        'from'      => from,
        'to'        => to,
        'expire'    => 0
    )
    printresults(results,context)
  end
end

