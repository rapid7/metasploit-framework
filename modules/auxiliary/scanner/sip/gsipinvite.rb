##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'digest/md5'
require 'sipsocket'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include SIP
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name'        => 'SIP Invite Tester (UDP)',
			'Version'     => '1',
			'Description' => 'Invite Testing Module for SIP Services',
			'Author'      => 'Fatih Ozavci <gamasec.net/fozavci>',
			'License'     => MSF_LICENSE
		)
	
		deregister_options('RHOSTS','USER_AS_PASS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS')

		register_options(
		[
			OptInt.new('NUMERIC_MIN',   [true, 'Starting extension',0]),
			OptInt.new('NUMERIC_MAX',   [true, 'Ending extension', 9999]),
			OptBool.new('NUMERIC_USERS',   [true, 'Numeric Username Bruteforcing', false]),
			OptBool.new('DOS_MODE',   [true, 'Denial of Service Mode', false]),
 			OptString.new('USERNAME',   [ true, "The login username to probe at each host", "NOUSER"]),
			OptString.new('PASSWORD',   [ true, "The login password to probe at each host", "password"]),
			OptString.new('REALM',   [ true, "The login realm to probe at each host", "realm.com.tr"]),
			OptString.new('TO',   [ true, "The destination number to probe at each host", "1000"]),
			OptString.new('FROM',   [ true, "The source number to probe at each host", "1000"]),
			OptString.new('FROMNAME',   [ false, "Custom Name for Invite Spoofing", nil]),
			OptBool.new('TO_as_FROM', [true, 'Try the to field as the from field for all users', false]),
			OptBool.new('LOGIN', [false, 'Login Before Sending Invite', false]),
			OptString.new('LOGINMETHOD', [false, 'Login Method (REGISTER | INVITE)', "INVITE"]),
			Opt::RHOST,
			Opt::RPORT(5060),
			Opt::CHOST,	
			Opt::CPORT(5065)
		], self.class)

		register_advanced_options(
		[
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false])
		], self.class)
	end

	def run
	    udp_sock = nil

	    # Login Parameters
	    user = datastore['USERNAME']
	    password = datastore['PASSWORD']	
	    realm = datastore['REALM']
	    from = datastore['FROM']
	    fromname = datastore['FROMNAME'] || nil
	    to = datastore['TO']
	    login = datastore['LOGIN']
	    logintype = datastore['LOGINTYPE']
	    listen_addr = datastore['CHOST']
	    listen_port = datastore['CPORT'].to_i 
	    dest_addr =datastore['RHOST']  
	    dest_port = datastore['RPORT'].to_i 
			
        sipsocket = SIP::Socket.new(listen_port,listen_addr,dest_port,dest_addr)

        if datastore['DOS_MODE']
		    if datastore['NUMERIC_USERS']
		      tos=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
		    else
		      tos=load_user_vars
		    end
        else
            tos=[to]
        end

        tos.each do |to|
            to.to_s
            from=to if datastore['TO_as_FROM']

            result,rdata,rdebug,rawdata,callopts = sipsocket.send_invite(
                'login'  	    => login,	
                'loginmethod'  	=> datastore['LOGINMETHOD']	,
                'user'     	    => user,
                'password'	    => password,
                'realm' 	    => realm,
                'from'    	    => from,
                'fromname'      => fromname,
                'to'    	    => to,
            )  

            if rdata != nil and rdata['resp'] =~ /^18|^20|^48/ and rawdata.to_s =~ /#{callopts["tag"]}/
                to=rdata['to'].gsub("@#{realm}","") if rdata["to"]	
                print_good("Call: #{from} ==> #{to} is Ringing, Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}")
            else
                print_status("Call: #{from} ==> #{to} is Failed")
                print_status("Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}") if rdata != nil
            end
                      
            #Debug
            if datastore['DEBUG']
                print_debug("---------------------------------Details--------------------------------")	
                rawdata.split("\n").each { |r| print_debug("#{r}") } if rdata != nil
                print_debug("-------------------------Irrelevant Responses---------------------------")	
                rdebug.each { |r| print_debug("#{r['resp']} #{r['resp_msg']}") } if rdebug
            end
        end
    end
end

