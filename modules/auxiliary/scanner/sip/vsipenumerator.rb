##
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'digest/md5'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'SIP User Enumerator (UDP)',
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
            		OptString.new('METHOD',   [ true, "Method for Brute Force (SUBSCRIBE,REGISTER,INVITE)", "SUBSCRIBE"]),
			OptString.new('USERNAME',   [ false, "The login username to probe at each host", "NOUSER"]),
			OptString.new('REALM',   [ true, "The login realm to probe at each host", "realm.com.tr"]),
			OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
			OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
			OptBool.new('USER_AS_FROM_and_TO', [true, 'Try the username as the password for all users', true]),
			Opt::RHOST,
			Opt::RPORT(5060),
			Opt::CHOST,	
			Opt::CPORT(5065),
		], self.class)
		register_advanced_options(
		[
			OptBool.new('DEBUG',   [ false, "Verbose Level", false]),
			OptBool.new('VERBOSE',   [ false, "Verbose Level", false])
		], self.class)
	end
	def run
		udp_sock = nil
	if datastore['METHOD'] =~ /[SUBSCRIBE|REGISTER|INVITE]/
		method = datastore['METHOD']
	else
		print_error("Brute Force METHOD must be defined")
	end

        realm = datastore['REALM']
        from = datastore['FROM']
        to = datastore['TO']		
        listen_addr = datastore['CHOST']
        listen_port = datastore['CPORT'].to_i 
        dest_addr =datastore['RHOST']  
        dest_port = datastore['RPORT'].to_i 
		
        start_sipsrv(listen_port,listen_addr,dest_port,dest_addr)

        if datastore['NUMERIC_USERS'] == true
		exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
		exts.each { |ext|
			ext=ext.to_s
			from=to=ext if datastore['USER_AS_FROM_and_TO']
			do_login(ext,realm,from,to,dest_addr,method)
		}      
        else
		each_user_pass { |user, password|
			from=to=user if datastore['USER_AS_FROM_and_TO']
			do_login(user,realm,from,to,dest_addr,method)
		}
        end
	end
	def do_login(user,realm,from,to,dest_addr,method)
		vprint_status("Trying username:'#{user}'")

		cred={
		    'login'     => false,	
		    'user'      => user,
		    'password'  => nil,
		    'realm'     => realm,
		    'from'      => from,
		    'to'        => to          
		}

		case method
		when "REGISTER"
			result,rdata,rdebug,rawdata = send_register(cred)
			possible = /^200/
		when "SUBSCRIBE"
			result,rdata,rdebug,rawdata = send_subscribe(cred)
			possible = /^40[0-3]/
		#when "OPTIONS"
			#result,rdata,rdebug,rawdata = send_options(cred)
			#possible = /^40[0-3]/
		when "INVITE"
			result,rdata,rdebug,rawdata = send_invite(cred)
			possible = /^40[0-3]/ #/^200/
		end

		if rdata != nil and rdata['resp'] =~ possible
			user=rdata['from'].gsub("@#{realm}","").gsub("\"","") if rdata["from"]

			print_good("User #{user} is Found, Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}")

			#Saving User to DB
			report_auth_info(
				:host	=> dest_addr,
				:port	=> datastore['RPORT'],
				:sname	=> 'sip',
				:user	=> user,
				:proof  => nil,
				:source_type => "user_supplied",
				:active => true
			)
		else	
			vprint_status("User #{user} is not found") 
		end

		#Debug
		if datastore['DEBUG']
			print_debug("#{rdata['source']}\tresponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}") if rdata !=nil
			print_debug("---------------------------------Details--------------------------------")	
			rawdata.split("\n").each { |r| print_debug("#{r}") } if rdata != nil
			print_debug("-------------------------Irrelevant Responses---------------------------")	
			rdebug.each { |r| print_debug("#{r['resp']} #{r['resp_msg']}") } if rdebug
		end
			
    end
end

