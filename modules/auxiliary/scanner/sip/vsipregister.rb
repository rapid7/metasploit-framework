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
        include Msf::Auxiliary::SIP

	def initialize
		super(
			'Name'        => 'SIP Register Discovery (UDP)',
			'Version'     => '1',
			'Description' => 'Register Discovery Module for SIP Services',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			OptString.new('USERNAME',   [ true, "The login username to probe at each host", "NOUSER"]),
			OptString.new('PASSWORD',   [ true, "The login password to probe at each host", "NOPASSWORD"]),
			OptString.new('REALM',   [ true, "The login realm to probe at each host", "realm.com.tr"]),
			OptString.new('TO',   [ false, "The destination username to probe at each host", "1000"]),
			OptString.new('FROM',   [ false, "The source username to probe at each host", "1000"]),
			OptBool.new('USER_AS_FROM_and_TO', [false, 'Use the Username for From and To fields', true]),
			OptBool.new('LOGIN', [true, 'Login Using Credentials', false]),
			OptBool.new('DEREGISTER', [true, 'DeRegister After Successful Login', false]),
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
	
	def run_host(dest_addr)
		udp_sock = nil

		# Login Parameters
		user = datastore['USERNAME']
		password = datastore['PASSWORD']	
		realm = datastore['REALM']
		if datastore['USER_AS_FROM_and_TO']
			from = user
			to = user
		else
			from = datastore['FROM']
			to = datastore['TO']			
		end
		listen_addr = datastore['CHOST']
		listen_port = datastore['CPORT'].to_i 
		dest_port = datastore['RPORT'].to_i 
		
        	start_sipsrv(listen_port,listen_addr,dest_port,dest_addr)
        
		result,rdata,rdebug,rawdata = send_register(
		    'login'  	=> datastore['LOGIN'],	
		    'user'     	=> user,
		    'password'	=> password,
		    'realm'		=> realm,
		    'from'    	=> from,
		    'to'    	=> to
		)  

        
		if  result =~ /succeed/ and rdata !=nil
			if result =~ /without/      
				user="User=NULL,FROM=#{from},TO=#{to}"               
				password=nil
			end

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
             
			if datastore['DEREGISTER'] ==true
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

		report = "#{rdata['source']}\tResponse: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}\n"
		report << "Credentials : User => #{user} , Password => #{password}\n" if !(result =~ /without/)
		report << "Server \t: #{rdata['server']}\n" if rdata['server']
		report << "User-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
		report << "Realm \t: #{rdata['digest']['realm']}\n" if rdata['digest']
		print_good(report)

		else
			if rdata !=nil
				report = "#{rdata["source"]}\t #{convert_error(result)} : #{rdata['resp_msg']}\n" 
				report << "Server \t: #{rdata['server']}\n" if rdata['server']
				report << "User-Agent \t: #{rdata['agent']}\n"	if rdata['agent']
				report << "Realm \t: #{rdata['digest']['realm']}\n" if rdata['digest']
				print_good(report)	
			else 
				vprint_status("#{dest_addr}")
			end
		end
		
		#Debug
		if datastore['DEBUG'] == true
			rawdata.split("\n").each { |r| print_debug("Response Details: #{r}") }
			rdebug.each { |r| print_debug("Irrelevant Responses :  #{r['resp']} #{r['resp_msg']}") }
		end	

	end
end

