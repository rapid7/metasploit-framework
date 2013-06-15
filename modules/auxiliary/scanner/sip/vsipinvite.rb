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
			'Name'        => 'SIP Invite Tester (UDP)',
			'Version'     => '1',
			'Description' => 'Invite Testing Module for SIP Services',
			'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
			'License'     => MSF_LICENSE
		)
	
		deregister_options('RHOSTS','USER_AS_PASS','THREADS','USERPASS_FILE','PASS_FILE','PASSWORD','BLANK_PASSWORDS', 'BRUTEFORCE_SPEED','STOP_ON_SUCCESS' )

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
			OptBool.new('LOGIN', [false, 'Login Before Sending Invite', false]),
			Opt::RHOST,
			Opt::RPORT(5060),
			Opt::CHOST,	
			Opt::CPORT(5065)
		], self.class)

		register_advanced_options(
		[
			OptString.new('LOGINMETHOD', [false, 'Login Method (REGISTER | INVITE)', "INVITE"]),
			OptBool.new('TO_as_FROM', [true, 'Try the to field as the from field for all users', false]),
			OptString.new('CUSTOMHEADER', [false, 'Custom Headers for Requests', nil]),
			OptString.new('P-Asserted-Identity', [false, 'Proxy Identity Field. Sample: <sip:100@RHOST:RPORT>', nil]),
			OptString.new('P-Charging-Vector', [false, 'Proxy Charging Field. Sample: icid-value=msanicid;msan-id=msan123;msan-pro=1 ', nil]),
			OptString.new('Record-Route', [false, 'Proxy Record-Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
			OptString.new('Route', [false, 'Proxy Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
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

		#Building Custom Headers
		customheader = ""
		customheader << datastore['CUSTOMHEADER']+"\r\n" if datastore['CUSTOMHEADER'] != nil
		customheader << "P-Asserted-Identity: "+datastore['P-Asserted-Identity']+"\r\n" if datastore['P-Asserted-Identity'] != nil
		customheader << "P-Charging-Vector: "+datastore['P-Charging-Vector']+"\r\n" if datastore['P-Charging-Vector'] != nil
		customheader << "Record-Route: "+datastore['Record-Route']+"\r\n" if datastore['Record-Route'] != nil
		customheader << "Route: "+datastore['Route']+"\r\n" if datastore['Route'] != nil	


		start_sipsrv(listen_port,listen_addr,dest_port,dest_addr)

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

		result,rdata,rdebug,rawdata,callopts = send_invite(
			'login' 	=> login,	
			'loginmethod'  	=> datastore['LOGINMETHOD'],
			'user'  	=> user,
			'password'	=> password,
			'realm' 	=> realm,
			'from'  	=> from,
			'fromname'  	=> fromname,
			'to'  		=> to,
			'customheader'	=> customheader,
		)  


		if rdata != nil and rdata['resp'] =~ /^18|^20|^48/ and rawdata.to_s =~ /#{callopts["tag"]}/
			to=rdata['to'].gsub("@#{realm}","") if rdata["to"]	
			print_good("Call: #{from} ==> #{to} is Ringing, Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}")
		else
			vprint_status("Call: #{from} ==> #{to} is Failed")
			vprint_status("Server Response: #{rdata['resp_msg'].split(" ")[1,5].join(" ")}") if rdata != nil
		end

		if customheader
			vprint_status("Custom Headers")
			vprint_status(customheader)
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

