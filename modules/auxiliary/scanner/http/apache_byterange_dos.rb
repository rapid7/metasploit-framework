##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'



class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'   		=> 'Apache HTTP Server Byte Range DoS',
			'Description'	=> %q{
				This module checks if the Apache Server is vulnerable to a Byte Range Denial of Service Attack.
			},
			'Author' 		=> [ 'Markus Neis markus.neis[at]oneconsult.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '$Revision: 15394 $')
			)

		register_options(
			[
				OptString.new('PATH', [ true,  "The path to test", '/'])
			], self.class)

	end

	def run_host(ip)
		check_for_dos()
	end

	def check_for_dos()
		path = datastore['PATH']
		begin
			res = send_request_cgi({
					'uri'  		=>  path,
					'method'   	=> 'HEAD',
					'headers'	=> { "HOST" => "Localhost", "Range" => "bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10"}
					})
		
		if (res and res.code == 206)
				print_status("Response was #{res.code}")
                                print_status("Found Byte-Range Header DOS for #{rhost} at #{path}")

		
		report_note(
                           :host   => rhost,
                           :port   => rport,
                           :data   => "Apache Byte-Range DOS at #{path}"
                           )

		else
			print_error("#{rhost} at path: #{path} is not vulnerable")		

		end 


		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end


	end

end
