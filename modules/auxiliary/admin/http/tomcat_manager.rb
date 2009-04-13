##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Tomcat Application Manager default access',
			'Version'     => '$Revision$',
			'Description' => 'Detect Tomcat Web Application Manager default access.',
			'References'  =>
				[
					['URL', 'http://tomcat.apache.org/'],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		)
	
		register_options(
			[
				Opt::RPORT(8180),
				OptString.new('TOMCAT_USER', [ false, 'The username to authenticate as', '']),
				OptString.new('TOMCAT_PASS', [ false, 'The password for the specified username', '']),
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
			], self.class)
	end

	def run_host(ip)

		begin 
			res = send_request_raw({
				'method'  => 'GET',
				'uri'     => '/',
			}, 25)

			if (res and res.code == 200)

				user = datastore['TOMCAT_USER'].to_s
				pass = datastore['TOMCAT_PASS'].to_s

				if user.length == 0
					default_usernames = ['admin','manager','role1','root','tomcat']
				else
					default_usernames = [user]
				end

				if pass.length == 0
					default_passwords = ['admin','manager','role1','root','tomcat']
				else
					default_passwords = [pass]
				end

				default_usernames.each do |username|
					default_passwords.each do |password|

						user_pass = Rex::Text.encode_base64("#{username}" + ":" + "#{password}") 

						begin

							res = send_request_cgi({
								'uri'     => "/manager/html",
								'method'  => 'GET',
								'headers' =>
								{
									'Authorization' => "Basic #{user_pass}",
								}
							}, 25)

							if (res.code == 200)
								print_status("http://#{target_host}:#{rport}/manager/html [#{res.headers['Server']}] [Tomcat Application Manager] [#{username}/#{password}]")
							end
			
							rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
							rescue ::Timeout::Error, ::Errno::EPIPE
						end
					end
				end
			end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
