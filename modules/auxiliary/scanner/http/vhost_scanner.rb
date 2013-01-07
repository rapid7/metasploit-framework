##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'

#
# May I reuse some methods?
#
require 'cgi'



	class Metasploit3 < Msf::Auxiliary

		include Msf::Exploit::Remote::HttpClient
		include Msf::Auxiliary::WmapScanServer
		include Msf::Auxiliary::Scanner
		include Msf::Auxiliary::Report


		def initialize(info = {})
			super(update_info(info,
				'Name'   		=> 'HTTP Virtual Host Brute Force Scanner',
				'Description'	=> %q{
					This module tries to identify unique virtual hosts
				hosted by the target web server.

					},
				'Author' 		=> [ 'et [at] cyberspace.org' ],
				'License'		=> BSD_LICENSE))

			register_options(
			[
				OptString.new('PATH', [ true,  "The PATH to use while testing", '/']),
				OptString.new('QUERY', [ false,  "HTTP URI Query", '']),
				OptString.new('DOMAIN', [ true,  "Domain name", '']),
				OptString.new('HEADERS', [ false,  "HTTP Headers", '']),
				OptPath.new('SUBDOM_LIST', [false, "Path to text file with subdomains"]),
			], self.class)

		end

		def run_host(ip)
			if datastore['SUBDOM_LIST'] and ::File.file?(datastore['SUBDOM_LIST'])
				valstr = IO.readlines(datastore['SUBDOM_LIST']).map {
					|e| e.gsub(".#{datastore['DOMAIN']}", "").chomp
				}
			else
				valstr = [
					"admin",
					"services",
					"webmail",
					"console",
					"apps",
					"mail",
					"intranet",
					"intra",
					"spool",
					"corporate",
					"www",
					"web"
				]
			end

			datastore['QUERY'] ? tquery = queryparse(datastore['QUERY']): nil
			datastore['HEADERS'] ? thead = headersparse(datastore['HEADERS']) : nil

			noexistsres = nil
			resparr = []

			2.times do |n|

				randhost = Rex::Text.rand_text_alpha(5)+"."+datastore['DOMAIN']


				begin
					noexistsres = send_request_cgi({
						'uri'  		=>  normalize_uri(datastore['PATH']),
						'vars_get' 	=>  tquery,
						'headers' 	=>  thead,
						'vhost'		=>  randhost,
						'method'   	=> 'GET',
						'ctype'		=> 'text/plain'
					}, 20)

					print_status("[#{ip}] Sending request with random domain #{randhost} ")

					if noexistsres
						resparr[n] = noexistsres.body
					end

				rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				rescue ::Timeout::Error, ::Errno::EPIPE
				end
			end

			if resparr[0] != resparr[1]
				print_error("[#{ip}] Unable to identify error response")
				return
			end

			vprint_status("Running with #{valstr.length} sudomains")
			valstr.each do |astr|
				thost = astr+"."+datastore['DOMAIN']

				begin
					res = send_request_cgi({
						'uri'  		=>  normalize_uri(datastore['PATH']),
						'vars_get' 	=>  tquery,
						'headers' 	=>  thead,
						'vhost'		=>  thost,
						'method'   	=> 'GET',
						'ctype'		=> 'text/plain'
					}, 20)


					if res and noexistsres

						if res.body !=  noexistsres.body
							print_status("[#{ip}] Vhost found  #{thost} ")

							report_note(
								:host	=> ip,
								:proto => 'tcp',
								:sname => (ssl ? 'https' : 'http'),
								:port	=> rport,
								:type	=> 'VHOST',
								:data	=> thost,
								:update => :unique_data
							)

						else
							vprint_status("NOT Found #{thost}")
						end
					else
						print_status("[#{ip}] NO Response")
					end

				rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				rescue ::Timeout::Error, ::Errno::EPIPE
				end

			end

		end
	end
