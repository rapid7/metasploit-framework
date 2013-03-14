##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'HTTP Version Detection',
			'Description' => 'Display version information about each system',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_wmap_options({
				'OrderID' => 0,
				'Require' => {},
			})
	end

	# Fingerprint a single host
	def run_host(ip)
		begin
			connect

			res = send_request_raw({'uri' => '/', 'method' => 'GET' })
			return if not res

			fp = http_fingerprint(:response => res)
			print_status("#{ip}:#{rport} #{fp}") if fp
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
