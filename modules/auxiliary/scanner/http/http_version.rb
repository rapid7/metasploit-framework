##
# $Id: http_version.rb 14597 2012-01-23 17:26:03Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
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
			'Version'     => '$Revision: 14597 $',
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
			fp = http_fingerprint
			print_status("#{ip}:#{rport} #{fp}") if fp
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end

