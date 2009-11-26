##
# $Id$
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
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP Version Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display version information about each system',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		
	end

	# Fingerprint a single host
	def run_host(ip)

		begin
			res = send_request_raw({
				'uri'          => '/',
				'method'       => 'GET'
			}, 10)

			if (res and res.headers['Server'])
				extra = http_fingerprint(res)
				print_status("#{ip} is running #{res.headers['Server']}#{extra}")
				
				report_note(
					:host	=> ip,
					:proto	=> 'HTTP',
					:port	=> rport,
					:type	=> 'WEB_SERVER',
					:data	=> "#{res.headers['Server']}#{extra}"
				)
			end

		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	end
	
	#
	# This is quick example of "extra" fingerprinting we can do
	#
	def http_fingerprint(res)
		return if not res
		return if not res.body
		extras = []

		if (res.headers['X-Powered-By'])
			extras << "Powered by " + res.headers['X-Powered-By']
		end
	
		case res.body

			when /Test Page for.*Fedora/
				extras << "Fedora Default Page"

			when /Placeholder page/
				extras << "Debian Default Page"
				
			when /Welcome to Windows Small Business Server (\d+)/
				extras << "Windows SBS #{$1}"

			when /Asterisk@Home/
				extras << "Asterix"
				
			when /swfs\/Shell\.html/
				extras << "BPS-1000"
			
		end
		
		if (extras.length == 0)
			return ''
		end
		
		
		# Format and return
		' ( ' + extras.join(', ') + ' )'
	end

end
