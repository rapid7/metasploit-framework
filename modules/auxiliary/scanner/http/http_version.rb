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
			}, 25)

			if (res)
				extra = http_fingerprint(res)
				print_status("#{ip} #{res.headers['Server'] ? ("is running " + res.headers['Server']) : "has no server header"}#{extra}")
				report_service(:host => ip, :port => rport, :name => (ssl ? 'https' : 'http'), :info => "#{res.headers['Server']}#{extra}")
			end

		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	end

	#
	# This is quick example of "extra" fingerprinting we can do
	#
	def http_fingerprint(res)
		return if not res

		extras = []

		case res.code
		when 301,302
			extras << "#{res.code}-#{res.headers['Location']}"
		when 401
			extras << "#{res.code}-#{res.headers['WWW-Authenticate']}"
		when 403
			extras << "#{res.code}-#{res.headers['WWW-Authenticate']||res.message}"
		when 500 .. 599
			extras << "#{res.code}-#{res.message}"
		end

		if (res.headers['X-Powered-By'])
			extras << "Powered by " + res.headers['X-Powered-By']
		end

		if (res.headers['Via'])
			extras << "Via-" + res.headers['Via']
		end

		if (res.headers['X-AspNet-Version'])
			extras << "AspNet-Version-" + res.headers['X-AspNet-Version']
		end

		case res.body
			when nil
				# Nothing
			when /openAboutWindow.*\>DD\-WRT ([^\<]+)\</
				extras << "DD-WRT #{$1.strip}"

			when /ID_ESX_Welcome/
				extras << "VMware ESX Server"

			when /Test Page for.*Fedora/
				extras << "Fedora Default Page"

			when /Placeholder page/
				extras << "Debian Default Page"

			when /Welcome to Windows Small Business Server (\d+)/
				extras << "Windows SBS #{$1}"

			when /Asterisk@Home/
				extras << "Asterisk"

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

