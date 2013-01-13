##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP WebDAV Scanner',
			'Description' => 'Detect webservers with WebDAV enabled',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('PATH', [true, "Path to use", '/']),
			], self.class)
	end

	def run_host(target_host)

		begin
			res = send_request_raw({
				'uri'          => normalize_uri(datastore['PATH']),
				'method'       => 'OPTIONS'
			}, 10)

			if res and res.code == 200
				http_fingerprint({ :response => res })

				tserver = res.headers['Server']
				tdav = res.headers['DAV'].to_s

				if (tdav == '1, 2' or tdav[0,3] == '1,2')
					wdtype = 'WEBDAV'
					if res.headers['X-MSDAVEXT']
						wdtype = 'SHAREPOINT DAV'
					end

					print_good("#{target_host} (#{tserver}) has #{wdtype} ENABLED")

					report_note(
						{
							:host   => target_host,
							:proto  => 'tcp',
							:sname => (ssl ? 'https' : 'http'),
							:port   => rport,
							:type   => wdtype,
							:data   => datastore['PATH']
						})

				else
					print_status("#{target_host} (#{tserver}) WebDAV disabled.")
				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
