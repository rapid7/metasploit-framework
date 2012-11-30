##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'        => 'HTTP Strict Transport Security (HSTS) Detection',
			'Description' => %q{
				Display HTTP Strict Transport Security (HSTS) information about each system.
			},
			'Author'      => 'Matt "hostess" Andreko <mandreko[at]accuvant.com>',
			'License'     => MSF_LICENSE
		))

		register_options([
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true]),
				Opt::RPORT(443)
			])
	end

	def run_host(ip)
		begin
			res = send_request_cgi({
				'uri'    => '/',
				'method' => 'GET',
				}, 25)

			hsts = res.headers['Strict-Transport-Security']

			if res and hsts
				print_good("#{ip}:#{rport} - Strict-Transport-Security:#{hsts}")
				report_note({
					:data => hsts,
					:type => "hsts.data",
					:host => ip,
					:port => rport
				})
			else
				print_error("#{ip}:#{rport} No HSTS found.")
			end

		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
