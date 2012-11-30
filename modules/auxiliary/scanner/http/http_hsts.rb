require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'HTTP HSTS Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display HTTP Strict Transport Security (HSTS) information about each system.',
			'Author'      => 'Matt "hostess" Andreko <mandreko@accuvant.com>',
			'License'     => MSF_LICENSE
		)

		register_options([
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true]),
				Opt::RPORT(443)
			])
	end

	def run_host(ip)
		begin
			connect

			res = send_request_cgi({
				'uri'	=>	'/',
				'method'	=>	'GET',
				}, 25)
			return if not res

			if res.headers['Strict-Transport-Security']
				print_good("#{ip}:#{rport} Strict-Transport-Security:#{res.headers['Strict-Transport-Security']}")
			else
				print_error("#{ip}:#{rport} No HSTS found.")
			end

		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end
