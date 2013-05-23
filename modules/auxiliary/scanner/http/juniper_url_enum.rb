##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Juniper URL Brute',
			'Description' => 'Brute Juniper URLS 0-100 /dana-na/auth/url_X/welcome.cgi. Correct URL should give a 200, wrong will 302 to url_default.',
			'Author'       => ['CG'],
			'License'     => MSF_LICENSE,
			'References' =>
				[
				[ 'URL', 'http://carnal0wnage.attackresearch.com/2013/05/funky-juniper-urls.html' ],
				],
		)
		register_options(
			[
				Opt::RPORT(443),
			], self.class)
end

	def run_host(ip)

		begin

		(0..100).each do |brute|
			res = send_request_raw({
				'version'	=> '1.0',
				'uri'		=>  '/dana-na/auth/url_'+brute.to_s+'/welcome.cgi',
				'method'        => 'GET',
				'headers' =>
				{
				}
			}, 15)

			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{uri}")
			elsif (res.code == 200)
				print_good("#{target_host}:#{rport} Received a HTTP 200 with #{res.headers['Content-Length']} bytes for /dana-na/auth/url_#{brute}/welcome.cgi \n")
					report_note(
						:host	=> ip,
						:proto => 'tcp',
						:ssl => ssl,
						:port	=> rport,
						:ntype => 'juniper url',
						:data	=> "/dana-na/auth/url_#{brute}/welcome.cgi",
						:update => :unique_data
					)

			elsif	(res.code == 302)
				vprint_status("#{target_host}:#{rport} Received #{res.code} --> Redirect to #{target_host}:#{rport} #{res.headers['Location']} for #{brute}")
			else
				vprint_status("#{target_host} response #{res.code}")
			end

		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout =>e
			print_error(e.message)
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
			print_error(e.message)
		end
	end
end

