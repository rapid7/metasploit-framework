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
			'Name'        => 'HTTP Page Scraper',
			'Description' => 'Scrap defined data from a specific web page based on a regular expresion',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('PATH', [ true,  "The test path to the page to analize", '/']),
				OptRegexp.new('REGEX', [ true,  "The regex to use (default regex is a sample to grab page title)", '\<title\>(.*)\<\/title\>'])

			], self.class)

	end

	def run_host(target_host)

		tpath = normalize_uri(datastore['PATH'])
		if tpath[-1,1] != '/'
			tpath += '/'
		end

		begin


			res = send_request_raw({
				'uri'     => tpath,
				'method'  => 'GET',
				'version' => '1.0',
			}, 10)


			if not res
				print_error("[#{target_host}] #{tpath} - No response")
				return
			end

			result = res.body.scan(datastore['REGEX']).flatten.map{ |s| s.strip }.uniq

			result.each do |u|
				print_status("[#{target_host}] #{tpath} [#{u}]")

				report_web_vuln(
					:host	=> target_host,
					:port	=> rport,
					:vhost  => vhost,
					:ssl    => ssl,
					:path	=> tpath,
					:method => 'GET',
					:pname  => "",
					:proof  => u,
					:risk   => 0,
					:confidence   => 100,
					:category     => 'scraper',
					:description  => 'Scraper',
					:name   => 'scraper'
				)

			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
