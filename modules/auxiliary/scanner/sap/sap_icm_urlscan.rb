##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'            => 'SAP URL Scanner',
			'Description'   => %q{
				This module scans for commonly found SAP Internet Communication Manager URLs
				and outputs return codes for the user.
			},
			'Author'          => [ 'Chris John Riley' ],
			'References'      =>
				[
					[ 'CVE', '2010-0738' ] # VERB auth bypass
				],
			'License'         => MSF_LICENSE
			))

		register_options(
			[
				OptString.new('VERB',    [true, "Verb for auth bypass testing", "HEAD"]),
				OptString.new('URLFILE', [true, "SAP ICM Paths File", "sap_icm_paths.txt"])
			], self.class)
	end

	# Base Structure of module borrowed from jboss_vulnscan
	def run_host(ip)
		# If URLFILE is set empty, obviously the user made a silly mistake
		if datastore['URLFILE'].empty?
			print_error("Please specify a URLFILE")
			return
		end

		# Initialize the actual URLFILE path
		if datastore['URLFILE'] == "sap_icm_paths.txt"
			url_file = "#{Msf::Config.data_directory}/wordlists/#{datastore['URLFILE']}"
		else
			# Not the default sap_icm_paths file
			url_file = datastore['URLFILE']
		end

		# If URLFILE path doesn't exist, no point to continue the rest of the script
		if not File.exists?(url_file)
			print_error("Required URL list #{url_file} was not found")
			return
		end

		res = send_request_cgi(
			{
				'uri'       => "/" + Rex::Text.rand_text_alpha(12),
				'method'    => 'GET',
				'ctype'     => 'text/plain',
			}, 20)

		if res
			print_status("Note: Please note these URLs may or may not be of interest based on server configuration")
			@info = []
			if not res.headers['Server'].nil?
				@info << res.headers['Server']
				print_status("#{rhost}:#{rport} Server responded with the following Server Header: #{@info[0]}")
			else
				print_status("#{rhost}:#{rport} Server responded with a blank or missing Server Header")
			end

			if (res.body and /class="note">(.*)code:(.*)</i.match(res.body) )
				print_error("#{rhost}:#{rport} SAP ICM error message: #{$2}")
			end

			# Load URLs
			urls_to_check = []
			File.open(url_file) do |f|
				f.each_line do |line|
					urls_to_check.push line
				end
			end

			print_status("#{rhost}:#{rport} Beginning URL check")
			urls_to_check.each do |url|
				check_url(url.strip)
			end
		else
			print_error("#{rhost}:#{rport} No response received")
		end

	end

	def check_url(url)
		res = send_request_cgi({
			'uri'       => url,
			'method'    => 'GET',
			'ctype'     => 'text/plain',
		}, 20)

		if (res)
			if not @info.include?(res.headers['Server']) and not res.headers['Server'].nil?
				print_good("New server header seen [#{res.headers['Server']}]")
				@info << res.headers['Server'] #Add To seen server headers
			end

			case
			when res.code == 200
				print_good("#{rhost}:#{rport} #{url} - does not require authentication (200)")
			when res.code == 403
				print_good("#{rhost}:#{rport} #{url} - restricted (403)")
			when res.code == 401
				print_good("#{rhost}:#{rport} #{url} - requires authentication (401): #{res.headers['WWW-Authenticate']}")
				# Attempt verb tampering bypass
				bypass_auth(url)
			when res.code == 404
				# Do not return by default, only display in verbose mode
				vprint_status("#{rhost}:#{rport} #{url.strip} - not found (404)")
			when res.code == 500
				print_good("#{rhost}:#{rport} #{url} - produced a server error (500)")
			when res.code == 301, res.code == 302
				print_good("#{rhost}:#{rport} #{url} - redirected (#{res.code}) to #{res.headers['Location']} (not following)")
			else
				vprint_status("#{rhost}:#{rport} - unhandle response code #{res.code}")
			end

		else
			print_status("#{rhost}:#{rport} #{url} - not found (No Repsonse code Received)")
		end
	end

	def bypass_auth(url)
		print_status("#{rhost}:#{rport} Check for verb tampering (#{datastore['VERB']})")

		res = send_request_raw({
			'uri'       => url,
			'method'    => datastore['VERB'],
			'version'   => '1.0' # 1.1 makes the head request wait on timeout for some reason
		}, 20)

		if (res and res.code == 200)
			print_good("#{rhost}:#{rport} Got authentication bypass via HTTP verb tampering")
		else
			print_status("#{rhost}:#{rport} Could not get authentication bypass via HTTP verb tampering")
		end
	end
end
