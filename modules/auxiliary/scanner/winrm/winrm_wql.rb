##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::WinRM
	include Msf::Auxiliary::Report


	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'WinRM WQL Query Runner',
			'Version'        => '$Revision$',
			'Description'    => %q{
				This module runs WQL queries against remote WinRM Services. 
				Authentication is required. Currently only works with NTLM auth.
				},
			'Author'         => [ 'thelightcosine' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [ true, "The URI of the WinRM service", "/wsman" ]),
				OptString.new('WQL', [ true, "The WQL query to run", "Select Name,Status from Win32_Service" ]),
				OptString.new('USERNAME', [ true, "The username to authenticate as"]),
				OptString.new('PASSWORD', [ true, "The password to authenticate with"])
			], self.class)
	end


	def run_host(ip)
		opts = {
			'uri' => datastore['URI'],
			'data' => winrm_wql_msg(datastore['WQL']),
			'username' => datastore['USERNAME'],
			'password' => datastore['PASSWORD']
		}
		resp,c = send_request_ntlm(opts)
		unless resp.code == 200
			print_error "Got unexpected response from #{ip}: \n #{resp.to_s}"
			return
		end
		resp_tbl = parse_wql_response(resp)
		print_good resp_tbl.to_s
		store_loot("winrm.wql_results", "text/csv", ip, resp_tbl.to_csv, "winrm_wql_results.csv", "WinRM WQL Query Results")
	end



end
