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
			'Name'           => 'WinRM Command Runner',
			'Version'        => '$Revision$',
			'Description'    => %q{
				This module runs arbitrary Windows commands using the WinRM Service
				},
			'Author'         => [ 'thelightcosine' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [ true, "The URI of the WinRM service", "/wsman" ]),
				OptString.new('CMD', [ true, "The WQL query to run", "ipconfig /all" ]),
				OptString.new('USERNAME', [ true, "The username to authenticate as"]),
				OptString.new('PASSWORD', [ true, "The password to authenticate with"]),
				OptBool.new('SAVE_OUTPUT', [true, "Store output as loot", false])
			], self.class)
	end


	def run_host(ip)
		resp,c = send_request_ntlm(winrm_open_shell_msg)
		unless resp.code == 200
			print_error "Got unexpected response from #{ip}: \n #{resp.to_s}"
			return
		end
		shell_id = winrm_get_shell_id(resp)
		resp,c = send_request_ntlm(winrm_cmd_msg(datastore['CMD'], shell_id))
		cmd_id = winrm_get_cmd_id(resp)
		resp,c = send_request_ntlm(winrm_cmd_recv_msg(shell_id,cmd_id))
		streams = winrm_get_cmd_streams(resp)
		resp,c = send_request_ntlm(winrm_terminate_cmd_msg(shell_id,cmd_id))
		resp,c = send_request_ntlm(winrm_delete_shell_msg(shell_id))
		print_error streams['stderr'] unless streams['stderr'] == ''
		print_good streams['stdout']
		if datastore['SAVE_OUTPUT']
			store_loot("winrm.cmd_results", "text/plain", ip, streams['stdout'], "winrm_cmd_results.txt", "WinRM CMD Results")
		end
	end



end
