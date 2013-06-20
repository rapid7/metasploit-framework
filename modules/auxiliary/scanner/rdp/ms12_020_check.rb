##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'MS12-020 Microsoft Remote Desktop Checker',
			'Description'    => %q{
				This module checks a range of hosts for the MS12-020 vulnerability.
				This does not cause a DoS on the target.
			},
			'References'     =>
				[
					[ 'CVE', '2012-0002' ],
					[ 'MSB', 'MS12-020' ],
					[ 'URL', 'http://technet.microsoft.com/en-us/security/bulletin/ms12-020' ],
					[ 'EDB', '18606' ],
					[ 'URL', 'https://svn.nmap.org/nmap/scripts/rdp-vuln-ms12-020.nse' ]
				],
			'Author'         =>
				[
					'Royce Davis @R3dy_ <rdavis[at]accuvant.com>',
					'Brandon McCann @zeknox <bmccann[at]accuvant.com>'
				],
			'License'        => MSF_LICENSE
		))

		register_options(
			[
				OptInt.new('RPORT', [ true, 'Remote port running RDP', '3389' ])
			], self.class)
	end

	def check_rdp
		# code to check if RDP is open or not
		vprint_status("#{peer} Verifying RDP protocol...")

		# send connection
		sock.put(connection_request)

		# read packet to see if its rdp
		res = sock.get_once(-1, 5)

		# return true if this matches our vulnerable response
		( res and res.match("\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00") )
	end

	def report_goods
		report_vuln(
			:host         => rhost,
			:port         => rport,
			:proto        => 'tcp',
			:name         => self.name,
			:info         => 'Response indicates a missing patch',
			:refs         => self.references
		)
	end

	def connection_request
		"\x03\x00" +    # TPKT Header version 03, reserved 0
		"\x00\x0b" +    # Length
		"\x06" +        # X.224 Data TPDU length
		"\xe0" +        # X.224 Type (Connection request)
		"\x00\x00" +    # dst reference
		"\x00\x00" +    # src reference
		"\x00"          # class and options
	end

	def connect_initial
		"\x03\x00\x00\x65" + # TPKT Header
		"\x02\xf0\x80" +     # Data TPDU, EOT
		"\x7f\x65\x5b" +     # Connect-Initial
		"\x04\x01\x01" +     # callingDomainSelector
		"\x04\x01\x01" +     # callingDomainSelector
		"\x01\x01\xff" +     # upwardFlag
		"\x30\x19" +         # targetParams + size
		"\x02\x01\x22" +     # maxChannelIds
		"\x02\x01\x20" +     # maxUserIds
		"\x02\x01\x00" +     # maxTokenIds
		"\x02\x01\x01" +     # numPriorities
		"\x02\x01\x00" +     # minThroughput
		"\x02\x01\x01" +     # maxHeight
		"\x02\x02\xff\xff" + # maxMCSPDUSize
		"\x02\x01\x02" +     # protocolVersion
		"\x30\x18" +         # minParams + size
		"\x02\x01\x01" +     # maxChannelIds
		"\x02\x01\x01" +     # maxUserIds
		"\x02\x01\x01" +     # maxTokenIds
		"\x02\x01\x01" +     # numPriorities
		"\x02\x01\x00" +     # minThroughput
		"\x02\x01\x01" +     # maxHeight
		"\x02\x01\xff" +     # maxMCSPDUSize
		"\x02\x01\x02" +     # protocolVersion
		"\x30\x19" +         # maxParams + size
		"\x02\x01\xff" +     # maxChannelIds
		"\x02\x01\xff" +     # maxUserIds
		"\x02\x01\xff" +     # maxTokenIds
		"\x02\x01\x01" +     # numPriorities
		"\x02\x01\x00" +     # minThroughput
		"\x02\x01\x01" +     # maxHeight
		"\x02\x02\xff\xff" + # maxMCSPDUSize
		"\x02\x01\x02" +     # protocolVersion
		"\x04\x00"           # userData
	end

	def user_request
		"\x03\x00" +         # header
		"\x00\x08" +         # length
		"\x02\xf0\x80" +     # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
		"\x28"               # PER encoded PDU contents
	end

	def channel_request
		"\x03\x00\x00\x0c" +
		"\x02\xf0\x80\x38"
	end

	def peer
		"#{rhost}:#{rport}"
	end

	def run_host(ip)

		connect

		# check if rdp is open
		if not check_rdp
			vprint_status "#{peer} Could not connect to RDP."
			disconnect
			return
		end

		# send connectInitial
		sock.put(connect_initial)

		# send userRequest
		sock.put(user_request)
		res = sock.get_once(-1, 5)
		user1 = res[9,2].unpack("n").first
		chan1 = user1 + 1001

		# send 2nd userRequest
		sock.put(user_request)
		res = sock.get_once(-1, 5)

		user2 = res[9,2].unpack("n").first
		chan2 = user2 + 1001

		# send channel request one
		sock.put(channel_request << [user1, chan2].pack("nn"))
		res = sock.get_once(-1, 5)

		if res and res[7,2] == "\x3e\x00"
			# send ChannelRequestTwo - prevent BSoD
			sock.put(channel_request << [user2, chan2].pack("nn"))

			print_good("#{peer} Vulnerable to MS12-020")
			report_goods
		else
			vprint_status("#{peer} Not Vulnerable")
		end

		disconnect()
	end

end
