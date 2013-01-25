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
			'License'        => MSF_LICENSE,
		))

		register_options(
			[
				OptInt.new('RPORT', [ true, 'Remote port running RDP', '3389' ])
			], self.class)
	end

	def checkRdp(packet)
		# code to check if RDP is open or not
		vprint_status("#{peer} - Verifying RDP Protocol")
		begin
			# send connection
			sock.put(packet)
			# read packet to see if its rdp
			res = sock.recv(1024)

			if res.unpack("H*").join == "0300000b06d00000123400"
				return true
			else
				return false
			end
		rescue
			print_error("could not connect to RHOST")
			return false
		end
	end

	def connectionRequest()
		packet = '' +
			"\x03\x00" +    # TPKT Header version 03, reserved 0
			"\x00\x0b" +    # Length
			"\x06" +        # X.224 Data TPDU length
			"\xe0" +        # X.224 Type (Connection request)
			"\x00\x00" +    # dst reference
			"\x00\x00" +    # src reference
			"\x00"          # class and options
		return packet
	end

	def report_goods
		report_vuln(
			:host         => rhost,
			:port         => rport,
			:proto        => 'tcp',
			:name         => 'The MS12-020 Checker',
			:vuln         => 'Confirmaiton that this host is vulnerable to MS12-020',
			:refs         => self.references,
			:exploited_at => Time.now.utc
		)
	end

	def connectInitial()
		packet = '' +
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
		return packet
	end

	def userRequest()
		packet = '' +
			"\x03\x00" +         # header
			"\x00\x08" +         # length
			"\x02\xf0\x80" +     # X.224 Data TPDU (2 bytes: 0xf0 = Data TPDU, 0x80 = EOT, end of transmission)
			"\x28"               # PER encoded PDU contents
		return packet
	end

	def channelRequestOne
		packet = '' +
			"\x03\x00\x00\x0c" +
			"\x02\xf0\x80\x38" +
			"\x00\x01\x03\xeb"
		return packet
	end

	def channelRequestTwo
		packet = '' +
			"\x03\x00\x00\x0c" +
			"\x02\xf0\x80\x38" +
			"\x00\x02\x03\xeb"
		return packet
	end

	def peer
		return "#{rhost}:#{rport}"
	end

	def run_host(ip)
		begin
			# open connection
			connect()
		rescue
			return
		end

		# check if rdp is open
		if checkRdp(connectionRequest)

			# send connectInitial
			sock.put(connectInitial)
			# send userRequest
			sock.put(userRequest)
			user1_res = sock.recv(1024)
			# send 2nd userRequest
			sock.put(userRequest)
			user2_res = sock.recv(1024)
			# send channel request one
			sock.put(channelRequestOne)
			channel_one_res = sock.recv(1024)
			if channel_one_res.unpack("H*").to_s[16..19] == '3e00'
				# vulnerable
				print_good("#{peer} - Vulnerable to MS12-020")
				report_goods

				# send ChannelRequestTwo - prevent bsod
				sock.put(channelRequestTwo)

				# report to the database
			else
				vprint_error("#{peer} - Not Vulnerable")
			end

		end
		# close connection
		disconnect()
	end

end

