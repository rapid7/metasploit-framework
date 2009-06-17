##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'TFTP Brute Forcer',
			'Description' => 'This module is a TFTP filename Brute Forcer.',
			'Author'      => 'antoine',
			'Version'     => '$Revision$',
			'License'     => BSD_LICENSE
		)

		register_options(
			[
				Opt::RPORT(69),
				OptPath.new('DICTIONARY', [ true, 'The list of filenames', File.join(Msf::Config.install_root, "data", "wordlists", "tftp.txt") ])
			], self.class)
	end

	def run_host(ip)
		begin
			udp_sock = Rex::Socket::Udp.create()
			IO.foreach(datastore['DICTIONARY']) do |filename|
				filename.chomp!
				pkt = "\x00\x01" + filename + "\x00" + "netascii" + "\x00"
				udp_sock.sendto(pkt, ip, rport)
				resp = udp_sock.get(1)
				if resp and resp.length >= 2 and resp[0, 2] == "\x00\x03"
					print_status("Found #{filename} on #{ip}")
				end
			end
		rescue
		ensure
			udp_sock.close
		end
	end

end

