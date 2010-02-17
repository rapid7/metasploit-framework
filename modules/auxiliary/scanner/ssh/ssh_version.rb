##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SSH Version Scannner',
			'Version'     => '$Revision$',
			'Description' => 'Detect SSH Version.',
			'References'  =>
				[
					[ 'URL', 'http://en.wikipedia.org/wiki/SecureShell' ],
				],
			'Author'      => [ 'Daniel van Eeden <metasploit[at]myname.nl>' ],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(22),
		], self.class)
	end

	def run_host(target_host)
		connect

		ver = sock.get_once(-1, 5)

		if (ver and ver =~ /SSH/)
			ver,msg = (ver.split(/(\n|\r)/))
			print_status("#{target_host}:#{rport}, SSH server version: #{ver}")
			report_service(:host => rhost, :port => rport, :name => "ssh", :info => ver)

			os_name = nil
			os_flav = nil
			case ver
				when /ubuntu/i
					os_name = 'Linux'
					os_flav = 'Ubuntu'
				when /debian/i
					os_name = 'Linux'
					os_flav = 'Debian'
				when /sun_ssh/i
					os_name = 'Solaris'
				when /vshell|remotelyanywhere|freessh/i
					os_name = 'Windows'
				when /vshell/i
					os_name = 'Windows'
				when /radware/i
					os_name = 'Radware'
				when /dropbear/i
					os_name = 'Linux'
				when /netscreen/i
					os_name = 'NetScreen'
				when /cisco|vpn3/i
					os_name = 'Cisco'
				when /mpSSH/
					os_name = 'HP iLO'
					os_flav = 'HP Integrated Lights-Out Controller'
			end

			if(os_name || os_flav)
				info = {:host => target_host}
				info[:os_flavor] = os_flav if os_flav
				info[:os_name]   = os_name if os_name
				report_host(info)
			end
		else
			print_status("#{target_host}:#{rport}, SSH server version detection failed!")
		end

		disconnect
	end
end

