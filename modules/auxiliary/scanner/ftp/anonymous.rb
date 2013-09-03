##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ftp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Anonymous FTP Access Detection',
			'Description' => 'Detect anonymous (read/write) FTP server access.',
			'References'  =>
				[
					['URL', 'http://en.wikipedia.org/wiki/File_Transfer_Protocol#Anonymous_FTP'],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(21),
			], self.class)
	end

	def run_host(target_host)

		begin

		res = connect_login(true, false)

		banner.strip! if banner

		dir = Rex::Text.rand_text_alpha(8)
		if res
			write_check = send_cmd( ['MKD', dir] , true)

			if (write_check and write_check =~ /^2/)
				send_cmd( ['RMD', dir] , true)

				print_status("#{target_host}:#{rport} Anonymous READ/WRITE (#{banner})")
				access_type = "rw"
			else
				print_status("#{target_host}:#{rport} Anonymous READ (#{banner})")
				access_type = "ro"
			end
			report_auth_info(
				:host   => target_host,
				:port   => rport,
				:sname  => 'ftp',
				:user   => datastore['FTPUSER'],
				:pass   => datastore['FTPPASS'],
				:type  => "password_#{access_type}",
				:active => true
			)
		end

		disconnect

		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError, ::IOError
		end

	end
end
