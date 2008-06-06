##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'

module Msf

class Auxiliary::Scanner::Ftp::Anonymous < Msf::Auxiliary

	include Exploit::Remote::Ftp
	include Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Anonymous FTP Access Detection',
			'Version'     => '$Revision$',
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

		res = connect_login

		if banner 
			banner.gsub!(/\n|\r/, "")
			print_status("#{target_host}:#{rport} [#{banner}]")
		end

		if res 
			write_check = send_cmd( ['MKD', "test"] , true)

			if write_check 
				send_cmd( ['RMD', "test"] , true)
				print_status("Anonymous read and write access on #{target_host}:#{rport}")
			else
				print_status("Anonymous read access on #{target_host}:#{rport}")
			end
		end

		disconnect
	end
end
end