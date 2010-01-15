##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ftp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'FTP Version Scanner',
			'Version'     => '$Revision$',
			'Description' => 'Detect FTP Version.',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(21),
			], self.class)
	end

	def run_host(target_host)

		begin

		res = connect(true, false)

		print_status("#{rhost}:#{rport} FTP Banner: #{banner.gsub(/[\r\n\x1b]|^220\s+/, "")}")
		report_service(:host => rhost, :port => rport, :name => "ftp", :info => banner.strip)

		disconnect

		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError, ::IOError
		end

	end
end

