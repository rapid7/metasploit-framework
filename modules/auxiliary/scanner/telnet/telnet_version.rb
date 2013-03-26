##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Telnet
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Telnet Service Banner Detection',
			'Description' => 'Detect telnet services',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		register_options(
		[
			Opt::RPORT(23),
			OptInt.new('TIMEOUT', [true, 'Timeout for the Telnet probe', 30])
		], self.class)
	end

	def to
		return 30 if datastore['TIMEOUT'].to_i.zero?
		datastore['TIMEOUT'].to_i
	end

	def run_host(ip)
		begin
			::Timeout.timeout(to) do
				res = connect
				# This makes db_services look a lot nicer.
				banner_santized = Rex::Text.to_hex_ascii(banner.to_s)
				print_status("#{ip}:#{rport} TELNET #{banner_santized}")
				report_service(:host => rhost, :port => rport, :name => "telnet", :info => banner_santized)
			end
		rescue ::Rex::ConnectionError
		rescue Timeout::Error
			print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds. Skipping.")
		rescue ::Exception => e
			print_error("#{e} #{e.backtrace}")
		end
	end
end
