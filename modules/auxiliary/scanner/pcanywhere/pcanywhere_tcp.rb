##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'PcAnywhere TCP Service Discovery',
			'Description' => 'Discover active pcAnywhere services through TCP',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(5631)
		], self.class)
	end

	def run_host(ip)
		begin
			connect
			sock.put("\x00\x00\x00\x00")
			res = sock.get_once(-1, 15)
			if not (res and res.index("Please press <Enter>"))
				disconnect
				return
			end

=begin
			sock.put( "\x6f\x06\xfe" )
			res = sock.get_once(-1, 15)

			sock.put("\x6f\x61\xff\x09\x00\x07\x00\x00\x01\xff\x00\x00\x07\x00")
			res = sock.get_once(-1, 15)

			sock.put("\x6f\x62\x00\x02\x00\x00\x00")
			res = sock.get_once(-1, 15)
			print_status(Rex::Text.to_hex_dump(res))
=end

			report_service(:host => rhost, :port => rport, :name => "pcanywhere_data", :info => "")
			print_status("#{rhost}:#{rport} pcAnywhere data service")

		rescue ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNRESET
		rescue ::Exception => e
			print_error("#{rhost}:#{rport} Error: #{e.class} #{e} #{e.backtrace}")
		end
	end
end
