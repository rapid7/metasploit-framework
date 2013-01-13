##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::RealPort
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Digi RealPort Serial Server Version',
			'Description' => 'Detect serial servers that speak the RealPort protocol.',
			'References'  =>
				[
					['URL', 'http://www.digi.com/pdf/fs_realport.pdf'],
					['URL', 'http://www.digi.com/support/productdetail?pid=2229&type=drivers']
				],
			'Author'      =>
				[
					'hdm'
				],
			'License'     => MSF_LICENSE
		)
	end

	def run_host(target_host)
		if realport_connect
			info = "#{@realport_name} ( ports: #{@realport_port_count} )"
			print_status("#{target_host}:#{rport} #{info}")
			report_service(:host => rhost, :port => rport, :name => "realport", :info => info)
		end
		realport_disconnect
	end
end
