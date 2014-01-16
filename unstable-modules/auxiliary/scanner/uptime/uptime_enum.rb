##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
# http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'			=> 'uptimesoftware.com Service Enumerator',
			#'Description' => 'Checks to see if the following scripts are available and unprotected on the machine running uptimesoftware client',
			'Description' => %q{This module can be used to identify system information on hosts running uptimesoftware.com client.
													If available a poorly configured host can identify system name, domain name, os version, number of cpu, if client is vmware, vmuuid,
													disks on system and their usage stats, the last user to log in to the system, processor stats, network interface statistics,
													running processes, who is currently logged in to the system, etc.},
			'Author'		=> 'RogueBit',
			'License'		=> MSF_LICENSE
	 	)
		register_options([
		Opt::RPORT(9998)], self.class)
	end

	def run_host(ip)
		begin
			print_status "#{rhost}:#{rport} - Sending sysinfo request."
			uptime_put("sysinfo")
			print_status "#{rhost}:#{rport} - Sending df-k request."
			uptime_put("df-k")
			print_status "#{rhost}:#{rport} - Sending lastuser request."
			uptime_put("lastuser")
			print_status "#{rhost}:#{rport} - Sending mpstat request."
			uptime_put("mpstat")
			print_status "#{rhost}:#{rport} - Sending netstat request."
			uptime_put("netstat")
			print_status "#{rhost}:#{rport} - Sending physdrv request."
			uptime_put("physdrv")
			print_status "#{rhost}:#{rport} - Sending psinfo request."
			uptime_put("psinfo")
			print_status "#{rhost}:#{rport} - Sending tcpinfo request."
			uptime_put("tcpinfo")
			print_status "#{rhost}:#{rport} - Sending whoin request."
			uptime_put("whoin")

			rescue ::Rex::ConnectionError
			rescue ::Exception => e
				print_error("#{e} #{e.backtrace}")
		end
		report_service(:host => rhost, :port => rport, :name => "uptime")
	end

	def uptime_put(marap)
		connect
		sock.put(marap)
			data = sock.recv(1024)
			print_status("Received: \r\n#{data}")
		disconnect
	end

end

