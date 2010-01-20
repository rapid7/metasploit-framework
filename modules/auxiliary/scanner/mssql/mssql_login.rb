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
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

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
				OptBool.new('VERBOSE', [ true, 'Verbose output', false])
			], self.class)
	end

	def run_host(ip)
		each_user_pass { |user, pass|
			do_login(user, pass, datastore['VERBOSE'])
		}
	end

	def do_login(user='sa', pass='', verbose=false)

		print_status("Trying username:'#{user}' with password:'#{pass}' against #{rhost}:#{rport}") if verbose
		begin
			success = mssql_login(user, pass)

			if (success)
				print_good("#{rhost}:#{rport} - successful login '#{user}' : '#{pass}'")
				report_auth_info(
					:host   => rhost,
					:proto  => 'mssql',
					:user   => user,
					:pass   => pass,
					:targ_host => rhost,
					:targ_port => rport
				)
				return :next_user
 			else
				print_error("#{rhost}:#{rport} failed to login as '#{user}'") if verbose
				return
			end
		rescue ::Rex::ConnectionError
			return :done
		end
	end
end
