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

	include Msf::Exploit::Remote::MYSQL
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'			=> 'MySQL Login Utility',
			'Description'	=> 'This module simply queries the MySQL instance for a specific user/pass (default is root with blank).',
			'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision$'
		))

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


	def do_login(user='root', pass='', verbose=false)

		print_status("Trying username:'#{user}' with password:'#{pass}' against #{rhost}:#{rport}") if verbose
		begin
			mysql_login(user, pass)
			print_status("#{rhost}:#{rport} successful logged in as '#{user}' with password '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:proto  => 'mysql',
				:user   => user,
				:pass   => pass,
				:targ_host => rhost,
				:targ_port => rport
			)
			return :next_user
		rescue ::RbMysql::AccessDeniedError
			print_status("#{rhost}:#{rport} failed to login as '#{user}' with password '#{pass}'") if verbose
			return :fail
		rescue ::RbMysql::Error => e
			print_error("#{rhost}:#{rport} failed to login: #{e}")
			return :error
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError
			return :done
		end
	end

	def next_pass(state)
		# Always try empty and the username
		passes = ['', state[:user]]
		state[:idx] ||= 0
		pass = passes[state[:idx]]
		state[:idx] += 1
		return pass
	end

end

