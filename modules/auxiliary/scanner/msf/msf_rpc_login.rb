##
# msf_rpc_login.rb
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/rpc/v10/client'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' 		=> 'Metasploit RPC interface Login Utility',
			'Description'	=> 'This module simply attempts to '
					'login to a Metasploit RPC interface '
					'using a specific user/pass.',
			'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(55553),
				register_autofilter_ports(3790),
				OptString.new('USERNAME', [true, "A specific username to authenticate as. Default is msf", "msf"]),
				OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
			], self.class)

	end

	def run_host(ip)
		begin
			@rpc = Msf::RPC::Client.new(
			:host => datastore['rhost'],
			:port => datastore['rport'],
			:ssl  => datastore['SSL']
			)
		rescue => e
			vprint_error("#{msg} #{datastore['SSL']} Cannot create RPC client : #{e}")
			return
		end

		each_user_pass do |user, pass|
			do_login(user, pass)
		end
	end

	def do_login(user='msf', pass='msf')
		vprint_status("#{msg} - Trying username:'#{user}' with password:'#{pass}'")
		begin
			res = @rpc.login(user, pass)
			if res
				print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

				report_hash = {
					:host   => datastore['RHOST'],
					:port   => datastore['RPORT'],
					:sname  => 'msf-rpc',
					:user   => user,
					:pass   => pass,
					:active => true,
					:type => 'password'}

				report_auth_info(report_hash)
				@rpc.close
				return :next_user
			end
		rescue  => e
			# vprint_status("#{msg} #{datastore['SSL']} - Bad login #{e}")
			vprint_status("#{msg} #{datastore['SSL']} - Bad login")
			@rpc.close
			return :skip_pass
		end
	end

	def msg
		"#{datastore['RHOST']}:#{datastore['RPORT']} Metasploit RPC -"
	end
end
