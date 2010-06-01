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

	include Msf::Exploit::Remote::Ftp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	def proto
		'ftp'
	end

	def initialize
		super(
			'Name'        => 'FTP Authentication Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module will test FTP logins on a range of machines and
				report successful logins.  If you have loaded a database plugin
				and connected to a database this module will record successful
				logins and hosts so you can track your access.
			},
			'Author'      => 'todb',
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(21)
			], self.class)

		deregister_options('FTPUSER','FTPPASS') # Can use these, but should use 'username' and 'password'

	end

	def run_host(ip)
		print_status("#{ip}:#{rport} - Starting FTP login sweep")
		begin
			check_banner
			each_user_pass { |user, pass|
				next if user.nil? || user.empty?
				do_login(user,pass)  
			}
		rescue ::Rex::ConnectionError, ::EOFError, ::IOError
			return
		end
	end

	def check_banner
		@ftp_sock = connect(true, false)
		if self.banner
			banner_sanitized = self.banner.to_s.gsub(/[\x00-\x19\x7f-\xff]/) { |s| "\\x%02x" % s[0].ord}
			print_status("#{rhost}:#{rport} - FTP Banner: '#{banner_sanitized}'")
			report_service(:host => rhost, :port => rport, :name => "ftp", :info => banner_sanitized)
		end
	end

	def do_login(user=nil,pass=nil)
		if !@ftp_sock || @ftp_sock.closed? 
			@ftp_sock = connect(true,false)
		end
		vprint_status("#{rhost}:#{rport} - Attempting FTP login for '#{user}':'#{pass}'") 
		if(self.banner)
			user_res = send_user(user, @ftp_sock)
			if user_res !~ /^(331|2)/
				vprint_error("#{rhost}:#{rport} - The server rejected username: '#{user}'")
				send_quit
				disconnect 
				return :next_user
			end
			pass_res = send_pass(pass, @ftp_sock)
			if pass_res =~ /^2/
				print_good("#{rhost}:#{rport} - Successful FTP login for '#{user}':'#{pass}'")
				access = test_ftp_access(user)
				report_ftp_creds(user,pass,access)
				send_quit
				disconnect
				return :next_user
			else
				vprint_status("#{rhost}:#{rport} - Failed FTP login for '#{user}':'#{pass}'") 
				# TODO: Shouldn't have to disconnect every time, but sadly, some FTP servers
				# behave erratically in the face of failed logins -- they will sometimes drop
				# in the middle of the user/pass sequence, which means we need to reconnect
				# and retry that user/pass combination. For now, we always
				# disconnect after a failed attempt. In many cases, 3 retries per session is
				# safe, but it's difficult to pin down the corner cases. IOW, set the retry 
				# behavior as a user option, so we can better handle FTP servers that employ
				# greylisting.
				send_quit
				disconnect 
				return :fail
			end
		else
			print_error("#{rhost}:#{rport} - The server did not provide a banner; aborting (FTPTimeout is currently set to #{datastore['FTPTimeout']})")
			disconnect
			return :abort
		end
	end

	def test_ftp_access(user)
		dir = Rex::Text.rand_text_alpha(8)
		write_check = send_cmd(['MKD', dir], true)
		if write_check and write_check =~ /^2/
			send_cmd(['RMD',dir], true)
			print_status("#{rhost}:#{rport} - User '#{user}' has READ/WRITE access")
			return :write
		else
			print_status("#{rhost}:#{rport} - User '#{user}' has READ access")
			return :read
		end
	end
	
	def report_ftp_creds(user,pass,access)
		report_auth_info(
			:host => rhost,
			:proto => 'ftp',
			:user => user,
			:pass => pass,
			:access => access,
			:target_host => rhost,
			:target_port => rport,
			:critical => true
		)
	end

end

