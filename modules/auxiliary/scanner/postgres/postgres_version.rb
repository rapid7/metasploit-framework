##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Postgres
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	# Creates an instance of this module.
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'PostgreSQL Version Probe',
			'Description'    => %q{
				Enumerates the verion of PostgreSQL servers.
			},
			'Author'         => [ 'todb' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://www.postgresql.org' ]
				]
		))

		register_options([ ], self.class) # None needed.

		deregister_options('SQL', 'RETURN_ROWSET')
	end

	# Loops through each host in turn. Note the current IP address is both
	# ip and datastore['RHOST']
	def run_host(ip)
		user = datastore['USERNAME']
		pass = postgres_password
		do_fingerprint(user,pass,datastore['DATABASE'])
	end

	# Alias for RHOST
	def rhost
		datastore['RHOST']
	end

	# Alias for RPORT
	def rport
		datastore['RPORT']
	end

	def do_fingerprint(user=nil,pass=nil,database=nil)
		begin
			msg = "#{rhost}:#{rport} Postgres -"
			password = pass || postgres_password
			vprint_status("#{msg} Trying username:'#{user}' with password:'#{password}' against #{rhost}:#{rport} on database '#{database}'")
			result = postgres_fingerprint(
				:db => database,
				:username => user,
				:password => password
			)
			if result[:auth]
				vprint_good "#{rhost}:#{rport} Postgres - Logged in to '#{database}' with '#{user}':'#{password}'"
				print_status "#{rhost}:#{rport} Postgres - Version #{result[:auth]} (Post-Auth)"
			elsif result[:preauth]
				print_status "#{rhost}:#{rport} Postgres - Version #{result[:preauth]} (Pre-Auth)"
			else # It's something we don't know yet
				vprint_status "#{rhost}:#{rport} Postgres - Authentication Error Fingerprint: #{result[:unknown]}"
				print_status "#{rhost}:#{rport} Postgres - Version Unknown (Pre-Auth)"
			end

			# Reporting

			report_service(
				:host => rhost,
				:port => rport,
				:name => "postgres",
				:info => result.values.first
			)

			if self.postgres_conn
				report_auth_info(
					:host => rhost,
					:port => rport,
					:sname => "postgres",
					:user => user,
					:pass => password,
					:active => true
				)
			end

			if result[:unknown]
				report_note(
					:host => rhost,
					:proto => 'tcp',
					:sname => 'postgres',
					:port => rport,
					:ntype => 'postgresql.fingerprint',
					:data => "Unknown Pre-Auth fingerprint: #{result[:unknown]}"
				)
			end

			# Logout

			postgres_logout

		rescue Rex::ConnectionError
			vprint_error "#{rhost}:#{rport} Connection Error: #{$!}"
			return :done
		end

	end

end
