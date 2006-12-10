require 'fileutils'
require 'msf/ui/console/command_dispatcher/db'


module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
#
###

class Plugin::DBPostgres < Msf::Plugin
	
	
	#
	# Command dispatcher for configuring Postgres
	#
	class PostgresCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		#
		# The dispatcher's name.
		#
		def name
			"Postgres Database"
		end
		
		#
		# The initial command set
		#		
		def commands
			{
				"db_connect"    => "Connect to an existing database ( user:pass@host:port/db )",
				"db_disconnect" => "Disconnect from the current database instance",
				"db_create"     => "Create a brand new database ( user:pass@host:port/db )",
				"db_destroy"    => "Drop an existing database ( user:pass@host:port/db )"
			}
		end


		#
		# Disconnect from the current Postgres instance
		#
		def cmd_db_disconnect(*args)
			if (framework.db)
				framework.db.disconnect()
				driver.remove_dispatcher('Database Backend')
			end
		end

		#
		# Connect to an existing Postgres database
		#
		def cmd_db_connect(*args)
			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'postgresql' }
			
			opts['username'] = info[:user] if (info[:user])
			opts['password'] = info[:pass] if (info[:pass])
			opts['database'] = info[:name]
			opts['host'] = info[:host] if (info[:host])
			opts['port'] = info[:port] if (info[:port])
			
			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database")
			end
			
			driver.append_dispatcher(DatabaseCommandDispatcher)
		end

		#
		# Create a new Postgres database instance
		#				
		def cmd_db_create(*args)
			cmd_db_disconnect()
			
			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'postgresql' }
			argv = []
			
			if (info[:user])
				opts['username'] = info[:user] 
				argv.push('-U')
				argv.push(info[:user])
			end
			
			if (info[:pass])
				print()
				print_status("Warning: You will need to enter the password at the prompts below")
				print()
				argv.push('-W')				
			end
			
			if (info[:host])
				opts['host'] = info[:host]
				argv.push('-h')
				argv.push(info[:host])
			end
			
			if (info[:port])
				opts['port'] = info[:port]
				argv.push('-p')
				argv.push(info[:port])
			end
						
			opts['database'] = info[:name]

			cargs = argv.map{|c| "'#{c}' "}.join
			
			sql = File.join(Msf::Config.install_root, "data", "sql", "postgres.sql")
			fd  = File.open(sql, 'r')
			
			system("dropdb #{cargs} #{info[:name]}")
			system("createdb #{cargs} #{info[:name]}")

			psql = File.popen("psql -q " + cargs + info[:name], "w")
			psql.write(fd.read)
			psql.close
			fd.close
			
			print_status("Database creation complete (check for errors)")

			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database")
			end
			driver.append_dispatcher(DatabaseCommandDispatcher)	
		end

		#
		# Drop an existing database
		#
		def cmd_db_destroy(*args)

			cmd_db_disconnect()

			info = parse_db_uri(args[0])
			argv = []
			
			if (info[:user])
				argv.push('-U')
				argv.push(info[:user])
			end
			
			if (info[:pass])
				argv.push('-P')
				argv.push(info[:pass])			
			end
			
			if (info[:host])
				argv.push('-h')
				argv.push(info[:host])
			end
			
			if (info[:port])
				argv.push('-p')
				argv.push(info[:port])
			end

			cargs = argv.map{|c| "'#{c}' "}.join
			system("dropdb #{cargs} #{info[:name]}")
		end
		
		def parse_db_uri(path)
			res = {}
			if (path)
				auth, dest = path.split('@')
				(dest = auth and auth = nil) if not dest
				res[:user],res[:pass] = auth.split(':') if auth
				targ,name = dest.split('/')
				(name = targ and targ = nil) if not name
				res[:host],res[:port] = targ.split(':') if targ
			end
			res[:name] = name || 'metasploit3'
			res
		end
	end
	
	#
	# Wrapper class for the database command dispatcher
	#
	class DatabaseCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher
		include Msf::Ui::Console::CommandDispatcher::Db
	end
	
	###
	#
	# Database specific initialization goes here
	#
	###
	
	def initialize(framework, opts)
		super
		add_console_dispatcher(PostgresCommandDispatcher)
	end
	

	def cleanup
		remove_console_dispatcher('PostgreSQL Database')
		remove_console_dispatcher('Database Backend')	
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_postgres"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Loads a new postgres database backend"
	end

protected

end
end
