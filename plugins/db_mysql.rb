require 'fileutils'
require 'msf/ui/console/command_dispatcher/db'
require "socket"

module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
#
###

class Plugin::DBMySQL < Msf::Plugin
	
	
	#
	# Command dispatcher for configuring Postgres
	#
	class PostgresCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		#
		# The dispatcher's name.
		#
		def name
			"MySQL Database"
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
		# Disconnect from the current MySQL instance
		#
		def cmd_db_disconnect(*args)
			if (framework.db)
				framework.db.disconnect()
				driver.remove_dispatcher('Database Backend')
			end
		end

		#
		# Connect to an existing MySQL database
		#
		def cmd_db_connect(*args)
			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'mysql' }
			
			opts['username'] = info[:user] if (info[:user])
			opts['password'] = info[:pass] if (info[:pass])
			opts['database'] = info[:name]
			opts['host'] = info[:host] if (info[:host])
			opts['port'] = info[:port] if (info[:port])

			# This is an ugly hack for a broken MySQL adapter:
			# 	http://dev.rubyonrails.org/ticket/3338
			if (opts['host'].strip.downcase == 'localhost')
				opts['host'] = Socket.gethostbyname("localhost")[3].unpack("C*").join(".")
			end
							
			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database")
			end
			
			driver.append_dispatcher(DatabaseCommandDispatcher)
		end

		#
		# Create a new MySQL database instance
		#				
		def cmd_db_create(*args)
			cmd_db_disconnect()
			
			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'mysql' }
						
			argv = []
			
			if (info[:user])
				opts['username'] = info[:user] 
				argv.push('-u')
				argv.push(info[:user])
			end
			
			if (info[:pass])
				argv.push('--password=' + info[:pass])
				opts['password'] = info[:pass]				
			end
			
			if (info[:host])
				opts['host'] = info[:host]
				argv.push('-h')
				argv.push(info[:host])
			end
			
			if (info[:port])
				opts['port'] = info[:port]
				argv.push('-P')
				argv.push(info[:port])
				
				# This is an ugly hack for a broken MySQL adapter:
				# 	http://dev.rubyonrails.org/ticket/3338
				if (opts['host'].strip.downcase == 'localhost')
					opts['host'] = Socket.gethostbyname("localhost")[3].unpack("C*").join(".")
				end
			end

			argv.push('-f')
			
			opts['database'] = info[:name]

			cargs = argv.map{|c| "'#{c}' "}.join
			
			sql = File.join(Msf::Config.install_root, "data", "sql", "mysql.sql")
			fd  = File.open(sql, 'r')
			
			system("mysqladmin #{cargs} drop #{info[:name]} >/dev/null 2>&1")
			system("mysqladmin #{cargs} create #{info[:name]}")

			psql = File.popen("mysql #{cargs} #{info[:name]}", "w")
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
				argv.push('-u')
				argv.push(info[:user])
			end
			
			if (info[:pass])
				argv.push('--password=' + info[:pass])
			end
			
			if (info[:host])
				argv.push('-h')
				argv.push(info[:host])
			end
			
			if (info[:port])
				argv.push('-P')
				argv.push(info[:port])
			end
			
			argv.push("-f")

			cargs = argv.map{|c| "'#{c}' "}.join
			system("mysqladmin -f #{cargs} drop #{info[:name]}")
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
		remove_console_dispatcher('MySQL Database')
		remove_console_dispatcher('Database Backend')	
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_mysql"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Loads a new mysql database backend"
	end

protected

end
end
