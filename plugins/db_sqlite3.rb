require 'fileutils'
require 'msf/ui/console/command_dispatcher/db'

require 'rubygems'
require 'sqlite3'

module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
#
###

class Plugin::DBSQLite3 < Msf::Plugin

	#
	# Command dispatcher for configuring SQLite
	#
	class SQLiteCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		#
		# The dispatcher's name.
		#
		def name
			"SQLite3 Database"
		end
		
		#
		# The initial command set
		#		
		def commands
			{
				"db_connect"    => "Connect to an existing database ( /path/to/db )",
				"db_disconnect" => "Disconnect from the current database instance",
				"db_create"     => "Create a brand new database ( /path/to/db )",
				"db_destroy"    => "Drop an existing database ( /path/to/db )"
			}
		end


		#
		# Disconnect from the current SQLite instance
		#
		def cmd_db_disconnect(*args)
			if (framework.db)
				framework.db.disconnect()
				driver.remove_dispatcher('Database Backend')
			end
		end

		#
		# Connect to an existing SQLite database
		#
		def cmd_db_connect(*args)

			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'sqlite3' }

			opts['dbfile'] = info[:path]

			if (not File.exists?(opts['dbfile']))
				print_status("The specified database does not exist")
				return
			end
						
			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database")
			end
			
			driver.append_dispatcher(DatabaseCommandDispatcher)
			
			print_status("Successfully connected to the database")
			print_status("File: #{opts['dbfile']}")			
		end

		#
		# Create a new SQLite database instance
		#				
		def cmd_db_create(*args)
			cmd_db_disconnect()
			
			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'sqlite3' }
	
			opts['dbfile'] = info[:path]
			
			sql = File.join(Msf::Config.install_root, "data", "sql", "sqlite.sql")

			if (File.exists?(opts['dbfile']))
				print_status("The specified database already exists, use db_connect or delete this file")
				print_status("File: #{opts['dbfile']}")
				return
			end
						
			print_status("Creating a new database instance...")
		
			sqlite3 = 
				Rex::FileUtils.find_full_path("sqlite3") || 
				Rex::FileUtils.find_full_path("sqlite3.exe")
				
			if (not sqlite3)
				print_error("The sqlite3 executable was not found in the system path")
				print_error("Please install sqlite3")
				return
			end
			
			IO.popen("#{sqlite3} \"#{opts['dbfile']}\" < \"#{sql}\"") do |io|
				io.each_line do |line|
					print_line("OUTPUT: " + line.strip)
				end
			end

			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database")
			end
			driver.append_dispatcher(DatabaseCommandDispatcher)	
			
			print_status("Successfully created the database")
			print_status("File: #{opts['dbfile']}")
		end

		#
		# Drop an existing database
		#
		def cmd_db_destroy(*args)
			cmd_db_disconnect()
			info = parse_db_uri(args[0])
			File.unlink(info[:path])
		end
		
		def parse_db_uri(path)
			res = {}
			res[:path] = path || File.join(Msf::Config.config_directory, 'sqlite3.db')
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
		add_console_dispatcher(SQLiteCommandDispatcher)
	end
	

	def cleanup
		remove_console_dispatcher('SQLite3 Database')
		remove_console_dispatcher('Database Backend')	
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_sqlite3"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Loads a new sqlite3 database backend"
	end

protected

end
end
