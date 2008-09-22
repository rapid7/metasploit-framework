require 'fileutils'
require 'msf/ui/console/command_dispatcher/wmap'
require 'rubygems'
require 'sqlite3'

module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
#
# For wmap purposes this is a full copy of db_sqlite.rb plugin 
# with minor modification poinitng to a different
# command dispatcher and a diferent sql file in data/wmap 
# directory.
#
# ET LoWNOISE 08
#
###

class Plugin::DBWmap < Msf::Plugin

	#
	# Command dispatcher for configuring SQLite
	#
	class WmapSQLiteCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		#
		# The dispatcher's name.
		#
		def name
			"Wmap SQLite3 Database"
		end
		
		#
		# The initial command set
		#		
		def commands
			{
				"wmap_connect"    => "Connect to an existing database ( /path/to/db )",
				"wmap_disconnect" => "Disconnect from the current database instance",
				"wmap_create"     => "Create a brand new database ( /path/to/db )",
				"wmap_destroy"    => "Drop an existing database ( /path/to/db )"
			}
		end


		#
		# Disconnect from the current SQLite instance
		#
		def cmd_wmap_disconnect(*args)
			if (framework.db)
				framework.db.disconnect()
				driver.remove_dispatcher('Database Backend')
			end
		end

		#
		# Connect to an existing SQLite database
		#
		def cmd_wmap_connect(*args)

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
			
			driver.append_dispatcher(WmapDatabaseCommandDispatcher)
			
			print_status("Successfully connected to the wmap database")
			print_status("File: #{opts['dbfile']}")
			
			print_status("Reloading targets...")
			driver.run_single("wmap_targets -r")
		end

		#
		# Create a new SQLite database instance
		#				
		def cmd_wmap_create(*args)
			cmd_wmap_disconnect()
			
			info = parse_db_uri(args[0])
			opts = { 'adapter' => 'sqlite3' }
	
			opts['dbfile'] = info[:path]
			
			sql = File.join(Msf::Config.install_root, "data", "wmap", "sql", "sqlite.sql")

			if (File.exists?(opts['dbfile']))
				print_status("The specified database already exists, connecting")
			else
						
				print_status("Creating a new database instance...")

				db = SQLite3::Database.new(opts['dbfile'])
				File.read(sql).split(";").each do |line|
					begin
						db.execute(line.strip)
					rescue ::SQLite3::SQLException, ::SQLite3::MisuseException
					end
				end
				db.close
			end
			

			if (not framework.db.connect(opts))
				raise PluginLoadError.new("Failed to connect to the database")
			end
			
			driver.append_dispatcher(WmapDatabaseCommandDispatcher)	
			
			print_status("Successfully connected to the database")
			print_status("File: #{opts['dbfile']}")
		end

		#
		# Drop an existing database
		#
		def cmd_wmap_destroy(*args)
			cmd_wmap_disconnect()
			info = parse_db_uri(args[0])
			File.unlink(info[:path])
		end
		
		def parse_db_uri(path)
			res = {}
			res[:path] = path || File.join(Msf::Config.install_root, "data", "wmap", "wmap_sqlite3.db")
			res
		end
	end
	
	#
	# Wrapper class for the database command dispatcher
	#
	class WmapDatabaseCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher
		include Msf::Ui::Console::CommandDispatcher::Wmap
	end

	###
	#
	# Database specific initialization goes here
	#
	###
	
	def initialize(framework, opts)
		super
		add_console_dispatcher(WmapSQLiteCommandDispatcher)

		print_status("=[ WMAP v0.1 - ET LoWNOISE")	
	end
	

	def cleanup
		remove_console_dispatcher('Wmap SQLite3 Database')
		remove_console_dispatcher('Wmap Database Backend')	
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_wmap_sqlite3"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Loads a new sqlite3 wmap database backend"
	end

protected

end
end
