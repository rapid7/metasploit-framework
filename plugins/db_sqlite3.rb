require 'fileutils'

module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
#
###

class Plugin::DBSQLite3 < Msf::Plugin

	###
	#
	# This class implements a sample console command dispatcher.
	#
	###
	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		#
		# The dispatcher's name.
		#
		def name
			"DBDispatcher"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"db_hosts" => "List all hosts in the database db",
				"db_services" => "List all services in the database db",
				"db_insert" => "Insert a new host into the db",
				"db_test"   => "Test",
			}
		end

		def cmd_db_hosts(*args)
			framework.db.each_host do |host|
				print_status("Host: #{host.address}")
			end
		end
		
		def cmd_db_services(*args)
			framework.db.each_service do |host, service|
				print_status("Service: host=#{host.address} port=#{service.port} port=#{service.proto}")
			end
		end		

		def cmd_db_insert(*args)
			print_status("Inserting #{args.length.to_s} hosts...")
			args.each do |address|
				framework.db.get_host(nil, address)
			end
		end
		
		def cmd_db_test(*args)
			framework.db.get_host(nil, "1.2.3.4")
			framework.db.get_host(nil, "1.2.3.5")
			framework.db.get_host(nil, "1.2.3.6")
			framework.db.each_host do |host|
				print_status("Host: #{host.address}")
			end	
		end		
	end


	def initialize(framework, opts)
		super

		odb = File.join(Msf::Config.install_root, "data", "sql", "sqlite3.db")
		ndb = File.join(Msf::Config.install_root, "current.db")
		
		if (File.exists?(ndb))
			File.unlink(ndb)
		end
		
		FileUtils.copy(odb, ndb)
		
		if (not framework.db.connect("adapter" => "sqlite3", "dbfile" => ndb))
			print_status("Failed to connect to the database :(")
			return
		end
		
		add_console_dispatcher(ConsoleCommandDispatcher)
	end

	def cleanup
		remove_console_dispatcher('DBDispatcher') 
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
		"Loads a new SQLite3 db and intializes it"
	end

protected

end
end
