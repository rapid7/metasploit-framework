require 'fileutils'
require 'msf/ui/console/command_dispatcher/db'


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
	# This class implements an event handler for db events
	#
	###
	class DBEventHandler
		def on_db_host(context, host)
			# puts "New host event: #{host.address}"
		end
		
		def on_db_service(context, service)
			# puts "New service event: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}"
		end
		
		def on_db_vuln(context, vuln)
			# puts "New vuln event: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name}"
		end
	end
	
	###
	#
	# Inherit the database command set
	#
	###
	class ConsoleCommandDispatcher
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

		odb = File.join(Msf::Config.install_root, "data", "sql", "sqlite3.db")
		ndb = File.join(Msf::Config.config_directory, "sqlite3.db")
		
		if (not File.exists?(ndb))
			FileUtils.copy(odb, ndb)
		end

		if (not framework.db.connect("adapter" => "sqlite3", "dbfile" => ndb))
			print_status("Error loading database from #{ndb}")
			raise PluginLoadError.new("Failed to connect to the database")
		end
		
		begin
			framework.db.check
		rescue ::ActiveRecord::StatementInvalid
			raise PluginLoadError.new("The database at #{ndb} appears to be corrupted")
		rescue ::Exception
			print_status("Strange new error class: "  + $!.class.to_s)
			raise $!
		end
		
		
		@dbh = DBEventHandler.new
		
		add_console_dispatcher(ConsoleCommandDispatcher)
		framework.events.add_db_subscriber(@dbh)
		
	end

	def cleanup
		framework.events.remove_db_subscriber(@dbh)
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
