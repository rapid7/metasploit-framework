require 'fileutils'
require 'msf/ui/console/command_dispatcher/wmap'

module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
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

			}
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
		
		#add_console_dispatcher(WmapDatabaseCommandDispatcher)
		
		add_console_dispatcher(WmapSQLiteCommandDispatcher)
		add_console_dispatcher(WmapDatabaseCommandDispatcher)	

		print_status("=[ WMAP v0.3 - ET LoWNOISE")	
	end
	

	def cleanup
		remove_console_dispatcher('Wmap SQLite3 Database')
		remove_console_dispatcher('Wmap Database Backend')	
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_wmap"
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
