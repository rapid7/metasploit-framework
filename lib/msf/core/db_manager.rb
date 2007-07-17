require 'msf/core'
require 'msf/core/db'

module Msf

###
#
# The db module provides persistent storage and events
#
###

class DBManager

	# Provides :framework and other accessors
	include Framework::Offspring
	
	# Returns true if we are ready to load/store data
	attr_accessor :active
	
	# Returns true if the prerequisites have been installed
	attr_accessor :usable
	
	def initialize(framework)
			
		self.framework = framework
		@usable = false
		@active = false
		
		# Load ActiveRecord if it is available
		begin	
			require 'rubygems'
			require 'active_record'
			require 'msf/core/db_objects'
			
			@usable = true
			
		rescue ::Exception => e
			elog("DB is not enabled due to load error: #{e.to_s}")
		end
	end
	
	#
	# Connects this instance to a database
	#
	def connect(opts={})
		
		return false if not @usable
		
		nopts = opts.dup
		if (nopts['port'])
			nopts['port'] = nopts['port'].to_i
		end
		
		
		begin
			ActiveRecord::Base.threaded_connections = false
			ActiveRecord::Base.establish_connection(nopts)
		rescue ::Exception => e
			elog("DB.connect threw an exception: #{e.to_s}")
			return false
		end
		
		@active = true
	end
	
	#
	# Disconnects a database session
	#
	def disconnect
		begin
			ActiveRecord::Base.remove_connection
		rescue ::Exception => e
			elog("DB.disconnect threw an exception: #{e.to_s}")
		end
		@active = false
	end

end
end
