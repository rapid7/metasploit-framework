require 'msf/core'
require 'msf/core/db'
require 'msf/core/task_manager'

module Msf

###
#
# The db module provides persistent storage and events. This class should be instantiated LAST
# as the active_suppport library overrides Kernel.require, slowing down all future code loads.
#
###

class DBManager

	# Provides :framework and other accessors
	include Framework::Offspring

	# Returns true if we are ready to load/store data
	attr_accessor :active

	# Returns true if the prerequisites have been installed
	attr_accessor :usable

	# Returns the list of usable database drivers
	attr_accessor :drivers

	# Returns the active driver
	attr_accessor :driver

	# Stores the error message for why the db was not loaded
	attr_accessor :error

	# Stores a TaskManager for serializing database events
	attr_accessor :sink

	def initialize(framework)

		self.framework = framework
		@usable = false
		@active = false

		#
		# Prefer our local copy of active_record and active_support
		#
		dir_ar = File.join(Msf::Config.data_directory, 'msfweb', 'vendor', 'rails', 'activerecord', 'lib')
		if(File.directory?(dir_ar) and not $:.include?(dir_ar))
			$:.unshift(dir_ar)
		end

		dir_as = File.join(Msf::Config.data_directory, 'msfweb', 'vendor', 'rails', 'activesupport', 'lib')
		if(File.directory?(dir_as) and not $:.include?(dir_as))
			$:.unshift(dir_as)
		end

		# Load ActiveRecord if it is available
		begin
			require 'rubygems'
			require 'active_record'
			require 'active_support'
			require 'msf/core/db_objects'
			require 'msf/core/model'
			@usable = true

		rescue ::Exception => e
			self.error = e
			elog("DB is not enabled due to load error: #{e}")
			return
		end

		#
		# Determine what drivers are available
		#
		initialize_drivers

		#
		# Instantiate the database sink
		#
		initialize_sink
	end

	#
	# Scan through available drivers
	#
	def initialize_drivers
		self.drivers = []
		tdrivers = %W{ sqlite3 mysql postgresql }
		tdrivers.each do |driver|
			begin
				ActiveRecord::Base.establish_connection(:adapter => driver)
				if(self.respond_to?("driver_check_#{driver}"))
					self.send("driver_check_#{driver}")
				end
				ActiveRecord::Base.remove_connection
				self.drivers << driver
			rescue ::Exception
			end
		end

		if(not self.drivers.empty?)
			self.driver = self.drivers[0]
		end
	end

	#
	# Create a new database sink and initialize it
	#
	def initialize_sink
		self.sink = TaskManager.new(framework)
		self.sink.start
	end

	#
	# Add a new task to the sink
	#
	def queue(proc)
		self.sink.queue_proc(proc)
	end


	# Verify that sqlite3 is ready
	def driver_check_sqlite3
		require 'sqlite3'
	end

	# Verify that mysql is ready
	def driver_check_mysql
		require 'mysql'
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
			# Configure the database adapter
			ActiveRecord::Base.establish_connection(nopts)

			# Migrate the database, if needed
			migrate

			# Set the default workspace
			framework.db.workspace = framework.db.default_workspace
		rescue ::Exception => e
			self.error = e
			elog("DB.connect threw an exception: #{e}")
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
			self.error = e
			elog("DB.disconnect threw an exception: #{e}")
		end
		@active = false
	end

	#
	# Migrate database to latest schema version
	#
	def migrate(verbose = false)
		begin
			migrate_dir = ::File.join(Msf::Config.install_root, "data", "sql", "migrate")
			ActiveRecord::Migration.verbose = verbose
			ActiveRecord::Migrator.migrate(migrate_dir, nil)
		rescue ::Exception => e
			self.error = e
			elog("DB.migrate threw an exception: #{e}")
			return false
		end
		return true
	end

	def workspace=(workspace)
		@workspace_name = workspace.name
	end

	def workspace
		framework.db.find_workspace(@workspace_name)
	end

end
end

