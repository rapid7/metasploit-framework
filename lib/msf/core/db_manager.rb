require "active_record"

require 'msf/core'
require 'msf/core/db'
require 'msf/core/task_manager'
require 'fileutils'

# Provide access to ActiveRecord models shared w/ commercial versions
require "metasploit_data_models"

# Patches issues with ActiveRecord
require "msf/core/patches/active_record"


require 'fileutils'

module Msf

###
#
# The db module provides persistent storage and events. This class should be instantiated LAST
# as the active_suppport library overrides Kernel.require, slowing down all future code loads.
#
###

class DBManager

	# Mainly, it's Ruby 1.9.1 that cause a lot of problems now, along with Ruby 1.8.6.
	# Ruby 1.8.7 actually seems okay, but why tempt fate? Let's say 1.9.3 and beyond.
	def self.warn_about_rubies
		if ::RUBY_VERSION =~ /^1\.9\.[012]($|[^\d])/
			$stderr.puts "**************************************************************************************"
			$stderr.puts "Metasploit requires at least Ruby 1.9.3. For an easy upgrade path, see https://rvm.io/"
			$stderr.puts "**************************************************************************************"
		end
	end

	begin
		include MetasploitDataModels
	rescue NameError => e
		warn_about_rubies
		raise e
	end

	# Provides :framework and other accessors
	include Framework::Offspring

	# Returns true if we are ready to load/store data
	def active
		return false if not @usable
		# We have established a connection, some connection is active, and we have run migrations
		(ActiveRecord::Base.connected? && ActiveRecord::Base.connection_pool.connected? && migrated)# rescue false
	end

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

	# Flag to indicate database migration has completed
	attr_accessor :migrated

	# Array of additional migration paths
	attr_accessor :migration_paths

	def initialize(framework, opts = {})

		self.framework = framework
		self.migrated  = false
		self.migration_paths = [ ::File.join(Msf::Config.install_root, "data", "sql", "migrate") ]

		@usable = false

		# Don't load the database if the user said they didn't need it.
		if (opts['DisableDatabase'])
			self.error = "disabled"
			return
		end

		initialize_database_support
	end

	#
	# Add additional migration paths
	#
	def add_migration_path(path)
		self.migration_paths.push(path)
	end

	#
	# Do what is necessary to load our database support
	#
	def initialize_database_support
		begin
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./

			@usable = true

		rescue ::Exception => e
			self.error = e
			elog("DB is not enabled due to load error: #{e}")
			return false
		end

		#
		# Determine what drivers are available
		#
		initialize_drivers

		#
		# Instantiate the database sink
		#
		initialize_sink

		true
	end

	#
	# Scan through available drivers
	#
	def initialize_drivers
		self.drivers = []
		tdrivers = %W{ postgresql }
		tdrivers.each do |driver|
			begin
				ActiveRecord::Base.default_timezone = :utc
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

		# Database drivers can reset our KCODE, do not let them
		$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
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

	#
	# Connects this instance to a database
	#
	def connect(opts={})

		return false if not @usable

		nopts = opts.dup
		if (nopts['port'])
			nopts['port'] = nopts['port'].to_i
		end

		# Prefer the config file's pool setting
		nopts['pool'] ||= 75

		begin
			self.migrated = false
			create_db(nopts)

			# Configure the database adapter
			ActiveRecord::Base.establish_connection(nopts)

			# Migrate the database, if needed
			migrate

			# Set the default workspace
			framework.db.workspace = framework.db.default_workspace

			# Flag that migration has completed
			self.migrated = true
		rescue ::Exception => e
			self.error = e
			elog("DB.connect threw an exception: #{e}")
			dlog("Call stack: #{$@.join"\n"}", LEV_1)
			return false
		ensure
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
		end

		true
	end

	#
	# Attempt to create the database
	#
	# If the database already exists this will fail and we will continue on our
	# merry way, connecting anyway.  If it doesn't, we try to create it.  If
	# that fails, then it wasn't meant to be and the connect will raise a
	# useful exception so the user won't be in the dark; no need to raise
	# anything at all here.
	#
	def create_db(opts)
		begin
			case opts["adapter"]
			when 'postgresql'
				# Try to force a connection to be made to the database, if it succeeds
				# then we know we don't need to create it :)
				ActiveRecord::Base.establish_connection(opts)
				# Do the checkout, checkin dance here to make sure this thread doesn't
				# hold on to a connection we don't need
				conn = ActiveRecord::Base.connection_pool.checkout
				ActiveRecord::Base.connection_pool.checkin(conn)
			end
		rescue ::Exception => e
			errstr = e.to_s
			if errstr =~ /does not exist/i or errstr =~ /Unknown database/
				ilog("Database doesn't exist \"#{opts['database']}\", attempting to create it.")
				ActiveRecord::Base.establish_connection(opts.merge('database' => nil))
				ActiveRecord::Base.connection.create_database(opts['database'])
			else
				ilog("Trying to continue despite failed database creation: #{e}")
			end
		end
		ActiveRecord::Base.remove_connection
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
		ensure
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
		end
	end

	#
	# Migrate database to latest schema version
	#
	def migrate(verbose=false)

		temp_dir = ::File.expand_path(::File.join( Msf::Config.config_directory, "schema", "#{Time.now.to_i}_#{$$}" ))
		::FileUtils.rm_rf(temp_dir)
		::FileUtils.mkdir_p(temp_dir)

		self.migration_paths.each do |mpath|
			dir = Dir.new(mpath) rescue nil
			if not dir
				elog("Could not access migration path #{mpath}")
				next
			end

			dir.entries.each do |ent|
				next unless ent =~ /^\d+.*\.rb$/
				::FileUtils.cp( ::File.join(mpath, ent), ::File.join(temp_dir, ent) )
			end
		end

		success = true
		begin

			::ActiveRecord::Base.connection_pool.with_connection {
				ActiveRecord::Migration.verbose = verbose
				ActiveRecord::Migrator.migrate(temp_dir, nil)
			}
		rescue ::Exception => e
			self.error = e
			elog("DB.migrate threw an exception: #{e}")
			dlog("Call stack:\n#{e.backtrace.join "\n"}")
			success = false
		end

		::FileUtils.rm_rf(temp_dir)

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

