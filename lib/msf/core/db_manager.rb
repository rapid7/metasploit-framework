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

  # Only include Mdm if we're not using Metasploit commercial versions
  # If Mdm::Host is defined, the dynamically created classes
  # are already in the object space
  begin
    include MetasploitDataModels unless defined? Mdm::Host
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
		
		# Prefer the config file's wait_timeout setting too
		nopts['wait_timeout'] ||= 300

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

	def update_all_module_details
		return if not self.migrated

		::ActiveRecord::Base.connection_pool.with_connection {
		
		refresh = []
		skipped = []

		Mdm::ModuleDetail.find_each do |md|

			unless md.ready
				refresh << md
				next
			end

			unless md.file and ::File.exists?(md.file)
				refresh << md
				next
			end

			if ::File.mtime(md.file).to_i != md.mtime.to_i
				refresh << md
				next
			end

			skipped << [md.mtype, md.refname]
		end

		refresh.each  {|md| md.destroy }
		refresh = nil

		stime = Time.now.to_f
		[
			[ 'exploit',   framework.exploits  ],
			[ 'auxiliary', framework.auxiliary ],
			[ 'post',      framework.post      ],
			[ 'payload',   framework.payloads  ],
			[ 'encoder',   framework.encoders  ],
			[ 'nop',       framework.nops      ]
		].each do |mt|
			mt[1].keys.sort.each do |mn|
				next if skipped.include?( [ mt[0], mn ] )
				obj   = mt[1].create(mn)
				next if not obj
				update_module_details(obj)		
			end
		end

		nil

		}
	end

	def update_module_details(obj)
		return if not self.migrated

		::ActiveRecord::Base.connection_pool.with_connection {
		info = module_to_details_hash(obj)
		bits = info.delete(:bits) || []

		md = Mdm::ModuleDetail.create(info)
		bits.each do |args|
			otype, vals = args
			case otype
			when :author
				md.add_author(vals[:name], vals[:email])
			when :action
				md.add_action(vals[:name])
			when :arch
				md.add_arch(vals[:name])
			when :platform
				md.add_platform(vals[:name])
			when :target
				md.add_target(vals[:index], vals[:name])
			when :ref
				md.add_ref(vals[:name])
			when :mixin
				# md.add_mixin(vals[:name])
			end
		end

		md.ready = true
		md.save
		md.id

		}
	end

	def remove_module_details(mtype, refname)
		return if not self.migrated
		::ActiveRecord::Base.connection_pool.with_connection {
		md = Mdm::ModuleDetail.find(:conditions => [ 'mtype = ? and refname = ?', mtype, refname])
		md.destroy if md
		}
	end

	def module_to_details_hash(m)
		res  = {}
		bits = []

		res[:mtime]    = ::File.mtime(m.file_path) rescue Time.now
		res[:file]     = m.file_path
		res[:mtype]    = m.type
		res[:name]     = m.name.to_s
		res[:refname]  = m.refname
		res[:fullname] = m.fullname
		res[:rank]     = m.rank.to_i
		res[:license]  = m.license.to_s

		res[:description] = m.description.to_s.strip

		m.arch.map{ |x| 
			bits << [ :arch, { :name => x.to_s } ] 
		}

		m.platform.platforms.map{ |x| 
			bits << [ :platform, { :name => x.to_s.split('::').last.downcase } ] 
		}

		m.author.map{|x| 
			bits << [ :author, { :name => x.to_s } ] 
		}

		m.references.map do |r|
			bits << [ :ref, { :name => [r.ctx_id.to_s, r.ctx_val.to_s].join("-") } ]
		end

		res[:privileged] = m.privileged?


		if m.disclosure_date
			begin
				res[:disclosure_date] = m.disclosure_date.to_datetime.to_time
			rescue ::Exception
				res.delete(:disclosure_date)
			end
		end

		if(m.type == "exploit")

			m.targets.each_index do |i|
				bits << [ :target, { :index => i, :name => m.targets[i].name.to_s } ]
			end

			if (m.default_target)
				res[:default_target] = m.default_target
			end

			# Some modules are a combination, which means they are actually aggressive
			res[:stance] = m.stance.to_s.index("aggressive") ? "aggressive" : "passive"

			
			m.class.mixins.each do |x|
			 	bits << [ :mixin, { :name => x.to_s } ]
			end
		end

		if(m.type == "auxiliary")
	
			m.actions.each_index do |i|
				bits << [ :action, { :name => m.actions[i].name.to_s } ]
			end

			if (m.default_action)
				res[:default_action] = m.default_action.to_s
			end

			res[:stance] = m.passive? ? "passive" : "aggressive"
		end

		res[:bits] = bits

		res
	end

end
end

