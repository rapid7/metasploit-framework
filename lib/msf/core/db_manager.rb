# -*- coding: binary -*-

require 'msf/base/config'
require 'msf/core'
require 'msf/core/db'
require 'msf/core/task_manager'
require 'fileutils'
require 'shellwords'

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
	def warn_about_rubies
		if ::RUBY_VERSION =~ /^1\.9\.[012]($|[^\d])/
			$stderr.puts "**************************************************************************************"
			$stderr.puts "Metasploit requires at least Ruby 1.9.3. For an easy upgrade path, see https://rvm.io/"
			$stderr.puts "**************************************************************************************"
		end
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

	# Flag to indicate that modules are cached
	attr_accessor :modules_cached

	# Flag to indicate that the module cacher is running
	attr_accessor :modules_caching

	def initialize(framework, opts = {})

		self.framework = framework
		self.migrated  = false
		self.modules_cached  = false
		self.modules_caching = false

		@usable = false

		# Don't load the database if the user said they didn't need it.
		if (opts['DisableDatabase'])
			self.error = "disabled"
			return
		end

		initialize_database_support
	end

	#
	# Do what is necessary to load our database support
	#
	def initialize_database_support
		begin
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./

			require "active_record"

			initialize_metasploit_data_models

			@usable = true

		rescue ::Exception => e
			self.error = e
			elog("DB is not enabled due to load error: #{e}")
			return false
		end

		# Only include Mdm if we're not using Metasploit commercial versions
		# If Mdm::Host is defined, the dynamically created classes
		# are already in the object space
		begin
			unless defined? Mdm::Host
				MetasploitDataModels.require_models
			end
		rescue NameError => e
			warn_about_rubies
			raise e
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

	# Loads Metasploit Data Models and adds its migrations to migrations paths.
	#
	# @return [void]
	def initialize_metasploit_data_models
		# Provide access to ActiveRecord models shared w/ commercial versions
		require "metasploit_data_models"

		metasploit_data_model_migrations_pathname = MetasploitDataModels.root.join(
				'db',
				'migrate'
		)
		ActiveRecord::Migrator.migrations_paths << metasploit_data_model_migrations_pathname.to_s
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
			self.migrated = false
			self.modules_cached = false
		rescue ::Exception => e
			self.error = e
			elog("DB.disconnect threw an exception: #{e}")
		ensure
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
		end
	end

	# Migrate database to latest schema version.
	#
	# @param verbose [Boolean] see ActiveRecord::Migration.verbose
	# @return [Array<ActiveRecord::MigrationProxy] List of migrations that ran.
	#
	# @see ActiveRecord::Migrator.migrate
	def migrate(verbose=false)
		ran = []
		ActiveRecord::Migration.verbose = verbose

		ActiveRecord::Base.connection_pool.with_connection do
			begin
				ran = ActiveRecord::Migrator.migrate(
						ActiveRecord::Migrator.migrations_paths
				)
			# ActiveRecord::Migrator#migrate rescues all errors and re-raises them as
			# StandardError
			rescue StandardError => error
				self.error = error
				elog("DB.migrate threw an exception: #{error}")
				dlog("Call stack:\n#{error.backtrace.join "\n"}")
			end
		end

		return ran
	end

	def workspace=(workspace)
		@workspace_name = workspace.name
	end

	def workspace
		framework.db.find_workspace(@workspace_name)
	end


	def purge_all_module_details
		return if not self.migrated
		return if self.modules_caching

		::ActiveRecord::Base.connection_pool.with_connection do
			Mdm::ModuleDetail.destroy_all
		end

		true
	end

	def update_all_module_details
		return if not self.migrated
		return if self.modules_caching

		self.framework.cache_thread = Thread.current

		self.modules_cached  = false
		self.modules_caching = true

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
				begin
					update_module_details(obj)
				rescue ::Exception
					elog("Error updating module details for #{obj.fullname}: #{$!.class} #{$!}")
				end
			end
		end

		self.framework.cache_initialized = true
		self.framework.cache_thread = nil

		self.modules_cached  = true
		self.modules_caching = false

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
				if m.targets[i].platform
					m.targets[i].platform.platforms.each do |name|
						bits << [ :platform, { :name => name.to_s.split('::').last.downcase } ]
					end
				end
				if m.targets[i].arch
					bits << [ :arch, { :name => m.targets[i].arch.to_s } ]
				end
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

		res[:bits] = bits.uniq

		res
	end



	#
	# This provides a standard set of search filters for every module.
	# The search terms are in the form of:
	#   {
	#     "text" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ],
	#     "cve" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ]
	#   }
	#
	# Returns true on no match, false on match
	#
	def search_modules(search_string, inclusive=false)
		return false if not search_string

		search_string += " "

		# Split search terms by space, but allow quoted strings
		terms = Shellwords.shellwords(search_string)
		terms.delete('')

		# All terms are either included or excluded
		res = {}

		terms.each do |t|
			f,v = t.split(":", 2)
			if not v
				v = f
				f = 'text'
			end
			next if v.length == 0
			f.downcase!
			v.downcase!
			res[f] ||= [  ]
			res[f]  << v
		end

		::ActiveRecord::Base.connection_pool.with_connection {

		where_q = []
		where_v = []

		res.keys.each do |kt|
			res[kt].each do |kv|
				kv = kv.downcase
				case kt
				when 'text'
					xv = "%#{kv}%"
					where_q << ' ( ' +
						'module_details.fullname ILIKE ? OR module_details.name ILIKE ? OR module_details.description ILIKE ? OR ' +
						'module_authors.name ILIKE ? OR module_actions.name ILIKE ? OR module_archs.name ILIKE ? OR ' +
						'module_targets.name ILIKE ? OR module_platforms.name ILIKE ? OR module_refs.name ILIKE ?' +
						') '
					where_v << [ xv, xv, xv, xv, xv, xv, xv, xv, xv ]
				when 'name'
					xv = "%#{kv}%"
					where_q << ' ( module_details.fullname ILIKE ? OR module_details.name ILIKE ? ) '
					where_v << [ xv, xv ]
				when 'author'
					xv = "%#{kv}%"
					where_q << ' ( module_authors.name ILIKE ? OR module_authors.email ILIKE ? ) '
					where_v << [ xv, xv ]
				when 'os','platform'
					xv = "%#{kv}%"
					where_q << ' (  module_platforms.name ILIKE ? OR module_targets.name ILIKE ? ) '
					where_v << [ xv, xv ]
				when 'port'
					# TODO
				when 'type'
					where_q << ' ( module_details.mtype = ? ) '
					where_v << [ kv ]
				when 'app'
					where_q << ' ( module_details.stance = ? )'
					where_v << [ ( kv == "client") ? "passive" : "active"  ]
				when 'ref'
					where_q << ' ( module_refs.name ILIKE ? )'
					where_v << [ '%' + kv + '%' ]
				when 'cve','bid','osvdb','edb'
					where_q << ' ( module_refs.name = ? )'
					where_v << [ kt.upcase + '-' + kv ]

				end
			end
		end

		qry = Mdm::ModuleDetail.select("DISTINCT(module_details.*)").
			joins(
				"LEFT OUTER JOIN module_authors   ON module_details.id = module_authors.module_detail_id " +
				"LEFT OUTER JOIN module_actions   ON module_details.id = module_actions.module_detail_id " +
				"LEFT OUTER JOIN module_archs     ON module_details.id = module_archs.module_detail_id " +
				"LEFT OUTER JOIN module_refs      ON module_details.id = module_refs.module_detail_id " +
				"LEFT OUTER JOIN module_targets   ON module_details.id = module_targets.module_detail_id " +
				"LEFT OUTER JOIN module_platforms ON module_details.id = module_platforms.module_detail_id "
			).
			where(where_q.join(inclusive ? " OR " : " AND "), *(where_v.flatten)).
			# Compatibility for Postgres installations prior to 9.1 - doesn't have support for wildcard group by clauses
			group("module_details.id, module_details.mtime, module_details.file, module_details.mtype, module_details.refname, module_details.fullname, module_details.name, module_details.rank, module_details.description, module_details.license, module_details.privileged, module_details.disclosure_date, module_details.default_target, module_details.default_action, module_details.stance, module_details.ready")

		res = qry.all

		}
	end

end
end
