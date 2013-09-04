# -*- coding: binary -*-

require 'msf/base/config'
require 'msf/core'
require 'msf/core/db'
require 'msf/core/db_manager/migration'
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
	# Provides :framework and other accessors
	include Msf::DBManager::Migration
	include Msf::Framework::Offspring

	# Mainly, it's Ruby 1.9.1 that cause a lot of problems now, along with Ruby 1.8.6.
	# Ruby 1.8.7 actually seems okay, but why tempt fate? Let's say 1.9.3 and beyond.
	def warn_about_rubies
		if ::RUBY_VERSION =~ /^1\.9\.[012]($|[^\d])/
			$stderr.puts "**************************************************************************************"
			$stderr.puts "Metasploit requires at least Ruby 1.9.3. For an easy upgrade path, see https://rvm.io/"
			$stderr.puts "**************************************************************************************"
		end
	end

	# Returns true if we are ready to load/store data
	def active
		return false if not @usable
		# We have established a connection, some connection is active, and we have run migrations
		(ActiveRecord::Base.connected? && ActiveRecord::Base.connection_pool.connected? && migrated)# rescue false
	end

	alias_method :active?, :active

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
		metasploit_data_model_migrations_path = metasploit_data_model_migrations_pathname.to_s

		# Since ActiveRecord::Migrator.migrations_paths can persist between
		# instances of Msf::DBManager, such as in specs,
		# metasploit_data_models_migrations_path may already be part of
		# migrations_paths, in which case it should not be added or multiple
		# migrations with the same version number errors will occur.
		unless ActiveRecord::Migrator.migrations_paths.include? metasploit_data_model_migrations_path
			ActiveRecord::Migrator.migrations_paths << metasploit_data_model_migrations_path
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

	def workspace=(workspace)
		@workspace_name = workspace.name
	end

	def workspace
		framework.db.find_workspace(@workspace_name)
	end


	# @note Does nothing unless {#migrated} is +true+ and {#modules_caching} is
	#   +false+.
	#
	# Destroys all Mdm::Module::Details in the database.
	#
	# @return [void]
	def purge_all_module_details
		return if not self.migrated
		return if self.modules_caching

		::ActiveRecord::Base.connection_pool.with_connection do
			Mdm::Module::Detail.destroy_all
		end
	end

	# Creates an Mdm::Module::Detail from a module instance.
	#
	# @param module_instance [Msf::Module] a metasploit module instance.
	# @raise [ActiveRecord::RecordInvalid] if Hash from {#module_to_details_hash} is invalid attributes for
	#   Mdm::Module::Detail.
	# @return [void]
	def update_module_details(module_instance)
		return if not self.migrated

		ActiveRecord::Base.connection_pool.with_connection do
			info = module_to_details_hash(module_instance)
			bits = info.delete(:bits) || []
			module_detail = Mdm::Module::Detail.create!(info)

			bits.each do |args|
				otype, vals = args

				case otype
					when :action
						module_detail.add_action(vals[:name])
					when :arch
						module_detail.add_arch(vals[:name])
					when :author
						module_detail.add_author(vals[:name], vals[:email])
					when :platform
						module_detail.add_platform(vals[:name])
					when :ref
						module_detail.add_ref(vals[:name])
					when :target
						module_detail.add_target(vals[:index], vals[:name])
				end
			end

			module_detail.ready = true
			module_detail.save!
		end
	end

	# Destroys Mdm::Module::Detail if one exists for the given
	# Mdm::Module::Detail#mtype and Mdm::Module::Detail#refname.
	#
	# @param mtype [String] module type.
	# @param refname [String] module reference name.
	# @return [void]
	def remove_module_details(mtype, refname)
		return if not self.migrated

		ActiveRecord::Base.connection_pool.with_connection do
			Mdm::Module::Detail.where(:mtype => mtype, :refname => refname).destroy_all
		end
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

  # Wraps values in +'%'+ for Arel::Prediciation#matches_any and other match* methods that map to SQL +'LIKE'+ or
  # +'ILIKE'+
  #
  # @param values [Set<String>, #each] a list of strings.
  # @return [Arrray<String>] strings wrapped like %<string>%
  def match_values(values)
    wrapped_values = values.collect { |value|
      "%#{value}%"
    }

    wrapped_values
  end

	# This provides a standard set of search filters for every module.
	#
	# Supported keywords with the format <keyword>:<search_value>:
	# +app+:: If +client+ then matches +'passive'+ stance modules, otherwise matches +'active' stance modules.
	# +author+:: Matches modules with the given author email or name.
	# +bid+:: Matches modules with the given Bugtraq ID.
	# +cve+:: Matches modules with the given CVE ID.
	# +edb+:: Matches modules with the given Exploit-DB ID.
	# +name+:: Matches modules with the given full name or name.
	# +os+, +platform+:: Matches modules with the given platform or target name.
	# +osvdb+:: Matches modules with the given OSVDB ID.
	# +ref+:: Matches modules with the given reference ID.
	# +type+:: Matches modules with the given type.
	#
	# Any text not associated with a keyword is matched against the description,
	# the full name, and the name of the module; the name of the module actions;
	# the name of the module archs; the name of the module authors; the name of
	# module platform; the module refs; or the module target.
	#
	# @param search_string [String] a string of space separated keyword pairs or
	#   free form text.
	# @return [[]] if search_string is +nil+
	# @return [ActiveRecord::Relation] module details that matched
	#   +search_string+
	def search_modules(search_string)
    search_string ||= ''
    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = Shellwords.shellwords(search_string)
    terms.delete('')

    # All terms are either included or excluded
    value_set_by_keyword = Hash.new { |hash, keyword|
      hash[keyword] = Set.new
    }

    terms.each do |term|
      keyword, value = term.split(':', 2)

      unless value
        value = keyword
        keyword = 'text'
      end

      unless value.empty?
        keyword.downcase!

        value_set = value_set_by_keyword[keyword]
        value_set.add value
      end
    end

    query = Mdm::Module::Detail.scoped

    ActiveRecord::Base.connection_pool.with_connection do
      # Although AREL supports taking the union or two queries, the ActiveRecord where syntax only supports
      # intersection, so creating the where clause has to be delayed until all conditions can be or'd together and
      # passed to one call ot where.
      union_conditions = []

      value_set_by_keyword.each do |keyword, value_set|
        case keyword
          when 'author'
            formatted_values = match_values(value_set)

            query = query.includes(:authors)
            module_authors = Mdm::Module::Author.arel_table
            union_conditions << module_authors[:email].matches_any(formatted_values)
            union_conditions << module_authors[:name].matches_any(formatted_values)
          when 'name'
            formatted_values = match_values(value_set)

            module_details = Mdm::Module::Detail.arel_table
            union_conditions << module_details[:fullname].matches_any(formatted_values)
            union_conditions << module_details[:name].matches_any(formatted_values)
          when 'os', 'platform'
            formatted_values = match_values(value_set)

            query = query.includes(:platforms)
            union_conditions << Mdm::Module::Platform.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:targets)
            union_conditions << Mdm::Module::Target.arel_table[:name].matches_any(formatted_values)
          when 'text'
            formatted_values = match_values(value_set)

            module_details = Mdm::Module::Detail.arel_table
            union_conditions << module_details[:description].matches_any(formatted_values)
            union_conditions << module_details[:fullname].matches_any(formatted_values)
            union_conditions << module_details[:name].matches_any(formatted_values)

            query = query.includes(:actions)
            union_conditions << Mdm::Module::Action.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:archs)
            union_conditions << Mdm::Module::Arch.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:authors)
            union_conditions << Mdm::Module::Author.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:platforms)
            union_conditions << Mdm::Module::Platform.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:refs)
            union_conditions << Mdm::Module::Ref.arel_table[:name].matches_any(formatted_values)

            query = query.includes(:targets)
            union_conditions << Mdm::Module::Target.arel_table[:name].matches_any(formatted_values)
          when 'type'
            formatted_values = match_values(value_set)
            union_conditions << Mdm::Module::Detail.arel_table[:mtype].matches_any(formatted_values)
          when 'app'
            formatted_values = value_set.collect { |value|
              formatted_value = 'aggressive'

              if value == 'client'
                formatted_value = 'passive'
              end

              formatted_value
            }

            union_conditions << Mdm::Module::Detail.arel_table[:stance].eq_any(formatted_values)
          when 'ref'
            formatted_values = match_values(value_set)

            query = query.includes(:refs)
            union_conditions << Mdm::Module::Ref.arel_table[:name].matches_any(formatted_values)
          when 'cve', 'bid', 'osvdb', 'edb'
            formatted_values = value_set.collect { |value|
              prefix = keyword.upcase

              "#{prefix}-%#{value}%"
            }

            query = query.includes(:refs)
            union_conditions << Mdm::Module::Ref.arel_table[:name].matches_any(formatted_values)
        end
      end

      unioned_conditions = union_conditions.inject { |union, condition|
        union.or(condition)
      }

      query = query.where(unioned_conditions).uniq
    end

    query
  end

end
end
