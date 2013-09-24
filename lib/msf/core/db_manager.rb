# -*- coding: binary -*-


#
# Standard Library
#

require 'csv'
require 'fileutils'
require 'shellwords'
require 'tmpdir'
require 'uri'
require 'zip'

#
#
# Gems
#
#

#
# PacketFu
#

require 'packetfu'

#
# Rex
#

require 'rex/socket'

# Check Rex::Parser.nokogiri_loaded for status of the Nokogiri parsers
require 'rex/parser/acunetix_nokogiri'
require 'rex/parser/appscan_nokogiri'
require 'rex/parser/burp_session_nokogiri'
require 'rex/parser/ci_nokogiri'
require 'rex/parser/foundstone_nokogiri'
require 'rex/parser/fusionvm_nokogiri'
require 'rex/parser/mbsa_nokogiri'
require 'rex/parser/nexpose_raw_nokogiri'
require 'rex/parser/nexpose_simple_nokogiri'
require 'rex/parser/nmap_nokogiri'
require 'rex/parser/openvas_nokogiri'
require 'rex/parser/wapiti_nokogiri'

# Legacy XML parsers -- these will be converted some day
require 'rex/parser/ip360_aspl_xml'
require 'rex/parser/ip360_xml'
require 'rex/parser/nessus_xml'
require 'rex/parser/netsparker_xml'
require 'rex/parser/nexpose_xml'
require 'rex/parser/nmap_xml'
require 'rex/parser/retina_xml'

#
# Project
#

require 'msf/base/config'
require 'msf/core'
require 'msf/core/database_event'
require 'msf/core/db_import_error'
require 'msf/core/host_state'
require 'msf/core/task_manager'
require 'msf/core/service_state'

# The db module provides persistent storage and events.
class Msf::DBManager < Metasploit::Model::Base
  require 'msf/core/db_manager/client'
  include Msf::DBManager::Client

  require 'msf/core/db_manager/cred'
  include Msf::DBManager::Cred

  require 'msf/core/db_manager/event'
  include Msf::DBManager::Event

  require 'msf/core/db_manager/exploit'
  include Msf::DBManager::Exploit

  require 'msf/core/db_manager/exploited_host'
  include Msf::DBManager::ExploitedHost

  # class declared under Msf::DBManager, so need to require after Msf::DBManager is declared.
  require 'msf/core/db_manager/export'

  require 'msf/core/db_manager/host'
  include Msf::DBManager::Host

  require 'msf/core/db_manager/import'
  include Msf::DBManager::Import

  require 'msf/core/db_manager/loot'
  include Msf::DBManager::Loot

  require 'msf/core/db_manager/migration'
  include Msf::DBManager::Migration

  require 'msf/core/db_manager/note'
  include Msf::DBManager::Note

  require 'msf/core/db_manager/ref'
  include Msf::DBManager::Ref

  require 'msf/core/db_manager/report'
  include Msf::DBManager::Report

  require 'msf/core/db_manager/search'
  include Msf::DBManager::Search

  require 'msf/core/db_manager/service'
  include Msf::DBManager::Service

  require 'msf/core/db_manager/session'
  include Msf::DBManager::Session

  require 'msf/core/db_manager/task'
  include Msf::DBManager::Task

  require 'msf/core/db_manager/validators'
  include Msf::DBManager::Validators

  require 'msf/core/db_manager/vuln'
  include Msf::DBManager::Vuln

  require 'msf/core/db_manager/web'
  include Msf::DBManager::Web

  require 'msf/core/db_manager/wmap'
  include Msf::DBManager::WMAP

  require 'msf/core/db_manager/workspace'
  include Msf::DBManager::Workspace

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

  def disabled
    unless instance_variable_defined? :@disabled
      if framework
        @disabled = framework.database_disabled?
      else
        @disabled = false
      end
    end

    @disabled
  end
  alias disabled? disabled

  attr_writer :disabled

  def initialize(attributes={})
    super

    self.migrated  = false
    self.modules_cached  = false
    self.modules_caching = false

    @usable = false

    # Don't load the database if the user said they didn't need it.
    if disabled?
      self.error = "disabled"
    else
      initialize_database_support
    end
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
    self.sink = Msf::TaskManager.new(framework)
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
end
