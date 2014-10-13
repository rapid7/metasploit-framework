# -*- coding: binary -*-

#
# Standard Library
#

require 'csv'
require 'fileutils'
require 'shellwords'
require 'tmpdir'
require 'uri'

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

require 'rex/parser/acunetix_nokogiri'
require 'rex/parser/appscan_nokogiri'
require 'rex/parser/burp_session_nokogiri'
require 'rex/parser/ci_nokogiri'
require 'rex/parser/foundstone_nokogiri'
require 'rex/parser/fusionvm_nokogiri'
require 'rex/parser/ip360_aspl_xml'
require 'rex/parser/ip360_xml'
require 'rex/parser/mbsa_nokogiri'
require 'rex/parser/nessus_xml'
require 'rex/parser/netsparker_xml'
require 'rex/parser/nexpose_raw_nokogiri'
require 'rex/parser/nexpose_simple_nokogiri'
require 'rex/parser/nexpose_xml'
require 'rex/parser/nmap_nokogiri'
require 'rex/parser/nmap_xml'
require 'rex/parser/openvas_nokogiri'
require 'rex/parser/outpost24_nokogiri'
require 'rex/parser/retina_xml'
require 'rex/parser/wapiti_nokogiri'
require 'rex/socket'

#
# Project
#

require 'metasploit/framework/require'
require 'msf/base/config'
require 'msf/core'
require 'msf/core/database_event'
require 'msf/core/db_import_error'
require 'msf/core/db_manager/import_msf_xml'
require 'msf/core/db_manager/migration'
require 'msf/core/host_state'
require 'msf/core/service_state'
require 'msf/core/task_manager'

module Msf

###
#
# The db module provides persistent storage and events. This class should be instantiated LAST
# as the active_suppport library overrides Kernel.require, slowing down all future code loads.
#
###

class DBManager
  extend Metasploit::Framework::Require

  autoload :Client, 'msf/core/db_manager/client'
  autoload :Cred, 'msf/core/db_manager/cred'
  autoload :Event, 'msf/core/db_manager/event'
  autoload :ExploitAttempt, 'msf/core/db_manager/exploit_attempt'
  autoload :ExploitedHost, 'msf/core/db_manager/exploited_host'
  autoload :Host, 'msf/core/db_manager/host'
  autoload :HostDetail, 'msf/core/db_manager/host_detail'
  autoload :HostTag, 'msf/core/db_manager/host_tag'
  autoload :Import, 'msf/core/db_manager/import'
  autoload :IPAddress, 'msf/core/db_manager/ip_address'
  autoload :Loot, 'msf/core/db_manager/loot'
  autoload :ModuleCache, 'msf/core/db_manager/module_cache'
  autoload :Note, 'msf/core/db_manager/note'
  autoload :Ref, 'msf/core/db_manager/ref'
  autoload :Report, 'msf/core/db_manager/report'
  autoload :Route, 'msf/core/db_manager/route'
  autoload :Service, 'msf/core/db_manager/service'
  autoload :Session, 'msf/core/db_manager/session'
  autoload :SessionEvent, 'msf/core/db_manager/session_event'
  autoload :Sink, 'msf/core/db_manager/sink'
  autoload :Task, 'msf/core/db_manager/task'
  autoload :Vuln, 'msf/core/db_manager/vuln'
  autoload :VulnAttempt, 'msf/core/db_manager/vuln_attempt'
  autoload :VulnDetail, 'msf/core/db_manager/vuln_detail'
  autoload :WMAP, 'msf/core/db_manager/wmap'
  autoload :Web, 'msf/core/db_manager/web'
  autoload :Workspace, 'msf/core/db_manager/workspace'

  optionally_include_metasploit_credential_creation

  include Msf::DBManager::Client
  include Msf::DBManager::Cred
  include Msf::DBManager::Event
  include Msf::DBManager::ExploitAttempt
  include Msf::DBManager::ExploitedHost
  include Msf::DBManager::Host
  include Msf::DBManager::HostDetail
  include Msf::DBManager::HostTag
  include Msf::DBManager::Import
  include Msf::DBManager::ImportMsfXml
  include Msf::DBManager::IPAddress
  include Msf::DBManager::Loot
  include Msf::DBManager::Migration
  include Msf::DBManager::ModuleCache
  include Msf::DBManager::Note
  include Msf::DBManager::Ref
  include Msf::DBManager::Report
  include Msf::DBManager::Route
  include Msf::DBManager::Service
  include Msf::DBManager::Session
  include Msf::DBManager::SessionEvent
  include Msf::DBManager::Sink
  include Msf::DBManager::Task
  include Msf::DBManager::Vuln
  include Msf::DBManager::VulnAttempt
  include Msf::DBManager::VulnDetail
  include Msf::DBManager::WMAP
  include Msf::DBManager::Web
  include Msf::DBManager::Workspace

  # Provides :framework and other accessors
  include Msf::Framework::Offspring

  #
  # CONSTANTS
  #

  # The adapter to use to establish database connection.
  ADAPTER = 'postgresql'

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
    # usable and migrated a just Boolean attributes, so check those first because they don't actually contact the
    # database.
    usable && migrated && connection_established?
  end

  # Returns true if the prerequisites have been installed
  attr_accessor :usable

  # Returns the list of usable database drivers
  def drivers
    @drivers ||= []
  end
  attr_writer :drivers

  # Returns the active driver
  attr_accessor :driver

  # Stores the error message for why the db was not loaded
  attr_accessor :error

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

      add_rails_engine_migration_paths

      @usable = true

    rescue ::Exception => e
      self.error = e
      elog("DB is not enabled due to load error: #{e}")
      return false
    end

    #
    # Determine what drivers are available
    #
    initialize_adapter

    #
    # Instantiate the database sink
    #
    initialize_sink

    true
  end

  # Checks if the spec passed to `ActiveRecord::Base.establish_connection` can connect to the database.
  #
  # @return [true] if an active connection can be made to the database using the current config.
  # @return [false] if an active connection cannot be made to the database.
  def connection_established?
    begin
      # use with_connection so the connection doesn't stay pinned to the thread.
      ActiveRecord::Base.connection_pool.with_connection {
        ActiveRecord::Base.connection.active?
      }
    rescue ActiveRecord::ConnectionNotEstablished, PG::ConnectionBad => error
      elog("Connection not established: #{error.class} #{error}:\n#{error.backtrace.join("\n")}")

      false
    end
  end

  #
  # Scan through available drivers
  #
  def initialize_adapter
    ActiveRecord::Base.default_timezone = :utc

    if connection_established? && ActiveRecord::Base.connection_config[:adapter] == ADAPTER
      dlog("Already established connection to #{ADAPTER}, so reusing active connection.")
      self.drivers << ADAPTER
      self.driver = ADAPTER
    else
      begin
        ActiveRecord::Base.establish_connection(adapter: ADAPTER)
        ActiveRecord::Base.remove_connection
      rescue Exception => error
        @adapter_error = error
      else
        self.drivers << ADAPTER
        self.driver = ADAPTER
      end
    end
  end

  # Loads Metasploit Data Models and adds its migrations to migrations paths.
  #
  # @return [void]
  def add_rails_engine_migration_paths
    unless defined? ActiveRecord
      fail "Bundle installed '--without #{Bundler.settings.without.join(' ')}'.  To clear the without option do " \
           "`bundle install --without ''` (the --without flag with an empty string) or `rm -rf .bundle` to remove " \
           "the .bundle/config manually and then `bundle install`"
    end

    Rails.application.railties.engines.each do |engine|
      migrations_paths = engine.paths['db/migrate'].existent_directories

      migrations_paths.each do |migrations_path|
        # Since ActiveRecord::Migrator.migrations_paths can persist between
        # instances of Msf::DBManager, such as in specs,
        # migrations_path may already be part of
        # migrations_paths, in which case it should not be added or multiple
        # migrations with the same version number errors will occur.
        unless ActiveRecord::Migrator.migrations_paths.include? migrations_path
          ActiveRecord::Migrator.migrations_paths << migrations_path
        end
      end
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

    # Prefer the config file's pool setting
    nopts['pool'] ||= 75

    # Prefer the config file's wait_timeout setting too
    nopts['wait_timeout'] ||= 300

    begin
      self.migrated = false

      # Check ActiveRecord::Base was already connected by Rails::Application.initialize! or some other API.
      unless connection_established?
        create_db(nopts)

        # Configure the database adapter
        ActiveRecord::Base.establish_connection(nopts)
      end
    rescue ::Exception => e
      self.error = e
      elog("DB.connect threw an exception: #{e}")
      dlog("Call stack: #{$@.join"\n"}", LEV_1)
      return false
    ensure
      after_establish_connection

      # Database drivers can reset our KCODE, do not let them
      $KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
    end

    true
  end

  # Finishes {#connect} after `ActiveRecord::Base.establish_connection` has succeeded by {#migrate migrating database}
  # and setting {#workspace}.
  #
  # @return [void]
  def after_establish_connection
    self.migrated = false

    begin
      # Migrate the database, if needed
      migrate

      # Set the default workspace
      framework.db.workspace = framework.db.default_workspace
    rescue ::Exception => exception
      self.error = exception
      elog("DB.connect threw an exception: #{exception}")
      dlog("Call stack: #{exception.backtrace.join("\n")}", LEV_1)
    else
      # Flag that migration has completed
      self.migrated = true
    end
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
        ActiveRecord::Base.establish_connection(
            opts.merge(
                'database' => 'postgres',
                'schema_search_path' => 'public'
            )
        )

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

  #
  # Determines if the database is functional
  #
  def check
  ::ActiveRecord::Base.connection_pool.with_connection {
    res = ::Mdm::Host.find(:first)
  }
  end

end
end
