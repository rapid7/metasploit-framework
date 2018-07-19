# -*- coding: binary -*-

#
# Gems
#

require 'rex/socket'

#
# Project
#
require 'metasploit/framework/require'
require 'msf/base/config'
require 'msf/core'
require 'msf/core/database_event'
require 'msf/core/db_import_error'
require 'msf/core/host_state'
require 'msf/core/service_state'
require 'metasploit/framework/data_service'


# The db module provides persistent storage and events. This class should be instantiated LAST
# as the active_suppport library overrides Kernel.require, slowing down all future code loads.
class Msf::DBManager
  extend Metasploit::Framework::Require

  # Default proto for making new `Mdm::Service`s. This should probably be a
  # const on `Mdm::Service`
  DEFAULT_SERVICE_PROTO = "tcp"

  autoload :Adapter, 'msf/core/db_manager/adapter'
  autoload :Client, 'msf/core/db_manager/client'
  autoload :Connection, 'msf/core/db_manager/connection'
  autoload :Cred, 'msf/core/db_manager/cred'
  autoload :DbExport, 'msf/core/db_manager/db_export'
  autoload :Event, 'msf/core/db_manager/event'
  autoload :ExploitAttempt, 'msf/core/db_manager/exploit_attempt'
  autoload :ExploitedHost, 'msf/core/db_manager/exploited_host'
  autoload :Host, 'msf/core/db_manager/host'
  autoload :HostDetail, 'msf/core/db_manager/host_detail'
  autoload :HostTag, 'msf/core/db_manager/host_tag'
  autoload :Import, 'msf/core/db_manager/import'
  autoload :ImportMsfXml, 'msf/core/db_manager/import_msf_xml'
  autoload :IPAddress, 'msf/core/db_manager/ip_address'
  autoload :Login, 'msf/core/db_manager/login'
  autoload :Loot, 'msf/core/db_manager/loot'
  autoload :Migration, 'msf/core/db_manager/migration'
  autoload :ModuleCache, 'msf/core/db_manager/module_cache'
  autoload :Note, 'msf/core/db_manager/note'
  autoload :Ref, 'msf/core/db_manager/ref'
  autoload :Report, 'msf/core/db_manager/report'
  autoload :Route, 'msf/core/db_manager/route'
  autoload :Service, 'msf/core/db_manager/service'
  autoload :Session, 'msf/core/db_manager/session'
  autoload :SessionEvent, 'msf/core/db_manager/session_event'
  autoload :Task, 'msf/core/db_manager/task'
  autoload :User, 'msf/core/db_manager/user'
  autoload :Vuln, 'msf/core/db_manager/vuln'
  autoload :VulnAttempt, 'msf/core/db_manager/vuln_attempt'
  autoload :VulnDetail, 'msf/core/db_manager/vuln_detail'
  autoload :WMAP, 'msf/core/db_manager/wmap'
  autoload :Web, 'msf/core/db_manager/web'
  autoload :Workspace, 'msf/core/db_manager/workspace'

  optionally_include_metasploit_credential_creation

  # Interface must be included first
  include Metasploit::Framework::DataService

  include Msf::DBManager::Adapter
  include Msf::DBManager::Client
  include Msf::DBManager::Connection
  include Msf::DBManager::Cred
  include Msf::DBManager::DbExport
  include Msf::DBManager::Event
  include Msf::DBManager::ExploitAttempt
  include Msf::DBManager::ExploitedHost
  include Msf::DBManager::Host
  include Msf::DBManager::HostDetail
  include Msf::DBManager::HostTag
  include Msf::DBManager::Import
  include Msf::DBManager::IPAddress
  include Msf::DBManager::Login
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
  include Msf::DBManager::Task
  include Msf::DBManager::User
  include Msf::DBManager::Vuln
  include Msf::DBManager::VulnAttempt
  include Msf::DBManager::VulnDetail
  include Msf::DBManager::WMAP
  include Msf::DBManager::Web
  include Msf::DBManager::Workspace

  # Provides :framework and other accessors
  include Msf::Framework::Offspring

  def name
    'local_db_service'
  end

  def is_local?
    true
  end

  #
  # Attributes
  #

  # Stores the error message for why the db was not loaded
  attr_accessor :error

  # Returns true if the prerequisites have been installed
  attr_accessor :usable

  #
  # initialize
  #

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

    return initialize_database_support
  end

  #
  # Instance Methods
  #

  #
  # Determines if the database is functional
  #
  def check
  ::ActiveRecord::Base.connection_pool.with_connection {
    res = ::Mdm::Host.first
  }
  end

  #
  # Do what is necessary to load our database support
  #
  def initialize_database_support
    begin
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

    true
  end

  def init_db(opts)

    init_success = false

    # Append any migration paths necessary to bring the database online
    if opts['DatabaseMigrationPaths']
      opts['DatabaseMigrationPaths'].each do |migrations_path|
        ActiveRecord::Migrator.migrations_paths << migrations_path
      end
    end

    if connection_established?
      after_establish_connection
    else
      configuration_pathname = Metasploit::Framework::Database.configurations_pathname(path: opts['DatabaseYAML'])

      if configuration_pathname.nil?
        self.error = "No database YAML file"
      else
        if configuration_pathname.readable?
          # parse specified database YAML file
          dbinfo = YAML.load_file(configuration_pathname) || {}
          dbenv  = opts['DatabaseEnv'] || Rails.env
          db     = dbinfo[dbenv]
        else
          elog("Warning, #{configuration_pathname} is not readable. Try running as root or chmod.")
        end

        if not db
          elog("No database definition for environment #{dbenv}")
        else
          init_success = connect(db)
        end
      end
    end

    # framework.db.active will be true if after_establish_connection ran directly when connection_established? was
    # already true or if framework.db.connect called after_establish_connection.
    if !! error
      if error.to_s =~ /RubyGem version.*pg.*0\.11/i
        elog("***")
        elog("*")
        elog("* Metasploit now requires version 0.11 or higher of the 'pg' gem for database support")
        elog("* There a three ways to accomplish this upgrade:")
        elog("* 1. If you run Metasploit with your system ruby, simply upgrade the gem:")
        elog("*    $ rvmsudo gem install pg ")
        elog("* 2. Use the Community Edition web interface to apply a Software Update")
        elog("* 3. Uninstall, download the latest version, and reinstall Metasploit")
        elog("*")
        elog("***")
        elog("")
        elog("")
      end

      elog("Failed to connect to the database: #{error}")
    end

    return init_success
  end
end
