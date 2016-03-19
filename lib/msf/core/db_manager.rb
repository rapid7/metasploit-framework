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
  autoload :Event, 'msf/core/db_manager/event'
  autoload :ExploitAttempt, 'msf/core/db_manager/exploit_attempt'
  autoload :ExploitedHost, 'msf/core/db_manager/exploited_host'
  autoload :Host, 'msf/core/db_manager/host'
  autoload :HostDetail, 'msf/core/db_manager/host_detail'
  autoload :HostTag, 'msf/core/db_manager/host_tag'
  autoload :Import, 'msf/core/db_manager/import'
  autoload :ImportMsfXml, 'msf/core/db_manager/import_msf_xml'
  autoload :IPAddress, 'msf/core/db_manager/ip_address'
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
  autoload :Vuln, 'msf/core/db_manager/vuln'
  autoload :VulnAttempt, 'msf/core/db_manager/vuln_attempt'
  autoload :VulnDetail, 'msf/core/db_manager/vuln_detail'
  autoload :WMAP, 'msf/core/db_manager/wmap'
  autoload :Web, 'msf/core/db_manager/web'
  autoload :Workspace, 'msf/core/db_manager/workspace'

  optionally_include_metasploit_credential_creation

  include Msf::DBManager::Adapter
  include Msf::DBManager::Client
  include Msf::DBManager::Connection
  include Msf::DBManager::Cred
  include Msf::DBManager::Event
  include Msf::DBManager::ExploitAttempt
  include Msf::DBManager::ExploitedHost
  include Msf::DBManager::Host
  include Msf::DBManager::HostDetail
  include Msf::DBManager::HostTag
  include Msf::DBManager::Import
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

    initialize_database_support
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

    true
  end
end
