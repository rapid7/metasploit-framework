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

  autoload :Cred, 'msf/core/db_manager/cred'
  autoload :ExploitedHost, 'msf/core/db_manager/exploited_host'
  autoload :Host, 'msf/core/db_manager/host'
  autoload :Import, 'msf/core/db_manager/import'
  autoload :IPAddress, 'msf/core/db_manager/ip_address'
  autoload :ModuleCache, 'msf/core/db_manager/module_cache'
  autoload :Service, 'msf/core/db_manager/service'
  autoload :Sink, 'msf/core/db_manager/sink'
  autoload :WMAP, 'msf/core/db_manager/wmap'
  autoload :Workspace, 'msf/core/db_manager/workspace'

  optionally_include_metasploit_credential_creation

  include Msf::DBManager::Cred
  include Msf::DBManager::ExploitedHost
  include Msf::DBManager::Host
  include Msf::DBManager::Import
  include Msf::DBManager::ImportMsfXml
  include Msf::DBManager::IPAddress
  include Msf::DBManager::Migration
  include Msf::DBManager::ModuleCache
  include Msf::DBManager::Service
  include Msf::DBManager::Sink
  include Msf::DBManager::WMAP
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

  # Returns a session based on opened_time, host address, and workspace
  # (or returns nil)
  def get_session(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts[:workspace] || opts[:wspace] || workspace
    addr   = opts[:addr] || opts[:address] || opts[:host] || return
    host = get_host(:workspace => wspace, :host => addr)
    time = opts[:opened_at] || opts[:created_at] || opts[:time] || return
    ::Mdm::Session.find_by_host_id_and_opened_at(host.id, time)
  }
  end

  # @note The Mdm::Session#desc will be truncated to 255 characters.
  # @todo https://www.pivotaltracker.com/story/show/48249739
  #
  # @overload report_session(opts)
  #   Creates an Mdm::Session from Msf::Session. If +via_exploit+ is set on the
  #   +session+, then an Mdm::Vuln and Mdm::ExploitAttempt is created for the
  #   session's host.  The Mdm::Host for the +session_host+ is created using
  #   The session.session_host, +session.arch+ (if +session+ responds to arch),
  #   and the workspace derived from opts or the +session+.  The Mdm::Session is
  #   assumed to be +last_seen+ and +opened_at+ at the time report_session is
  #   called.  +session.exploit_datastore['ParentModule']+ is used for the
  #   Mdm::Session#via_exploit if +session.via_exploit+ is
  #   'exploit/multi/handler'.
  #
  #   @param opts [Hash{Symbol => Object}] options
  #   @option opt [Msf::Session, #datastore, #platform, #type, #via_exploit, #via_payload] :session
  #     The in-memory session to persist to the database.
  #   @option opts [Mdm::Workspace] :workspace The workspace for in which the
  #     :session host is contained.  Also used as the workspace for the
  #     Mdm::ExploitAttempt and Mdm::Vuln.  Defaults to Mdm::Worksapce with
  #     Mdm::Workspace#name equal to +session.workspace+.
  #   @return [nil] if {Msf::DBManager#active} is +false+.
  #   @return [Mdm::Session] if session is saved
  #   @raise [ArgumentError] if :session is not an {Msf::Session}.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved, in which case, the Mdm::ExploitAttempt and Mdm::Vuln will not be
  #     created, but the Mdm::Host will have been.   (There is no transaction
  #       to rollback the Mdm::Host creation.)
  #   @see #find_or_create_host
  #   @see #normalize_host
  #   @see #report_exploit_success
  #   @see #report_vuln
  #
  # @overload report_session(opts)
  #   Creates an Mdm::Session from Mdm::Host.
  #
  #   @param opts [Hash{Symbol => Object}] options
  #   @option opts [DateTime, Time] :closed_at The date and time the sesion was
  #     closed.
  #   @option opts [String] :close_reason Reason the session was closed.
  #   @option opts [Hash] :datastore {Msf::DataStore#to_h}.
  #   @option opts [String] :desc Session description.  Will be truncated to 255
  #     characters.
  #   @option opts [Mdm::Host] :host The host on which the session was opened.
  #   @option opts [DateTime, Time] :last_seen The last date and time the
  #     session was seen to be open.  Defaults to :closed_at's value.
  #   @option opts [DateTime, Time] :opened_at The date and time that the
  #     session was opened.
  #   @option opts [String] :platform The platform of the host.
  #   @option opts [Array] :routes ([]) The routes through the session for
  #     pivoting.
  #   @option opts [String] :stype Session type.
  #   @option opts [String] :via_exploit The {Msf::Module#fullname} of the
  #     exploit that was used to open the session.
  #   @option option [String] :via_payload the {MSf::Module#fullname} of the
  #     payload sent to the host when the exploit was successful.
  #   @return [nil] if {Msf::DBManager#active} is +false+.
  #   @return [Mdm::Session] if session is saved.
  #   @raise [ArgumentError] if :host is not an Mdm::Host.
  #   @raise [ActiveRecord::RecordInvalid] if session is invalid and cannot be
  #     saved.
  #
  # @raise ArgumentError if :host and :session is +nil+
  def report_session(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    if opts[:session]
      raise ArgumentError.new("Invalid :session, expected Msf::Session") unless opts[:session].kind_of? Msf::Session
      session = opts[:session]
      wspace = opts[:workspace] || find_workspace(session.workspace)
      h_opts = { }
      h_opts[:host]      = normalize_host(session)
      h_opts[:arch]      = session.arch if session.respond_to?(:arch) and session.arch
      h_opts[:workspace] = wspace
      host = find_or_create_host(h_opts)
      sess_data = {
          :host_id     => host.id,
          :stype       => session.type,
          :desc        => session.info,
          :platform    => session.platform,
          :via_payload => session.via_payload,
          :via_exploit => session.via_exploit,
          :routes      => [],
          :datastore   => session.exploit_datastore.to_h,
          :port        => session.session_port,
          :opened_at   => Time.now.utc,
          :last_seen   => Time.now.utc,
          :local_id    => session.sid
      }
    elsif opts[:host]
      raise ArgumentError.new("Invalid :host, expected Host object") unless opts[:host].kind_of? ::Mdm::Host
      host = opts[:host]
      sess_data = {
        :host_id => host.id,
        :stype => opts[:stype],
        :desc => opts[:desc],
        :platform => opts[:platform],
        :via_payload => opts[:via_payload],
        :via_exploit => opts[:via_exploit],
        :routes => opts[:routes] || [],
        :datastore => opts[:datastore],
        :opened_at => opts[:opened_at],
        :closed_at => opts[:closed_at],
        :last_seen => opts[:last_seen] || opts[:closed_at],
        :close_reason => opts[:close_reason],
      }
    else
      raise ArgumentError.new("Missing option :session or :host")
    end
    ret = {}

    # Truncate the session data if necessary
    if sess_data[:desc]
      sess_data[:desc] = sess_data[:desc][0,255]
    end

    # In the case of multi handler we cannot yet determine the true
    # exploit responsible. But we can at least show the parent versus
    # just the generic handler:
    if session and session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
      sess_data[:via_exploit] = sess_data[:datastore]['ParentModule']
    end

    s = ::Mdm::Session.new(sess_data)
    s.save!

    if session and session.exploit_task and session.exploit_task.record
      session_task =  session.exploit_task.record
      if session_task.class == Mdm::Task
        Mdm::TaskSession.create(:task => session_task, :session => s )
      end
    end


    if opts[:session]
      session.db_record = s
    end

    # If this is a live session, we know the host is vulnerable to something.
    if opts[:session] and session.via_exploit
      mod = framework.modules.create(session.via_exploit)

      if session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
        mod_fullname = sess_data[:datastore]['ParentModule']
        mod_name = ::Mdm::Module::Detail.find_by_fullname(mod_fullname).name
      else
        mod_name = mod.name
        mod_fullname = mod.fullname
      end

      vuln_info = {
        :host => host.address,
        :name => mod_name,
        :refs => mod.references,
        :workspace => wspace,
        :exploited_at => Time.now.utc,
        :info => "Exploited by #{mod_fullname} to create Session #{s.id}"
      }

      port    = session.exploit_datastore["RPORT"]
      service = (port ? host.services.find_by_port(port.to_i) : nil)

      vuln_info[:service] = service if service

      vuln = framework.db.report_vuln(vuln_info)

      if session.via_exploit == "exploit/multi/handler" and sess_data[:datastore]['ParentModule']
        via_exploit = sess_data[:datastore]['ParentModule']
      else
        via_exploit = session.via_exploit
      end
      attempt_info = {
        :timestamp   => Time.now.utc,
        :workspace   => wspace,
        :module      => via_exploit,
        :username    => session.username,
        :refs        => mod.references,
        :session_id  => s.id,
        :host        => host,
        :service     => service,
        :vuln        => vuln
      }

      framework.db.report_exploit_success(attempt_info)

    end

    s
  }
  end

  #
  # Record a session event in the database
  #
  # opts MUST contain one of:
  # +:session+:: the Msf::Session OR the ::Mdm::Session we are reporting
  # +:etype+::   event type, enum: command, output, upload, download, filedelete
  #
  # opts may contain
  # +:output+::      the data for an output event
  # +:command+::     the data for an command event
  # +:remote_path+:: path to the associated file for upload, download, and filedelete events
  # +:local_path+::  path to the associated file for upload, and download
  #
  def report_session_event(opts)
    return if not active
    raise ArgumentError.new("Missing required option :session") if opts[:session].nil?
    raise ArgumentError.new("Expected an :etype") unless opts[:etype]
    session = nil

  ::ActiveRecord::Base.connection_pool.with_connection {
    if opts[:session].respond_to? :db_record
      session = opts[:session].db_record
      if session.nil?
        # The session doesn't have a db_record which means
        #  a) the database wasn't connected at session registration time
        # or
        #  b) something awful happened and the report_session call failed
        #
        # Either way, we can't do anything with this session as is, so
        # log a warning and punt.
        wlog("Warning: trying to report a session_event for a session with no db_record (#{opts[:session].sid})")
        return
      end
      event_data = { :created_at => Time.now }
    else
      session = opts[:session]
      event_data = { :created_at => opts[:created_at] }
    end

    event_data[:session_id] = session.id
    [:remote_path, :local_path, :output, :command, :etype].each do |attr|
      event_data[attr] = opts[attr] if opts[attr]
    end

    s = ::Mdm::SessionEvent.create(event_data)
  }
  end

  def report_session_route(session, route)
    return if not active
    if session.respond_to? :db_record
      s = session.db_record
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

  ::ActiveRecord::Base.connection_pool.with_connection {

    subnet, netmask = route.split("/")
    s.routes.create(:subnet => subnet, :netmask => netmask)
  }
  end

  def report_session_route_remove(session, route)
    return if not active
    if session.respond_to? :db_record
      s = session.db_record
    else
      s = session
    end
    unless s.respond_to?(:routes)
      raise ArgumentError.new("Invalid :session, expected Session object got #{session.class}")
    end

  ::ActiveRecord::Base.connection_pool.with_connection {
    subnet, netmask = route.split("/")
    r = s.routes.find_by_subnet_and_netmask(subnet, netmask)
    r.destroy if r
  }
  end


  def report_exploit_success(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {

    wspace = opts.delete(:workspace) || workspace
    mrefs  = opts.delete(:refs) || return
    host   = opts.delete(:host)
    port   = opts.delete(:port)
    prot   = opts.delete(:proto)
    svc    = opts.delete(:service)
    vuln   = opts.delete(:vuln)

    timestamp = opts.delete(:timestamp)
    username  = opts.delete(:username)
    mname     = opts.delete(:module)

    # Look up or generate the host as appropriate
    if not (host and host.kind_of? ::Mdm::Host)
      if svc.kind_of? ::Mdm::Service
        host = svc.host
      else
        host = report_host(:workspace => wspace, :address => host )
      end
    end

    # Bail if we dont have a host object
    return if not host

    # Look up or generate the service as appropriate
    if port and svc.nil?
      svc = report_service(:workspace => wspace, :host => host, :port => port, :proto => prot ) if port
    end

    if not vuln
      # Create a references map from the module list
      ref_objs = ::Mdm::Ref.where(:name => mrefs.map { |ref|
        if ref.respond_to?(:ctx_id) and ref.respond_to?(:ctx_val)
          "#{ref.ctx_id}-#{ref.ctx_val}"
        else
          ref.to_s
        end
      })

      # Try find a matching vulnerability
      vuln = find_vuln_by_refs(ref_objs, host, svc)
    end

    # We have match, lets create a vuln_attempt record
    if vuln
      attempt_info = {
        :vuln_id      => vuln.id,
        :attempted_at => timestamp || Time.now.utc,
        :exploited    => true,
        :username     => username  || "unknown",
        :module       => mname
      }

      attempt_info[:session_id] = opts[:session_id] if opts[:session_id]
      attempt_info[:loot_id]    = opts[:loot_id]    if opts[:loot_id]

      vuln.vuln_attempts.create(attempt_info)

      # Correct the vuln's associated service if necessary
      if svc and vuln.service_id.nil?
        vuln.service = svc
        vuln.save
      end
    end

    # Report an exploit attempt all the same
    attempt_info = {
      :attempted_at => timestamp || Time.now.utc,
      :exploited    => true,
      :username     => username  || "unknown",
      :module       => mname
    }

    attempt_info[:vuln_id]    = vuln.id           if vuln
    attempt_info[:session_id] = opts[:session_id] if opts[:session_id]
    attempt_info[:loot_id]    = opts[:loot_id]    if opts[:loot_id]

    if svc
      attempt_info[:port]  = svc.port
      attempt_info[:proto] = svc.proto
    end

    if port and svc.nil?
      attempt_info[:port]  = port
      attempt_info[:proto] = prot || "tcp"
    end

    host.exploit_attempts.create(attempt_info)
  }
  end

  def report_exploit_failure(opts)

  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    mrefs  = opts.delete(:refs) || return
    host   = opts.delete(:host)
    port   = opts.delete(:port)
    prot   = opts.delete(:proto)
    svc    = opts.delete(:service)
    vuln   = opts.delete(:vuln)

    timestamp  = opts.delete(:timestamp)
    freason    = opts.delete(:fail_reason)
    fdetail    = opts.delete(:fail_detail)
    username   = opts.delete(:username)
    mname      = opts.delete(:module)

    # Look up the host as appropriate
    if not (host and host.kind_of? ::Mdm::Host)
      if svc.kind_of? ::Mdm::Service
        host = svc.host
      else
        host = get_host( :workspace => wspace, :address => host )
      end
    end

    # Bail if we dont have a host object
    return if not host

    # Look up the service as appropriate
    if port and svc.nil?
      prot ||= "tcp"
      svc = get_service(wspace, host, prot, port) if port
    end

    if not vuln
      # Create a references map from the module list
      ref_objs = ::Mdm::Ref.where(:name => mrefs.map { |ref|
        if ref.respond_to?(:ctx_id) and ref.respond_to?(:ctx_val)
          "#{ref.ctx_id}-#{ref.ctx_val}"
        else
          ref.to_s
        end
      })

      # Try find a matching vulnerability
      vuln = find_vuln_by_refs(ref_objs, host, svc)
    end

    # Report a vuln_attempt if we found a match
    if vuln
      attempt_info = {
        :attempted_at => timestamp || Time.now.utc,
        :exploited    => false,
        :fail_reason  => freason,
        :fail_detail  => fdetail,
        :username     => username  || "unknown",
        :module       => mname
      }

      vuln.vuln_attempts.create(attempt_info)
    end

    # Report an exploit attempt all the same
    attempt_info = {
      :attempted_at => timestamp || Time.now.utc,
      :exploited    => false,
      :username     => username  || "unknown",
      :module       => mname,
      :fail_reason  => freason,
      :fail_detail  => fdetail
    }

    attempt_info[:vuln_id] = vuln.id if vuln

    if svc
      attempt_info[:port]  = svc.port
      attempt_info[:proto] = svc.proto
    end

    if port and svc.nil?
      attempt_info[:port]  = port
      attempt_info[:proto] = prot || "tcp"
    end

    host.exploit_attempts.create(attempt_info)
  }
  end


  def report_vuln_attempt(vuln, opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    return if not vuln
    info = {}

    # Opts can be keyed by strings or symbols
    ::Mdm::VulnAttempt.column_names.each do |kn|
      k = kn.to_sym
      next if ['id', 'vuln_id'].include?(kn)
      info[k] = opts[kn] if opts[kn]
      info[k] = opts[k]  if opts[k]
    end

    return unless info[:attempted_at]

    vuln.vuln_attempts.create(info)
  }
  end

  def report_exploit_attempt(host, opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    return if not host
    info = {}

    # Opts can be keyed by strings or symbols
    ::Mdm::VulnAttempt.column_names.each do |kn|
      k = kn.to_sym
      next if ['id', 'host_id'].include?(kn)
      info[k] = opts[kn] if opts[kn]
      info[k] = opts[k]  if opts[k]
    end

    host.exploit_attempts.create(info)
  }
  end

  def get_client(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    host   = get_host(:workspace => wspace, :host => opts[:host]) || return
    client = host.clients.where({:ua_string => opts[:ua_string]}).first()
    return client
  }
  end

  def find_or_create_client(opts)
    report_client(opts)
  end

  #
  # Report a client running on a host.
  #
  # opts MUST contain
  # +:ua_string+::  the value of the User-Agent header
  # +:host+::       the host where this client connected from, can be an ip address or a Host object
  #
  # opts can contain
  # +:ua_name+::    one of the Msf::HttpClients constants
  # +:ua_ver+::     detected version of the given client
  # +:campaign+::   an id or Campaign object
  #
  # Returns a Client.
  #
  def report_client(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    addr = opts.delete(:host) || return
    wspace = opts.delete(:workspace) || workspace
    report_host(:workspace => wspace, :host => addr)

    ret = {}

    host = get_host(:workspace => wspace, :host => addr)
    client = host.clients.find_or_initialize_by_ua_string(opts[:ua_string])

    opts[:ua_string] = opts[:ua_string].to_s

    campaign = opts.delete(:campaign)
    if campaign
      case campaign
      when Campaign
        opts[:campaign_id] = campaign.id
      else
        opts[:campaign_id] = campaign
      end
    end

    opts.each { |k,v|
      if (client.attribute_names.include?(k.to_s))
        client[k] = v
      else
        dlog("Unknown attribute for Client: #{k}")
      end
    }
    if (client and client.changed?)
      client.save!
    end
    ret[:client] = client
  }
  end

  #
  # This method iterates the vulns table calling the supplied block with the
  # vuln instance of each entry.
  #
  def each_vuln(wspace=workspace,&block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.vulns.each do |vulns|
      block.call(vulns)
    end
  }
  end

  #
  # This methods returns a list of all vulnerabilities in the database
  #
  def vulns(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.vulns
  }
  end

  #
  # This method iterates the notes table calling the supplied block with the
  # note instance of each entry.
  #
  def each_note(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.notes.each do |note|
      block.call(note)
    end
  }
  end

  #
  # Find or create a note matching this type/data
  #
  def find_or_create_note(opts)
    report_note(opts)
  end

  #
  # Report a Note to the database.  Notes can be tied to a ::Mdm::Workspace, Host, or Service.
  #
  # opts MUST contain
  # +:type+::  The type of note, e.g. smb_peer_os
  #
  # opts can contain
  # +:workspace+::  the workspace to associate with this Note
  # +:host+::       an IP address or a Host object to associate with this Note
  # +:service+::    a Service object to associate with this Note
  # +:data+::       whatever it is you're making a note of
  # +:port+::       along with +:host+ and +:proto+, a service to associate with this Note
  # +:proto+::      along with +:host+ and +:port+, a service to associate with this Note
  # +:update+::     what to do in case a similar Note exists, see below
  #
  # The +:update+ option can have the following values:
  # +:unique+::       allow only a single Note per +:host+/+:type+ pair
  # +:unique_data+::  like +:uniqe+, but also compare +:data+
  # +:insert+::       always insert a new Note even if one with identical values exists
  #
  # If the provided +:host+ is an IP address and does not exist in the
  # database, it will be created.  If +:workspace+, +:host+ and +:service+
  # are all omitted, the new Note will be associated with the current
  # workspace.
  #
  def report_note(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end
    seen = opts.delete(:seen) || false
    crit = opts.delete(:critical) || false
    host = nil
    addr = nil
    # Report the host so it's there for the Proc to use below
    if opts[:host]
      if opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
      else
        addr = normalize_host(opts[:host])
        host = report_host({:workspace => wspace, :host => addr})
      end
      # Do the same for a service if that's also included.
      if (opts[:port])
        proto = nil
        sname = nil
        case opts[:proto].to_s.downcase # Catch incorrect usages
        when 'tcp','udp'
          proto = opts[:proto]
          sname = opts[:sname] if opts[:sname]
        when 'dns','snmp','dhcp'
          proto = 'udp'
          sname = opts[:proto]
        else
          proto = 'tcp'
          sname = opts[:proto]
        end
        sopts = {
          :workspace => wspace,
          :host  => host,
          :port  => opts[:port],
          :proto => proto
        }
        sopts[:name] = sname if sname
        report_service(sopts)
      end
    end
    # Update Modes can be :unique, :unique_data, :insert
    mode = opts[:update] || :unique

    ret = {}

    if addr and not host
      host = get_host(:workspace => wspace, :host => addr)
    end
    if host and (opts[:port] and opts[:proto])
      service = get_service(wspace, host, opts[:proto], opts[:port])
    elsif opts[:service] and opts[:service].kind_of? ::Mdm::Service
      service = opts[:service]
    end
=begin
    if host
      host.updated_at = host.created_at
      host.state      = HostState::Alive
      host.save!
    end
=end
    ntype  = opts.delete(:type) || opts.delete(:ntype) || (raise RuntimeError, "A note :type or :ntype is required")
    data   = opts[:data]
    note   = nil

    conditions = { :ntype => ntype }
    conditions[:host_id] = host[:id] if host
    conditions[:service_id] = service[:id] if service

    case mode
    when :unique
      note      = wspace.notes.where(conditions).first_or_initialize
      note.data = data
    when :unique_data
      notes = wspace.notes.where(conditions)

      # Don't make a new Note with the same data as one that already
      # exists for the given: type and (host or service)
      notes.each do |n|
        # Compare the deserialized data from the table to the raw
        # data we're looking for.  Because of the serialization we
        # can't do this easily or reliably in SQL.
        if n.data == data
          note = n
          break
        end
      end
      if not note
        # We didn't find one with the data we're looking for, make
        # a new one.
        note = wspace.notes.new(conditions.merge(:data => data))
      end
    else
      # Otherwise, assume :insert, which means always make a new one
      note = wspace.notes.new
      if host
        note.host_id = host[:id]
      end
      if opts[:service] and opts[:service].kind_of? ::Mdm::Service
        note.service_id = opts[:service][:id]
      end
      note.seen     = seen
      note.critical = crit
      note.ntype    = ntype
      note.data     = data
    end
    msf_import_timestamps(opts,note)
    note.save!
    ret[:note] = note
  }
  end

  #
  # This methods returns a list of all notes in the database
  #
  def notes(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.notes
  }
  end

  # This is only exercised by MSF3 XML importing for now. Needs the wait
  # conditions and return hash as well.
  def report_host_tag(opts)
    name = opts.delete(:name)
    raise DBImportError.new("Missing required option :name") unless name
    addr = opts.delete(:addr)
    raise DBImportError.new("Missing required option :addr") unless addr
    wspace = opts.delete(:wspace)
    raise DBImportError.new("Missing required option :wspace") unless wspace
  ::ActiveRecord::Base.connection_pool.with_connection {
    if wspace.kind_of? String
      wspace = find_workspace(wspace)
    end

    host = nil
    report_host(:workspace => wspace, :address => addr)


    host = get_host(:workspace => wspace, :address => addr)
    desc = opts.delete(:desc)
    summary = opts.delete(:summary)
    detail = opts.delete(:detail)
    crit = opts.delete(:crit)
    possible_tags = Mdm::Tag.includes(:hosts).where("hosts.workspace_id = ? and tags.name = ?", wspace.id, name).order("tags.id DESC").limit(1)
    tag = (possible_tags.blank? ? Mdm::Tag.new : possible_tags.first)
    tag.name = name
    tag.desc = desc
    tag.report_summary = !!summary
    tag.report_detail = !!detail
    tag.critical = !!crit
    tag.hosts = tag.hosts | [host]
    tag.save! if tag.changed?
  }
  end

  #
  # Find or create a vuln matching this service/name
  #
  def find_or_create_vuln(opts)
    report_vuln(opts)
  end

  #
  # opts MUST contain
  # +:host+:: the host where this vulnerability resides
  # +:name+:: the friendly name for this vulnerability (title)
  #
  # opts can contain
  # +:info+::   a human readable description of the vuln, free-form text
  # +:refs+::   an array of Ref objects or string names of references
  # +:details:: a hash with :key pointed to a find criteria hash and the rest containing VulnDetail fields
  #
  def report_vuln(opts)
    return if not active
    raise ArgumentError.new("Missing required option :host") if opts[:host].nil?
    raise ArgumentError.new("Deprecated data column for vuln, use .info instead") if opts[:data]
    name = opts[:name] || return
    info = opts[:info]

  ::ActiveRecord::Base.connection_pool.with_connection {

    wspace = opts.delete(:workspace) || workspace
    exploited_at = opts[:exploited_at] || opts["exploited_at"]
    details = opts.delete(:details)
    rids = opts.delete(:ref_ids)

    if opts[:refs]
      rids ||= []
      opts[:refs].each do |r|
        if (r.respond_to?(:ctx_id)) and (r.respond_to?(:ctx_val))
          r = "#{r.ctx_id}-#{r.ctx_val}"
        end
        rids << find_or_create_ref(:name => r)
      end
    end

    host = nil
    addr = nil
    if opts[:host].kind_of? ::Mdm::Host
      host = opts[:host]
    else
      host = report_host({:workspace => wspace, :host => opts[:host]})
      addr = normalize_host(opts[:host])
    end

    ret = {}

    # Truncate the info field at the maximum field length
    if info
      info = info[0,65535]
    end

    # Truncate the name field at the maximum field length
    name = name[0,255]

    # Placeholder for the vuln object
    vuln = nil

    # Identify the associated service
    service = opts.delete(:service)

    # Treat port zero as no service
    if service or opts[:port].to_i > 0

      if not service
        proto = nil
        case opts[:proto].to_s.downcase # Catch incorrect usages, as in report_note
        when 'tcp','udp'
          proto = opts[:proto]
        when 'dns','snmp','dhcp'
          proto = 'udp'
          sname = opts[:proto]
        else
          proto = 'tcp'
          sname = opts[:proto]
        end

        service = host.services.find_or_create_by_port_and_proto(opts[:port].to_i, proto)
      end

      # Try to find an existing vulnerability with the same service & references
      # If there are multiple matches, choose the one with the most matches
      # If a match is found on a vulnerability with no associated service,
      # update that vulnerability with our service information. This helps
      # prevent dupes of the same vuln found by both local patch and
      # service detection.
      if rids and rids.length > 0
        vuln = find_vuln_by_refs(rids, host, service)
        vuln.service = service if vuln
      end
    else
      # Try to find an existing vulnerability with the same host & references
      # If there are multiple matches, choose the one with the most matches
      if rids and rids.length > 0
        vuln = find_vuln_by_refs(rids, host)
      end
    end

    # Try to match based on vuln_details records
    if not vuln and opts[:details_match]
      vuln = find_vuln_by_details(opts[:details_match], host, service)
      if vuln and service and not vuln.service
        vuln.service = service
      end
    end

    # No matches, so create a new vuln record
    unless vuln
      if service
        vuln = service.vulns.find_by_name(name)
      else
        vuln = host.vulns.find_by_name(name)
      end

      unless vuln

        vinf = {
          :host_id => host.id,
          :name    => name,
          :info    => info
        }

        vinf[:service_id] = service.id if service
        vuln = Mdm::Vuln.create(vinf)
      end
    end

    # Set the exploited_at value if provided
    vuln.exploited_at = exploited_at if exploited_at

    # Merge the references
    if rids
      vuln.refs << (rids - vuln.refs)
    end

    # Finalize
    if vuln.changed?
      msf_import_timestamps(opts,vuln)
      vuln.save!
    end

    # Handle vuln_details parameters
    report_vuln_details(vuln, details) if details

    vuln
  }
  end

  def find_vuln_by_refs(refs, host, service=nil)

    vuln = nil

    # Try to find an existing vulnerability with the same service & references
    # If there are multiple matches, choose the one with the most matches
    if service
      refs_ids = refs.map{|x| x.id }
      vuln = service.vulns.find(:all, :include => [:refs], :conditions => { 'refs.id' => refs_ids }).sort { |a,b|
        ( refs_ids - a.refs.map{|x| x.id } ).length <=> ( refs_ids - b.refs.map{|x| x.id } ).length
      }.first
    end

    # Return if we matched based on service
    return vuln if vuln

    # Try to find an existing vulnerability with the same host & references
    # If there are multiple matches, choose the one with the most matches
    refs_ids = refs.map{|x| x.id }
    vuln = host.vulns.find(:all, :include => [:refs], :conditions => { 'service_id' => nil, 'refs.id' => refs_ids }).sort { |a,b|
      ( refs_ids - a.refs.map{|x| x.id } ).length <=> ( refs_ids - b.refs.map{|x| x.id } ).length
    }.first

    return vuln
  end


  def find_vuln_by_details(details_map, host, service=nil)

    # Create a modified version of the criteria in order to match against
    # the joined version of the fields

    crit = {}
    details_map.each_pair do |k,v|
      crit[ "vuln_details.#{k}" ] = v
    end

    vuln = nil

    if service
      vuln = service.vulns.find(:first, :include => [:vuln_details], :conditions => crit)
    end

    # Return if we matched based on service
    return vuln if vuln

    # Prevent matches against other services
    crit["vulns.service_id"] = nil if service
    vuln = host.vulns.find(:first, :include => [:vuln_details], :conditions => crit)

    return vuln
  end

  def get_vuln(wspace, host, service, name, data='')
    raise RuntimeError, "Not workspace safe: #{caller.inspect}"
  ::ActiveRecord::Base.connection_pool.with_connection {
    vuln = nil
    if (service)
      vuln = ::Mdm::Vuln.find.where("name = ? and service_id = ? and host_id = ?", name, service.id, host.id).order("vulns.id DESC").first()
    else
      vuln = ::Mdm::Vuln.find.where("name = ? and host_id = ?", name, host.id).first()
    end

    return vuln
  }
  end

  #
  # Find or create a reference matching this name
  #
  def find_or_create_ref(opts)
    ret = {}
    ret[:ref] = get_ref(opts[:name])
    return ret[:ref] if ret[:ref]

  ::ActiveRecord::Base.connection_pool.with_connection {
    ref = ::Mdm::Ref.find_or_initialize_by_name(opts[:name])
    if ref and ref.changed?
      ref.save!
    end
    ret[:ref] = ref
  }
  end

  def get_ref(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    ::Mdm::Ref.find_by_name(name)
  }
  end

  #
  # Populate the vuln_details table with additional
  # information, matched by a specific criteria
  #
  def report_vuln_details(vuln, details)
  ::ActiveRecord::Base.connection_pool.with_connection {
    detail = ::Mdm::VulnDetail.where(( details.delete(:key) || {} ).merge(:vuln_id => vuln.id)).first
    if detail
      details.each_pair do |k,v|
        detail[k] = v
      end
      detail.save! if detail.changed?
      detail
    else
      detail = ::Mdm::VulnDetail.create(details.merge(:vuln_id => vuln.id))
    end
  }
  end

  #
  # Update vuln_details records en-masse based on specific criteria
  # Note that this *can* update data across workspaces
  #
  def update_vuln_details(details)
  ::ActiveRecord::Base.connection_pool.with_connection {
    criteria = details.delete(:key) || {}
    ::Mdm::VulnDetail.update(key, details)
  }
  end

  #
  # Populate the host_details table with additional
  # information, matched by a specific criteria
  #
  def report_host_details(host, details)
  ::ActiveRecord::Base.connection_pool.with_connection {

    detail = ::Mdm::HostDetail.where(( details.delete(:key) || {} ).merge(:host_id => host.id)).first
    if detail
      details.each_pair do |k,v|
        detail[k] = v
      end
      detail.save! if detail.changed?
      detail
    else
      detail = ::Mdm::HostDetail.create(details.merge(:host_id => host.id))
    end
  }
  end

  # report_exploit() used to be used to track sessions and which modules
  # opened them. That information is now available with the session table
  # directly. TODO: kill this completely some day -- for now just warn if
  # some other UI is actually using it.
  def report_exploit(opts={})
    wlog("Deprecated method call: report_exploit()\n" +
      "report_exploit() options: #{opts.inspect}\n" +
      "report_exploit() call stack:\n\t#{caller.join("\n\t")}"
    )
  end

  #
  # Find a reference matching this name
  #
  def has_ref?(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Ref.find_by_name(name)
  }
  end

  #
  # Find a vulnerability matching this name
  #
  def has_vuln?(name)
  ::ActiveRecord::Base.connection_pool.with_connection {
    Mdm::Vuln.find_by_name(name)
  }
  end

  def events(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.events.find :all, :order => 'created_at ASC'
  }
  end

  def report_event(opts = {})
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    return if not wspace # Temp fix?
    uname  = opts.delete(:username)

    if ! opts[:host].kind_of? ::Mdm::Host and opts[:host]
      opts[:host] = report_host(:workspace => wspace, :host => opts[:host])
    end

    ::Mdm::Event.create(opts.merge(:workspace_id => wspace[:id], :username => uname))
  }
  end

  #
  # Loot collection
  #
  #
  # This method iterates the loot table calling the supplied block with the
  # instance of each entry.
  #
  def each_loot(wspace=workspace, &block)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.loots.each do |note|
      block.call(note)
    end
  }
  end

  #
  # Find or create a loot matching this type/data
  #
  def find_or_create_loot(opts)
    report_loot(opts)
  end

  def report_loot(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    path = opts.delete(:path) || (raise RuntimeError, "A loot :path is required")

    host = nil
    addr = nil

    # Report the host so it's there for the Proc to use below
    if opts[:host]
      if opts[:host].kind_of? ::Mdm::Host
        host = opts[:host]
      else
        host = report_host({:workspace => wspace, :host => opts[:host]})
        addr = normalize_host(opts[:host])
      end
    end

    ret = {}

    ltype  = opts.delete(:type) || opts.delete(:ltype) || (raise RuntimeError, "A loot :type or :ltype is required")
    ctype  = opts.delete(:ctype) || opts.delete(:content_type) || 'text/plain'
    name   = opts.delete(:name)
    info   = opts.delete(:info)
    data   = opts[:data]
    loot   = wspace.loots.new

    if host
      loot.host_id = host[:id]
    end
    if opts[:service] and opts[:service].kind_of? ::Mdm::Service
      loot.service_id = opts[:service][:id]
    end

    loot.path         = path
    loot.ltype        = ltype
    loot.content_type = ctype
    loot.data         = data
    loot.name         = name if name
    loot.info         = info if info
    loot.workspace    = wspace
    msf_import_timestamps(opts,loot)
    loot.save!

    ret[:loot] = loot
  }
  end

  #
  # This methods returns a list of all loot in the database
  #
  def loots(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.loots
  }
  end

  #
  # Find or create a task matching this type/data
  #
  def find_or_create_task(opts)
    report_task(opts)
  end

  def report_task(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace
    path = opts.delete(:path) || (raise RuntimeError, "A task :path is required")

    ret = {}

    user      = opts.delete(:user)
    desc      = opts.delete(:desc)
    error     = opts.delete(:error)
    info      = opts.delete(:info)
    mod       = opts.delete(:mod)
    options   = opts.delete(:options)
    prog      = opts.delete(:prog)
    result    = opts.delete(:result)
    completed_at = opts.delete(:completed_at)
    task      = wspace.tasks.new

    task.created_by = user
    task.description = desc
    task.error = error if error
    task.info = info
    task.module = mod
    task.options = options
    task.path = path
    task.progress = prog
    task.result = result if result
    msf_import_timestamps(opts,task)
    # Having blank completed_ats, while accurate, will cause unstoppable tasks.
    if completed_at.nil? || completed_at.empty?
      task.completed_at = opts[:updated_at]
    else
      task.completed_at = completed_at
    end
    task.save!
    ret[:task] = task
  }
  end

  #
  # This methods returns a list of all tasks in the database
  #
  def tasks(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.tasks
  }
  end


  # TODO This method does not attempt to find. It just creates
  # a report based on the passed params.
  def find_or_create_report(opts)
    report_report(opts)
  end

  # Creates a Report based on passed parameters. Does not handle
  # child artifacts.
  # @param opts [Hash]
  # @return [Integer] ID of created report
  def report_report(opts)
    return if not active
    created = opts.delete(:created_at)
    updated = opts.delete(:updated_at)
    state   = opts.delete(:state)

  ::ActiveRecord::Base.connection_pool.with_connection {
    report = Report.new(opts)
    report.created_at = created
    report.updated_at = updated

    unless report.valid?
      errors = report.errors.full_messages.join('; ')
      raise RuntimeError "Report to be imported is not valid: #{errors}"
    end
    report.state = :complete # Presume complete since it was exported
    report.save

    report.id
  }
  end

  # Creates a ReportArtifact based on passed parameters.
  # @param opts [Hash] of ReportArtifact attributes
  def report_artifact(opts)
    return if not active

    artifacts_dir = Report::ARTIFACT_DIR
    tmp_path = opts[:file_path]
    artifact_name = File.basename tmp_path
    new_path = File.join(artifacts_dir, artifact_name)
    created = opts.delete(:created_at)
    updated = opts.delete(:updated_at)

    unless File.exists? tmp_path
      raise DBImportError 'Report artifact file to be imported does not exist.'
    end

    unless (File.directory?(artifacts_dir) && File.writable?(artifacts_dir))
      raise DBImportError "Could not move report artifact file to #{artifacts_dir}."
    end

    if File.exists? new_path
      unique_basename = "#{(Time.now.to_f*1000).to_i}_#{artifact_name}"
      new_path = File.join(artifacts_dir, unique_basename)
    end

    FileUtils.copy(tmp_path, new_path)
    opts[:file_path] = new_path
    artifact = ReportArtifact.new(opts)
    artifact.created_at = created
    artifact.updated_at = updated

    unless artifact.valid?
      errors = artifact.errors.full_messages.join('; ')
      raise RuntimeError "Artifact to be imported is not valid: #{errors}"
    end
    artifact.save
  end

  #
  # This methods returns a list of all reports in the database
  #
  def reports(wspace=workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.reports
  }
  end

  #
  # WMAP
  # Support methods
  #

  #
  # Report a Web Site to the database.  WebSites must be tied to an existing Service
  #
  # opts MUST contain
  # +:service+:: the service object this site should be associated with
  # +:vhost+::   the virtual host name for this particular web site`
  #
  # If +:service+ is NOT specified, the following values are mandatory
  # +:host+:: the ip address of the server hosting the web site
  # +:port+:: the port number of the associated web site
  # +:ssl+::  whether or not SSL is in use on this port
  #
  # These values will be used to create new host and service records
  #
  # opts can contain
  # +:options+:: a hash of options for accessing this particular web site
  # +:info+:: if present, report the service with this info
  #
  # Duplicate records for a given host, port, vhost combination will be overwritten
  #
  def report_web_site(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection { |conn|
    wspace = opts.delete(:workspace) || workspace
    vhost  = opts.delete(:vhost)

    addr = nil
    port = nil
    name = nil
    serv = nil
    info = nil

    if opts[:service] and opts[:service].kind_of?(::Mdm::Service)
      serv = opts[:service]
    else
      addr = opts[:host]
      port = opts[:port]
      name = opts[:ssl] ? 'https' : 'http'
      info = opts[:info]
      if not (addr and port)
        raise ArgumentError, "report_web_site requires service OR host/port/ssl"
      end

      # Force addr to be the address and not hostname
      addr = Rex::Socket.getaddress(addr, true)
    end

    ret = {}

    host = serv ? serv.host : find_or_create_host(
      :workspace => wspace,
      :host      => addr,
      :state     => Msf::HostState::Alive
    )

    if host.name.to_s.empty?
      host.name = vhost
      host.save!
    end

    serv = serv ? serv : find_or_create_service(
      :workspace => wspace,
      :host      => host,
      :port      => port,
      :proto     => 'tcp',
      :state     => 'open'
    )

    # Change the service name if it is blank or it has
    # been explicitly specified.
    if opts.keys.include?(:ssl) or serv.name.to_s.empty?
      name = opts[:ssl] ? 'https' : 'http'
      serv.name = name
    end
    # Add the info if it's there.
    unless info.to_s.empty?
      serv.info = info
    end
    serv.save! if serv.changed?
=begin
    host.updated_at = host.created_at
    host.state      = HostState::Alive
    host.save!
=end

    vhost ||= host.address
    site = ::Mdm::WebSite.find_or_initialize_by_vhost_and_service_id(vhost, serv[:id])
    site.options = opts[:options] if opts[:options]

    # XXX:
    msf_import_timestamps(opts, site)
    site.save!

    ret[:web_site] = site
  }
  end

  #
  # Report a Web Page to the database.  WebPage must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+:: the web site object that this page should be associated with
  # +:path+::     the virtual host name for this particular web site
  # +:code+::     the http status code from requesting this page
  # +:headers+::  this is a HASH of headers (lowercase name as key) of ARRAYs of values
  # +:body+::     the document body of the server response
  # +:query+::    the query string after the path
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  # These values will be used to create new host, service, and web_site records
  #
  # opts can contain
  # +:cookie+::   the Set-Cookie headers, merged into a string
  # +:auth+::     the Authorization headers, merged into a string
  # +:ctype+::    the Content-Type headers, merged into a string
  # +:mtime+::    the timestamp returned from the server of the last modification time
  # +:location+:: the URL that a redirect points to
  #
  # Duplicate records for a given web_site, path, and query combination will be overwritten
  #

  def report_web_page(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace

    path    = opts[:path]
    code    = opts[:code].to_i
    body    = opts[:body].to_s
    query   = opts[:query].to_s
    headers = opts[:headers]
    site    = nil

    if not (path and code and body and headers)
      raise ArgumentError, "report_web_page requires the path, query, code, body, and headers parameters"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_page was unable to create the associated web site"
      end
    end

    ret = {}

    page = ::Mdm::WebPage.find_or_initialize_by_web_site_id_and_path_and_query(site[:id], path, query)
    page.code     = code
    page.body     = body
    page.headers  = headers
    page.cookie   = opts[:cookie] if opts[:cookie]
    page.auth     = opts[:auth]   if opts[:auth]
    page.mtime    = opts[:mtime]  if opts[:mtime]
    page.ctype    = opts[:ctype]  if opts[:ctype]
    page.location = opts[:location] if opts[:location]
    msf_import_timestamps(opts, page)
    page.save!

    ret[:web_page] = page
  }

  end


  #
  # Report a Web Form to the database.  WebForm must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+:: the web site object that this page should be associated with
  # +:path+::     the virtual host name for this particular web site
  # +:query+::    the query string that is appended to the path (not valid for GET)
  # +:method+::   the form method, one of GET, POST, or PATH
  # +:params+::   an ARRAY of all parameters and values specified in the form
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  # Duplicate records for a given web_site, path, method, and params combination will be overwritten
  #

  def report_web_form(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace

    path    = opts[:path]
    meth    = opts[:method].to_s.upcase
    para    = opts[:params]
    quer    = opts[:query].to_s
    site    = nil

    if not (path and meth)
      raise ArgumentError, "report_web_form requires the path and method parameters"
    end

    if not %W{GET POST PATH}.include?(meth)
      raise ArgumentError, "report_web_form requires the method to be one of GET, POST, PATH"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_form was unable to create the associated web site"
      end
    end

    ret = {}

    # Since one of our serialized fields is used as a unique parameter, we must do the final
    # comparisons through ruby and not SQL.

    form = nil
    ::Mdm::WebForm.find_all_by_web_site_id_and_path_and_method_and_query(site[:id], path, meth, quer).each do |xform|
      if xform.params == para
        form = xform
        break
      end
    end
    if not form
      form = ::Mdm::WebForm.new
      form.web_site_id = site[:id]
      form.path        = path
      form.method      = meth
      form.params      = para
      form.query       = quer
    end

    msf_import_timestamps(opts, form)
    form.save!
    ret[:web_form] = form
  }
  end


  #
  # Report a Web Vuln to the database.  WebVuln must be tied to an existing Web Site
  #
  # opts MUST contain
  # +:web_site+::  the web site object that this page should be associated with
  # +:path+::      the virtual host name for this particular web site
  # +:query+::     the query string appended to the path (not valid for GET method flaws)
  # +:method+::    the form method, one of GET, POST, or PATH
  # +:params+::    an ARRAY of all parameters and values specified in the form
  # +:pname+::     the specific field where the vulnerability occurs
  # +:proof+::     the string showing proof of the vulnerability
  # +:risk+::      an INTEGER value from 0 to 5 indicating the risk (5 is highest)
  # +:name+::      the string indicating the type of vulnerability
  #
  # If web_site is NOT specified, the following values are mandatory
  # +:host+::  the ip address of the server hosting the web site
  # +:port+::  the port number of the associated web site
  # +:vhost+:: the virtual host for this particular web site
  # +:ssl+::   whether or not SSL is in use on this port
  #
  #
  # Duplicate records for a given web_site, path, method, pname, and name
  # combination will be overwritten
  #

  def report_web_vuln(opts)
    return if not active
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace = opts.delete(:workspace) || workspace

    path    = opts[:path]
    meth    = opts[:method]
    para    = opts[:params] || []
    quer    = opts[:query].to_s
    pname   = opts[:pname]
    proof   = opts[:proof]
    risk    = opts[:risk].to_i
    name    = opts[:name].to_s.strip
    blame   = opts[:blame].to_s.strip
    desc    = opts[:description].to_s.strip
    conf    = opts[:confidence].to_i
    cat     = opts[:category].to_s.strip
    payload = opts[:payload].to_s
    owner   = opts[:owner] ? opts[:owner].shortname : nil


    site    = nil

    if not (path and meth and proof and pname)
      raise ArgumentError, "report_web_vuln requires the path, method, proof, risk, name, params, and pname parameters. Received #{opts.inspect}"
    end

    if not %W{GET POST PATH}.include?(meth)
      raise ArgumentError, "report_web_vuln requires the method to be one of GET, POST, PATH. Received '#{meth}'"
    end

    if risk < 0 or risk > 5
      raise ArgumentError, "report_web_vuln requires the risk to be between 0 and 5 (inclusive). Received '#{risk}'"
    end

    if conf < 0 or conf > 100
      raise ArgumentError, "report_web_vuln requires the confidence to be between 1 and 100 (inclusive). Received '#{conf}'"
    end

    if cat.empty?
      raise ArgumentError, "report_web_vuln requires the category to be a valid string"
    end

    if name.empty?
      raise ArgumentError, "report_web_vuln requires the name to be a valid string"
    end

    if opts[:web_site] and opts[:web_site].kind_of?(::Mdm::WebSite)
      site = opts.delete(:web_site)
    else
      site = report_web_site(
        :workspace => wspace,
        :host      => opts[:host], :port => opts[:port],
        :vhost     => opts[:host], :ssl  => opts[:ssl]
      )
      if not site
        raise ArgumentError, "report_web_form was unable to create the associated web site"
      end
    end

    ret = {}

    meth = meth.to_s.upcase

    vuln = ::Mdm::WebVuln.find_or_initialize_by_web_site_id_and_path_and_method_and_pname_and_name_and_category_and_query(site[:id], path, meth, pname, name, cat, quer)
    vuln.name     = name
    vuln.risk     = risk
    vuln.params   = para
    vuln.proof    = proof.to_s
    vuln.category = cat
    vuln.blame    = blame
    vuln.description = desc
    vuln.confidence  = conf
    vuln.payload = payload
    vuln.owner   = owner

    msf_import_timestamps(opts, vuln)
    vuln.save!

    ret[:web_vuln] = vuln
  }
  end
end
end
