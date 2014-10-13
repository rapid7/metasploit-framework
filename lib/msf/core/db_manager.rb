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
  autoload :Service, 'msf/core/db_manager/service'
  autoload :Session, 'msf/core/db_manager/session'
  autoload :SessionEvent, 'msf/core/db_manager/session_event'
  autoload :Sink, 'msf/core/db_manager/sink'
  autoload :Task, 'msf/core/db_manager/task'
  autoload :Vuln, 'msf/core/db_manager/vuln'
  autoload :VulnDetail, 'msf/core/db_manager/vuln_detail'
  autoload :WMAP, 'msf/core/db_manager/wmap'
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
  include Msf::DBManager::Service
  include Msf::DBManager::Session
  include Msf::DBManager::SessionEvent
  include Msf::DBManager::Sink
  include Msf::DBManager::Task
  include Msf::DBManager::Vuln
  include Msf::DBManager::VulnDetail
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
