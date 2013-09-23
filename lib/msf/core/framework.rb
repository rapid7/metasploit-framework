# -*- coding: binary -*-
require 'msf/core'
require 'msf/util'

module Msf

###
#
# This class is the primary context that modules, scripts, and user
# interfaces interact with.  It ties everything together.
#
###
class Framework < Metasploit::Model::Base
  # Use MonitorMixin instead of Mutex_m to get #synchronize as Monitors are reentrant while mutexes aren't, so
  # #synchronize can be called instead an outer #synchronize block when using a monitor.
  # Use a monitor allows for lazy initialization of children, which makes testing those children easier.
  include MonitorMixin

  require 'msf/core/framework/modules'
  include Msf::Framework::Modules

  #
  #
  # CONSTANTS
  #
  #

  #
  # Versioning information
  #

  Major    = 4
  Minor    = 8
  Point    = 0
  Release  = "-dev"

  if(Point)
    Version  = "#{Major}.#{Minor}.#{Point}#{Release}"
  else
    Version  = "#{Major}.#{Minor}#{Release}"
  end

  Revision = "$Revision$"

  # Repository information
  RepoRevision        = ::Msf::Util::SVN.revision
  RepoUpdated         = ::Msf::Util::SVN.updated
  RepoUpdatedDays     = ::Msf::Util::SVN.days_since_update
  RepoUpdatedDaysNote = ::Msf::Util::SVN.last_updated_friendly
  RepoUpdatedDate     = ::Msf::Util::SVN.last_updated_date
  RepoRoot            = ::Msf::Util::SVN.root

  # EICAR canary
  EICARCorrupted      = ::Msf::Util::EXE.is_eicar_corrupted?

  # API Version
  APIMajor = 1
  APIMinor = 0

  # Base/API Version
  VersionCore  = Major + (Minor / 10.0)
  VersionAPI   = APIMajor + (APIMinor / 10.0)

  #
  # Mixin meant to be included into all classes that can have instances that
  # should be tied to the framework, such as modules.
  #
  module Offspring

    #
    # A reference to the framework instance from which this offspring was
    # derived.
    #
    attr_accessor :framework
  end

  #
  # Attributes
  #

  # @!attribute [rw] database_disabled
  #   Whether {#db} should be {Msf::DBManager#disabled}.
  #
  #   @return [Boolean] Defaults to `false`.


  #
  # Methods
  #

  def database_disabled
    @database_disabled ||= false
  end
  alias database_disabled? database_disabled
  attr_writer :database_disabled

  # Requires need to be here because they use Msf::Framework::Offspring, which is declared immediately before this.
  require 'msf/core/db_manager'
  require 'msf/core/event_dispatcher'
  require 'msf/core/plugin_manager'
  require 'msf/core/session_manager'

  # The global framework datastore that can be used by modules.
  #
  # @return [Msf::DataStore]
  # @todo https://www.pivotaltracker.com/story/show/57456210
  def datastore
    synchronize {
      @datastore ||= Msf::DataStore.new
    }
  end

  # Maintains the database and handles database events
  #
  # @return [Msf::DBManager]
  def db
    synchronize {
      @db ||= Msf::DBManager.new(framework: self)
    }
  end

  # Event management interface for registering event handler subscribers and
  # for interacting with the correlation engine.
  #
  # @return [Msf::EventDispatcher]
  def events
    synchronize {
      @events ||= Msf::EventDispatcher.new(self)
    }
  end

  # @param attributes [Hash{Symbol => Object}]
  # @option attributes [Array<String>] :module_types a subset of `Metasploit::Model::Module::Type::ALL`.
  def initialize(attributes={})
    # call super to initialize MonitorMixin and set attributes with Metasploit::Model::Base
    super

    # Configure the thread factory
    # @todo https://www.pivotaltracker.com/story/show/57432206
    Rex::ThreadFactory.provider = self.threads

    subscriber = FrameworkEventSubscriber.new(self)
    events.add_exploit_subscriber(subscriber)
    events.add_session_subscriber(subscriber)
    events.add_general_subscriber(subscriber)
    events.add_db_subscriber(subscriber)
    events.add_ui_subscriber(subscriber)
  end

  # Background job management specific to things spawned from this instance
  # of the framework.
  #
  # @return [Rex::JobContainer]
  def jobs
    synchronize {
      # @todo https://www.pivotaltracker.com/story/show/57432316
      @jobs ||= Rex::JobContainer.new
    }
  end

  # The plugin manager allows for the loading and unloading of plugins.
  #
  # @return [Msf::PluginManager]
  def plugins
    synchronize {
      @plugins ||= Msf::PluginManager.new(self)
    }
  end

  # Session manager that tracks sessions associated with this framework
  # instance over the course of their lifetime.
  #
  # @return []
  def sessions
    synchronize {
      @sessions ||= Msf::SessionManager.new(self)
    }
  end

  # The thread manager provides a cleaner way to manage spawned threads.
  #
  # @return [Metasploit::Framework::Thread::Manager]
  def threads
    synchronize {
      @threads ||= Metasploit::Framework::Thread::Manager.new(framework: self)
    }
  end

  #
  # Returns the framework version in Major.Minor format.
  #
  def version
    Version
  end
end

class FrameworkEventSubscriber
  include Framework::Offspring
  def initialize(framework)
    self.framework = framework
  end

  def report_event(data)
    if framework.db.active
      framework.db.report_event(data)
    end
  end

  include GeneralEventSubscriber

  #
  # Generic handler for module events
  #
  def module_event(name, instance, opts={})
    if framework.db.active
      event = {
        :workspace => framework.db.find_workspace(instance.workspace),
        :name      => name,
        :username  => instance.owner,
        :info => {
          :module_name => instance.fullname,
          :module_uuid => instance.uuid
        }.merge(opts)
      }

      report_event(event)
    end
  end

  ##
  # :category: ::Msf::GeneralEventSubscriber implementors
  def on_module_run(instance)
    opts = { :datastore => instance.datastore.to_h }
    module_event('module_run', instance, opts)
  end

  ##
  # :category: ::Msf::GeneralEventSubscriber implementors
  def on_module_complete(instance)
    module_event('module_complete', instance)
  end

  ##
  # :category: ::Msf::GeneralEventSubscriber implementors
  def on_module_error(instance, exception=nil)
    module_event('module_error', instance, :exception => exception.to_s)
  end

  include ::Msf::UiEventSubscriber
  ##
  # :category: ::Msf::UiEventSubscriber implementors
  def on_ui_command(command)
    if framework.db.active
      report_event(:name => "ui_command", :info => {:command => command})
    end
  end

  ##
  # :category: ::Msf::UiEventSubscriber implementors
  def on_ui_stop()
    if framework.db.active
      report_event(:name => "ui_stop")
    end
  end

  ##
  # :category: ::Msf::UiEventSubscriber implementors
  def on_ui_start(rev)
    #
    # The database is not active at startup time unless msfconsole was
    # started with a database.yml, so this event won't always be saved to
    # the db.  Not great, but best we can do.
    #
    info = { :revision => rev }
    report_event(:name => "ui_start", :info => info)
  end

  require 'msf/core/session'

  include ::Msf::SessionEvent

  #
  # Generic handler for session events
  #
  def session_event(name, session, opts={})
    address = session.session_host

    if not (address and address.length > 0)
      elog("Session with no session_host/target_host/tunnel_peer")
      dlog("#{session.inspect}", LEV_3)
      return
    end

    if framework.db.active
      ws = framework.db.find_workspace(session.workspace)
      event = {
        :workspace => ws,
        :username  => session.username,
        :name => name,
        :host => address,
        :info => {
          :session_id   => session.sid,
          :session_info => session.info,
          :session_uuid => session.uuid,
          :session_type => session.type,
          :username     => session.username,
          :target_host  => address,
          :via_exploit  => session.via_exploit,
          :via_payload  => session.via_payload,
          :tunnel_peer  => session.tunnel_peer,
          :exploit_uuid => session.exploit_uuid
        }.merge(opts)
      }
      report_event(event)
    end
  end


  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_open(session)
    opts = { :datastore => session.exploit_datastore.to_h, :critical => true }
    session_event('session_open', session, opts)
    framework.db.report_session(:session => session)
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_upload(session, lpath, rpath)
    session_event('session_upload', session, :local_path => lpath, :remote_path => rpath)
    framework.db.report_session_event({
      :etype => 'upload',
      :session => session,
      :local_path => lpath,
      :remote_path => rpath
    })
  end
  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_download(session, rpath, lpath)
    session_event('session_download', session, :local_path => lpath, :remote_path => rpath)
    framework.db.report_session_event({
      :etype => 'download',
      :session => session,
      :local_path => lpath,
      :remote_path => rpath
    })
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_close(session, reason='')
    session_event('session_close', session)
    if session.db_record
      # Don't bother saving here, the session's cleanup method will take
      # care of that later.
      session.db_record.close_reason = reason
      session.db_record.closed_at = Time.now.utc
    end
  end

  #def on_session_interact(session)
  #	$stdout.puts('session_interact', session.inspect)
  #end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_command(session, command)
    session_event('session_command', session, :command => command)
    framework.db.report_session_event({
      :etype => 'command',
      :session => session,
      :command => command
    })
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_output(session, output)
    # Break up the output into chunks that will fit into the database.
    buff = output.dup
    chunks = []
    if buff.length > 1024
      while buff.length > 0
        chunks << buff.slice!(0,1024)
      end
    else
      chunks << buff
    end
    chunks.each { |chunk|
      session_event('session_output', session, :output => chunk)
      framework.db.report_session_event({
        :etype => 'output',
        :session => session,
        :output => chunk
      })
    }
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_route(session, route)
    framework.db.report_session_route(session, route)
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_route_remove(session, route)
    framework.db.report_session_route_remove(session, route)
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_script_run(session, script)
    framework.db.report_session_event({
      :etype => 'script_run',
      :session => session,
      :local_path => script
    })
  end

  ##
  # :category: ::Msf::SessionEvent implementors
  def on_session_module_run(session, mod)
    framework.db.report_session_event({
      :etype => 'module_run',
      :session => session,
      :local_path => mod.fullname
    })
  end

  #
  # This is covered by on_module_run and on_session_open, so don't bother
  #
  #require 'msf/core/exploit'
  #include ExploitEvent
  #def on_exploit_success(exploit, session)
  #end

end
end

